#!/bin/bash
# agent-scan :: taint — Phase-2 Hunter runner (ONE function unit per run)
#
# Usage: hunt-run.sh [--timeout S] [--keep] <model-dir> <unit-name>
#
#   <model-dir>   data/firmware/<vendor>/<model> — needs task.json, a
#                 task-<id>:solved image, and Phase-1 output
#                 (taint-work-output/, taint-work/)
#   <unit-name>   a directory name under taint-work-output/functions/
#                 (list them: ls <model>/taint-work-output/functions)
#   --timeout     agent wall-clock budget, default 3600s
#   --keep        leave the derived container running after harvest
#                 (for inspection; next run of the same unit removes it)
#
# What it does — derives a disposable lab container from the solved image,
# stages the unit's ammunition, runs the Hunter agent (claude, effort=max)
# INSIDE the container under a watchdog, then harvests:
#
#   INPUT  : <model>/taint-work-output/{auth,dispatch,boundary}.json
#            <model>/taint-work-output/functions/<unit>/{sources,getters}.json
#            <model>/taint-work/{call-site-dump,map,frontend-surface.json,
#            mapper-notes.md}   (each optional -> warned, skipped)
#            <model>/decompiled-rootfs/  (host fallback: only cp'd into the
#            container when the baked /home/decompiled-rootfs is empty)
#            scripts/taint/{hunt-prompt.md,poc-run.sh}, scripts/rehost/emu.sh
#            $ROOT/.env (LLM credentials, injected via --env-file)
#   STAGING: /work/hunt (unit jsons + auth/dispatch/boundary)
#            /work/taint (global Phase-1 material)
#            /usr/local/bin/{poc-run,emu}  <- NOT baked in the image: the
#            CURRENT script must be what grades (and speaks) during the run
#   OUTPUT : <model>/hunt-output/functions/<unit>/
#              pocs/       the agent's /work/archive (the replay contract)
#              evidence/   poc-run reports gathered from the container
#              run/        agent.log, prompt.rendered.md, result.json,
#                          transcripts, /work/poc copy (audit, not graded)
#   RESULT : run/result.json — the driver's own verdict (never written by
#            the agent): status = success | agent_timeout | agent_error |
#            infra_error, plus pocs[] and archive-contract violations
#            (anything archived that is not .py/.c). Empty pocs/ is a
#            legitimate success — the unit was hunted and stayed clean.
#            This run does NOT re-grade the pocs; that is the verify
#            container's job (pristine boot per poc, one per boot).
#   EXIT   : 0 = status success
#   PARALLEL: different units may run concurrently (own container each; the
#            loop-shim isolates the kernel-global loop pool — same story as
#            agent-run.sh). Same unit twice at once: refused by a lock.
set -euo pipefail

TIMEOUT=3600
KEEP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: hunt-run.sh [--timeout S] [--keep] <model-dir> <unit-name>}"
UNIT="${2:?usage: hunt-run.sh [--timeout S] [--keep] <model-dir> <unit-name>}"
[ -d "$MODEL" ] || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
MODEL="$(cd "$MODEL" && pwd)"
UNITDIR="$MODEL/taint-work-output/functions/$UNIT"
[ -f "$MODEL/task.json" ] || { echo "[-] not a model dir (no task.json): $MODEL" >&2; exit 1; }
[ -f "$UNITDIR/sources.json" ] && [ -f "$UNITDIR/getters.json" ] \
    || { echo "[-] no unit ammunition: $UNITDIR/{sources,getters}.json" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"
ENV_FILE="$ROOT/.env"
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE" >&2; exit 1; }

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' \
          | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "[-] no solved image: $IMAGE (run rehost + commit-solved first)" >&2; exit 1; }

# one agent per unit at a time (container name + output dir are per-unit)
ULOCK=/tmp/agent-scan-hunt-$(printf '%s/%s' "$TASK_ID" "$UNIT" | tr -c 'a-z0-9._-' '-').lock
exec 8>"$ULOCK"
flock -n 8 || { echo "[-] another hunt-run is already on $UNIT" >&2; exit 1; }

# container name: docker allows [a-zA-Z0-9_.-], NOT underscore-free logic —
# just map '_' to '-' and cap; on truncation append a hash so distinct units
# can never collide
CSLUG=$(printf '%s-%s' "$TASK_ID" "$UNIT" | tr '_' '-')
[ "${#CSLUG}" -gt 80 ] && CSLUG="${CSLUG:0:70}-$(printf '%s' "$UNIT" | md5sum | cut -c1-8)"
CONTAINER="hunt-$CSLUG"

OUTROOT="$MODEL/hunt-output/functions/$UNIT"
RUNDIR="$OUTROOT/run"
rm -rf "$OUTROOT"; mkdir -p "$OUTROOT/pocs" "$OUTROOT/evidence" "$RUNDIR"

RUN_START=$(date +%s)
RUN_START_ISO=$(date -Iseconds)

infra_fail() { # pre-agent failures: verdict file, no half-staged world left
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    python3 - "$RUNDIR/result.json" "$TASK_ID" "$UNIT" "$RUN_START_ISO" "$1" <<'EOF'
import json, sys, datetime
p, task, unit, started, reason = sys.argv[1:6]
json.dump({"task": task, "unit": unit, "status": "infra_error", "reason": reason,
           "started_at": started,
           "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")},
          open(p, "w"), indent=2, ensure_ascii=False)
EOF
    echo "[-] infra_error: $reason (see $RUNDIR/result.json)" >&2
    exit 1
}

echo "[*] task=$TASK_ID unit=$UNIT image=$IMAGE timeout=${TIMEOUT}s"
echo "[*] derived container: $CONTAINER"

# ---- derive: solved image, lab entrypoint (boot idle), credentials -------
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d \
    --init --privileged --device /dev/kvm -v /dev:/dev \
    --env-file "$ENV_FILE" \
    --entrypoint /usr/local/bin/emu-shell \
    --name "$CONTAINER" \
    "$IMAGE" >/dev/null || infra_fail "docker-run-failed"

for _ in $(seq 1 30); do
    docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 || infra_fail "postgres-failed"

# loop-pool isolation, same contract as agent-run.sh (shim = parallel-safe;
# no shim = serialize host-wide on the shared lock, also honored by rehost)
docker cp "$ROOT/scripts/rehost/loop-shim/losetup.sh" "$CONTAINER:/usr/local/sbin/losetup" 2>/dev/null \
 && docker cp "$ROOT/scripts/rehost/loop-shim/kpartx.sh" "$CONTAINER:/usr/local/sbin/kpartx" 2>/dev/null \
 && docker exec "$CONTAINER" chmod +x /usr/local/sbin/losetup /usr/local/sbin/kpartx 2>/dev/null \
 && SHIM=1 || SHIM=0
if [ "$SHIM" = 1 ]; then
    echo "[*] loop shims installed — parallel-safe"
else
    echo "[*] loop shims NOT installed — waiting for the shared /dev loop pool"
    exec 9>/tmp/agent-scan-agent-run.lock; flock 9
fi

# ---- stage the ammunition --------------------------------------------------
docker exec "$CONTAINER" mkdir -p /work/hunt /work/taint /work/poc /work/archive
docker cp "$UNITDIR/sources.json"  "$CONTAINER:/work/hunt/sources.json"
docker cp "$UNITDIR/getters.json"  "$CONTAINER:/work/hunt/getters.json"
for g in auth dispatch boundary; do
    docker cp "$MODEL/taint-work-output/$g.json" "$CONTAINER:/work/hunt/$g.json" \
        || echo "[!] taint-work-output/$g.json missing — unit blind on $g"
done
# global Phase-1 material (all optional: warn, do not abort)
[ -d "$MODEL/taint-work/call-site-dump" ] \
    && docker cp "$MODEL/taint-work/call-site-dump" "$CONTAINER:/work/taint/" \
    || echo "[!] no call-site-dump/ — storage-channel grep degraded"
[ -f "$MODEL/taint-work/frontend-surface.json" ] \
    && docker cp "$MODEL/taint-work/frontend-surface.json" "$CONTAINER:/work/taint/" || true
[ -f "$MODEL/taint-work/mapper-notes.md" ] \
    && docker cp "$MODEL/taint-work/mapper-notes.md" "$CONTAINER:/work/taint/" || true
[ -d "$MODEL/taint-work/map" ] \
    && docker cp "$MODEL/taint-work/map" "$CONTAINER:/work/taint/" || true
# the CURRENT grader + the CURRENT boot modes (solved images may bake an
# older emu.sh — the debug-analyze composite must exist for this run)
docker cp "$SCRIPTS/poc-run.sh" "$CONTAINER:/usr/local/bin/poc-run"
docker cp "$ROOT/scripts/rehost/emu.sh" "$CONTAINER:/usr/local/bin/emu"
docker exec "$CONTAINER" chmod +x /usr/local/bin/poc-run /usr/local/bin/emu
# decompiled mirror: normally baked at rehost staging; host fallback covers
# images built before the tree existed (519M — only when genuinely missing)
if [ -z "$(docker exec "$CONTAINER" bash -c 'ls /home/decompiled-rootfs 2>/dev/null | head -1')" ] \
   && [ -n "$(ls "$MODEL/decompiled-rootfs" 2>/dev/null | head -1)" ]; then
    echo "[*] /home/decompiled-rootfs empty in image — copying from host (may take minutes)"
    docker exec "$CONTAINER" mkdir -p /home/decompiled-rootfs
    docker cp "$MODEL/decompiled-rootfs/." "$CONTAINER:/home/decompiled-rootfs/"
fi

# ---- render the mission brief ---------------------------------------------
sed -e "s|{{UNIT}}|$UNIT|g" -e "s|{{IMAGE}}|$IMAGE|g" -e "s|{{TIMEOUT}}|$TIMEOUT|g" \
    "$SCRIPTS/hunt-prompt.md" > "$RUNDIR/prompt.rendered.md"
docker cp "$RUNDIR/prompt.rendered.md" "$CONTAINER:/opt/hunt-prompt.md"

# ---- run the agent (in-container, watchdog: TERM -> 30s -> KILL) ----------
# same envelope as agent-run.sh: the kill must happen INSIDE the container
# (killing the docker-exec client leaves the exec'd process alive); the
# marker file, not watchdog liveness, records the timeout verdict.
echo "[*] starting Hunter agent (effort=max)..."
set +e
docker exec -w /root -e IS_SANDBOX=1 -e TO="$TIMEOUT" "$CONTAINER" bash -c '
set -u
rm -f /tmp/.agent-timed-out
START=$(date +%s)
setsid claude -p "$(cat /opt/hunt-prompt.md)" \
    --effort max \
    --dangerously-skip-permissions &
PID=$!
(   while kill -0 "$PID" 2>/dev/null; do
        sleep 5
        if [ $(( $(date +%s) - START )) -ge "$TO" ]; then
            touch /tmp/.agent-timed-out
            kill -TERM -- "-$PID" 2>/dev/null
            sleep 30
            kill -KILL -- "-$PID" 2>/dev/null
            exit 0
        fi
    done
) &
WD=$!
wait "$PID"; RC=$?
kill "$WD" 2>/dev/null
[ -f /tmp/.agent-timed-out ] && exit 124 || exit "$RC"
' 2>&1 | tee "$RUNDIR/agent.log"
AGENT_RC=${PIPESTATUS[0]}
set -e
AGENT_DUR=$(( $(date +%s) - RUN_START ))
echo "[*] agent rc=$AGENT_RC duration=${AGENT_DUR}s"

# ---- harvest ---------------------------------------------------------------
echo "[*] harvesting..."
# the archive is the graded deliverable; /work/poc + poc-run evidence come
# along for audit; transcripts are best-effort benchmark gold
docker cp "$CONTAINER:/work/archive/." "$OUTROOT/pocs/" 2>/dev/null || true
docker cp "$CONTAINER:/work/poc/." "$RUNDIR/poc-workdir/" 2>/dev/null || true
docker cp "$CONTAINER:/tmp/poc-runs/." "$OUTROOT/evidence/poc-runs-tmp/" 2>/dev/null || true
docker cp "$CONTAINER:/work/poc-runs/." "$OUTROOT/evidence/poc-runs-work/" 2>/dev/null || true
docker exec "$CONTAINER" bash -c 'tar -C /root -cf /tmp/agent-transcripts.tar .claude .claude.json 2>/dev/null || true'
docker cp "$CONTAINER:/tmp/agent-transcripts.tar" "$RUNDIR/agent-transcripts.tar" 2>/dev/null || true

# ---- result.json — the driver's own verdict --------------------------------
python3 - "$OUTROOT" "$TASK_ID" "$UNIT" "$IMAGE" "$CONTAINER" \
    "$RUN_START_ISO" "$AGENT_RC" "$AGENT_DUR" "$TIMEOUT" <<'EOF'
import json, os, sys, datetime
outroot, task, unit, image, container = sys.argv[1:6]
started, agent_rc, agent_dur, timeout = sys.argv[6], int(sys.argv[7]), int(sys.argv[8]), int(sys.argv[9])

pocs = []
violations = []
for name in sorted(os.listdir(os.path.join(outroot, "pocs"))):
    p = os.path.join(outroot, "pocs", name)
    if not os.path.isfile(p):
        continue
    entry = {"name": name, "bytes": os.path.getsize(p)}
    pocs.append(entry)
    if not name.endswith((".py", ".c")):
        violations.append(f"archived non-poc file: {name}")

n_runs = 0
ev = os.path.join(outroot, "evidence", "poc-runs-tmp")
if os.path.isdir(ev):
    n_runs = len([d for d in os.listdir(ev) if os.path.isdir(os.path.join(ev, d))])

if agent_rc == 124:
    status = "agent_timeout"
elif agent_rc != 0:
    status = "agent_error"
else:
    status = "success"

result = {
    "task": task, "unit": unit, "image": image,
    "status": status,
    "started_at": started,
    "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "duration_s": agent_dur,
    "agent": {"rc": agent_rc, "duration_s": agent_dur, "timeout_s": timeout,
              "log": "run/agent.log"},
    "pocs": pocs,
    "poc_run_evidence_runs": n_runs,
    "contract_violations": violations,
    "graded_elsewhere": "pocs/ are replayed by the verify container (fresh boot per poc, one poc per boot) — this driver did not re-grade",
}
json.dump(result, open(os.path.join(outroot, "run", "result.json"), "w"), indent=2, ensure_ascii=False)
print(f"[hunt-run] status={status} pocs={len(pocs)} evidence_runs={n_runs} violations={len(violations)}")
for v in violations[:10]:
    print(f"  ! {v}")
EOF

if [ -z "$KEEP" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    CTR_LINE="(removed)"
else
    CTR_LINE="$CONTAINER (--keep)"
fi

STATUS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$RUNDIR/result.json")
echo
echo "===== hunt-run: $TASK_ID :: $UNIT ====="
echo "status : $STATUS"
echo "output : $OUTROOT/"
echo "agent  : rc=$AGENT_RC duration=${AGENT_DUR}s timeout=${TIMEOUT}s"
echo "ctr    : $CTR_LINE"
[ "$STATUS" = "success" ] || exit 1
