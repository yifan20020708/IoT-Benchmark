#!/bin/bash
# agent-scan :: taint — verify container: re-grade ONE unit's archive
#
# Usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] [--port P]
#                      [--retries N] [--gate-confirm S] [--keep] [--no-report]
#                      [--report-timeout S] <model-dir> <unit-name>
#
#   <model-dir>     data/firmware/<vendor>/<model> (solved image present)
#   <unit-name>     taint-work-output/functions/<unit> whose archive under
#                   hunt-output/functions/<unit>/pocs/ is to be re-graded
#   --port          the model's ATTACK-SURFACE service port. Default order:
#                   explicit --port > boundary.json "service_port" (declared
#                   by the Mapper from its own probing) > 80.
#                   TN3108-style firmwares whose early-answering :80 is an
#                   unrelated static server and whose real daemon (Kylin)
#                   binds :443 minutes later MUST be graded on 443:
#                   the serving gate and the DoS liveness channel both
#                   follow this port, and TARGET_PORT handed to the poc
#                   equals it). Never auto-detect: the gate must ask "is the
#                   attacked daemon up", not "did some server wake up".
#   --parallel      concurrent poc jobs (default 4, capped at #pocs).
#                   One poc attempt = one dedicated container = one fresh
#                   boot, exactly as the serial protocol; parallelism only
#                   overlaps the boots. Each TCG QEMU ~1 core; on a
#                   busy host (e.g. this unit runs inside hunt-batch,
#                   which already parallelizes units) pass --parallel 1.
#   --mode          emulation mode for every poc boot (default debug:
#                   THE grading boot — canary-file CI + crash-line BOF
#                   + liveness all live there; treat it as fixed)
#   --boot-timeout  seconds to wait for a freshly booted emulation to
#                   accept TCP on --port before the poc run is recorded
#                   boot_failed / rc3-inconclusive-equivalent (default 300)
#   --gate-confirm  stability confirmation after the serving gate's first
#                   "up": sleep this many seconds, re-probe, and only a box
#                   still answering is handed to poc-run (default 8; 0 =
#                   the old single-probe gate). A first "up" is NOT yet the
#                   attack surface on images whose daemon dies right after
#                   listening: R7000 httpd#1 listens 0.5-1.6s, then SIGSEGVs
#                   at 0x17350 (null https-cert-file pointer) before the
#                   watchdog respawn — a single connect catches that death
#                   blip and hands poc-run a dead box (baseline-gate rc3,
#                   the poc never runs). Sub-2s transients can never pass an
#                   8s confirmation; the stable respawned daemon always does.
#   --retries       extra grading attempts for a poc whose verdict is
#                   neither TRIGGERED nor service_down (default 5; 0 = the
#                   old single-shot). Every attempt is a FRESH container+
#                   boot — the protocol's reset button — so probabilistic
#                   obstacles (a residual boot race, a flapping daemon) and
#                   race-condition triggers that need several shots to win
#                   all get their chance. Every attempt is preserved
#                   (evidence/<n>-<poc>/attempt-<k>/ + result.json
#                   attempts[]); the score of record is the LAST attempt.
#                   rc=4 (poc_error) is deterministic and never retried.
#   --keep          leave ALL per-poc verify containers running afterwards
#                   (the protocol's reset button is each container's
#                   writable layer; with --keep nothing is graded twice in
#                   one container anyway — every job starts its own)
#   --no-report     skip the round-vault step (default ON: every hit —
#                   rc0 TRIGGERED or rc2 service_down — is archived to
#                   data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/ as
#                   poc + full grading evidence + meta.json, and a
#                   STATIC-only report agent (report-agent.sh, effort
#                   high, boots nothing — the rc is already final) writes
#                   the English REPORT.md + the AUDIT.json judgment
#                   ledger (evidence-audit dimensions + binary 0-DAY/N-DAY
#                   novelty verdict; the archiver derives the overall
#                   3-tier confidence from them, never agent-asserted);
#                   the snapshot is inline (fast,
#                   deterministic) but the AGENT RUNS DETACHED — grading
#                   never waits on an LLM; an entry with the same poc
#                   hash is append-only, so re-runs cannot lose hits)
#   --report-timeout report-agent wall budget per hit, seconds (default 2400)
#
# The scoring path of Phase-2: NO LLM anywhere IN THE VERDICT. N container
# jobs at a time, but ONE FRESH CONTAINER PER POC ATTEMPT (unique name
# verify-<unit-slug>-<idx>, destroyed after harvest — the writable layer
# is the reset button): the grading protocol demands a factory-state boot
# per attempt, and a destructive poc poisons the container's raw in place
# (AC15 lesson). Recreation is cheap because the 519M of image layers are
# shared; only the writable layer is new. The loop shim is installed into
# EVERY container (parallel jobs contend on the kernel-global loop pool;
# scripts/rehost/loop-shim header).
#
# Per poc: new container -> stage CURRENT poc-run.sh + emu.sh + poc
# -> emu <mode> -> wait for serving -> poc-run --out-root /work/poc-runs/N
# -> harvest rc + full report to
#   hunt-output/functions/<unit>/verify/{result.json,evidence/}
#   and, for hits, snapshot + DETACHED report into data/round/ (the
#   "round" field of each poc line is that vault path; note records
#   "report-detached").
# Verdicts mirror the rc contract: 0 TRIGGERED / 1 not_triggered /
# 2 service_down / 3 inconclusive / 4 poc_error / -1 boot_failed.
# Archive files outside [A-Za-z0-9._@+-]*.py|c violate the contract and
# are listed in result.json but never executed.
#
# Exit: 0 always on a completed pass (inconclusive verdicts are verdicts;
# the pass verdict for the unit is result.json — not this exit code).
set -euo pipefail

MODE="debug"; BOOT_TIMEOUT=300; KEEP=""
PORT=""; RETRIES=5; GATE_CONFIRM=8
REPORT_ON=1; REPORT_TIMEOUT=2400; PAR=4
while [ $# -gt 0 ]; do
    case "$1" in
        --parallel) PAR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --retries) RETRIES="$2"; shift 2 ;;
        --gate-confirm) GATE_CONFIRM="$2"; shift 2 ;;
        --report-timeout) REPORT_TIMEOUT="$2"; shift 2 ;;
        --no-report) REPORT_ON=""; shift ;;
        --keep) KEEP=1; shift ;;
        -h|--help) awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,"");print}' "$0"; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] [--port P] <model-dir> <unit-name>}"
UNIT="${2:?usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] [--port P] <model-dir> <unit-name>}"
MODEL="$(cd "$MODEL" 2>/dev/null && pwd)" || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"

# attack-surface port: explicit --port > Phase-1 declaration > legacy default
if [ -z "$PORT" ]; then
    PORT=$(python3 -I -c "
import json,sys
try: print(json.load(open(sys.argv[1])).get('service_port') or 80)
except Exception: print(80)" "$MODEL/taint-work-output/boundary.json" 2>/dev/null) || PORT=80
    [ "$PORT" != 80 ] && echo "[verify-run] port from boundary.json service_port: $PORT"
fi

UNITOUT="$MODEL/hunt-output/functions/$UNIT"
POCSDIR="$UNITOUT/pocs"
[ -d "$POCSDIR" ] || { echo "[-] no archive dir: $POCSDIR (run hunt-run.sh first)" >&2; exit 1; }
VOUT="$UNITOUT/verify"

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' \
          | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "[-] no solved image: $IMAGE" >&2; exit 1; }

CSLUG=$(printf '%s-%s' "$TASK_ID" "$UNIT" | tr '_' '-')
[ "${#CSLUG}" -gt 80 ] && CSLUG="${CSLUG:0:70}-$(printf '%s' "$UNIT" | md5sum | cut -c1-8)"
CONTAINER="verify-$CSLUG"

SAFE_RE='^[A-Za-z0-9._@+-]+\.(py|c)$'
mapfile -t POC_LIST < <(cd "$POCSDIR" && find . -maxdepth 1 -type f \( -name '*.py' -o -name '*.c' \) -printf '%f\n' | grep -E "$SAFE_RE" | sort)
mapfile -t JUNK_LIST < <(cd "$POCSDIR" && find . -maxdepth 1 -type f -printf '%f\n' | grep -vE "$SAFE_RE" | sort)

if [ -d "$VOUT" ]; then
    # preserve the previous grading pass (evidence of past verdicts must
    # never be silently overwritten by a re-run)
    mv "$VOUT" "$UNITOUT/verify.pre-$(date +%Y%m%d-%H%M%S)"
fi
rm -rf "$VOUT"; mkdir -p "$VOUT/evidence"
RESULTS="$VOUT/poc-results.jsonl"; : > "$RESULTS"
printf '%s\n' "${JUNK_LIST[@]}" 2>/dev/null | grep -v '^$' > "$VOUT/violations.txt" || : > "$VOUT/violations.txt"
V_START=$(date +%s)

write_final_result() {   # python assembles result.json from the harvest files
    python3 - "$VOUT/result.json" "$RESULTS" "$VOUT/violations.txt" \
              "$TASK_ID" "$UNIT" "$IMAGE" "$MODE" "$V_START" "$PORT" <<'EOF'
import json, sys, collections, datetime, os
p, results, junk, task, unit, image, mode, start, port = sys.argv[1:10]
pocs = [json.loads(l) for l in open(results) if l.strip()]
counts = collections.Counter(x["verdict"] for x in pocs)
viol = [x for x in open(junk).read().splitlines() if x.strip()]
infra = sum(1 for x in pocs if x["rc"] == -1)
json.dump({
    "task": task, "unit": unit, "image": image, "mode": mode, "port": int(port),
    "status": "success" if infra == 0 else "partial_infra",
    "started_at": datetime.datetime.fromtimestamp(int(start)).astimezone().isoformat(timespec="seconds"),
    "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "grade": "one fresh container+boot per poc attempt; non-hit verdicts re-graded up to --retries times; deterministic replay by the CURRENT poc-run.sh only",
    "attempts_total": sum(x.get("attempts_used", 1) for x in pocs),
    "pocs": pocs, "counts": dict(counts), "contract_violations": viol,
}, open(p, "w"), indent=2, ensure_ascii=False)
print(f"[verify-run] summary: {dict(counts)} attempts={sum(x.get('attempts_used', 1) for x in pocs)} violations={len(viol)}")
EOF
}

if [ "${#POC_LIST[@]}" = 0 ]; then
    # empty archive: still record the verify verdict — this file is the
    # batch layer's resume marker and the unit's "graded clean" claim
    for t in $(docker ps -aq -f "name=^${CONTAINER}-" 2>/dev/null); do
        docker rm -f "$t" >/dev/null 2>&1 || true
    done
    write_final_result
    echo "[verify-run] $UNIT: archive empty — nothing to grade"
    exit 0
fi

boot_container() {   # $1 = container name; fresh writable layer = factory state
    local CTR="$1"
    docker rm -f "$CTR" >/dev/null 2>&1 || true
    docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
        --entrypoint /usr/local/bin/emu-shell \
        --name "$CTR" "$IMAGE" >/dev/null || return 1
    for _ in $(seq 1 30); do docker exec "$CTR" pg_isready -q -h 127.0.0.1 && break; sleep 1; done
    docker exec "$CTR" pg_isready -q -h 127.0.0.1 || return 1
    # loop shim in EVERY container: parallel jobs contend on the
    # kernel-global loop pool, and each container's PATH is its own
    docker cp "$ROOT/scripts/rehost/loop-shim/losetup.sh" "$CTR:/usr/local/sbin/losetup" 2>/dev/null \
     && docker cp "$ROOT/scripts/rehost/loop-shim/kpartx.sh" "$CTR:/usr/local/sbin/kpartx" 2>/dev/null \
     && docker exec "$CTR" chmod +x /usr/local/sbin/losetup /usr/local/sbin/kpartx 2>/dev/null \
     || echo "[verify-run] WARN: loop shim not installed in $CTR (loop mounts may contend)" >&2
    return 0
}

gate_probe() {   # $1 = container — raw TCP probe of the DECLARED attack-surface port
    docker exec -e GATEPORT="$PORT" "$1" bash -c '
        IP=$( { cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null; } | head -1)
        if [ -n "$IP" ] && timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$GATEPORT" 2>/dev/null; then
            echo up
        else
            echo 000
        fi' 2>/dev/null || echo 000
}

run_poc_job() {   # $1 = idx, $2 = poc — self-contained job, writes its own part file
    local IDX="$1" poc="$2"
    local CTR="$CONTAINER-$IDX"
    local EVROOT="$VOUT/evidence/$IDX-$poc"
    local RC=-1 VERDICT=boot_failed NOTE="" ROUND="" EVDIR=""
    local a=0 CODE DEADLINE SAWUP
    mkdir -p "$EVROOT"
    # attempt loop: a poc whose verdict is neither TRIGGERED nor
    # service_down is re-graded on a FRESH container+boot (the protocol's
    # reset button) up to --retries extra times. Combats the probabilistic
    # classes — residual boot races, flapping daemons — and gives
    # race-condition triggers several shots to win. Hits and deterministic
    # poc errors (rc=4) short-circuit. The score of record is the LAST
    # attempt; every attempt stays on disk (evidence/.../attempt-<k>/).
    while :; do
        a=$(( a + 1 ))
        RC=-1; NOTE=""; SAWUP=""; EVDIR="$EVROOT/attempt-$a"
        if boot_container "$CTR"; then
            docker exec "$CTR" mkdir -p /work/poc /work/poc-runs
            docker cp "$SCRIPTS/poc-run.sh" "$CTR:/usr/local/bin/poc-run"
            docker cp "$ROOT/scripts/rehost/emu.sh" "$CTR:/usr/local/bin/emu"
            docker exec "$CTR" chmod +x /usr/local/bin/poc-run /usr/local/bin/emu
            docker cp "$POCSDIR/$poc" "$CTR:/work/poc/$poc"
            docker exec "$CTR" emu "$MODE" >/dev/null 2>&1 || NOTE="emu-boot-cmd-failed"
            # serving gate: wait until the DECLARED attack-surface port accepts
            # TCP — STABLY. Do NOT probe plain HTTP on some port that answers
            # early — on TN3108-style firmwares :80 is an unrelated static
            # server that is up ~70s before the real daemon (Kylin :443)
            # binds, and grading pocs in that window kills them at connect()
            # ("no endpoint" aborts, DoS channels blind). And do NOT trust a
            # first "up": on images whose daemon dies right after listening
            # (R7000 httpd#1: listens 0.5-1.6s, SIGSEGV at 0x17350 before the
            # watchdog respawn), a single connect catches the death blip and
            # hands poc-run a dead box — its baseline gate then returns rc=3
            # and the poc never runs (the "infra error" flake). The
            # confirmation probe $GATE_CONFIRM seconds later filters every
            # sub-2s transient; the stable respawned daemon always passes.
            # poc-run's own baseline gate keeps the final say either way.
            DEADLINE=$(( $(date +%s) + BOOT_TIMEOUT ))
            while :; do
                CODE=$(gate_probe "$CTR")
                if [ "$CODE" = "up" ]; then
                    SAWUP=1
                    if [ "$GATE_CONFIRM" -gt 0 ]; then
                        sleep "$GATE_CONFIRM"
                        CODE=$(gate_probe "$CTR")
                        [ "$CODE" = "up" ] && break   # confirmed stable
                        # transient listener died inside the confirmation
                        # window — keep polling for the real daemon
                    else
                        break
                    fi
                fi
                [ "$(date +%s)" -ge "$DEADLINE" ] && break
                sleep 5
            done
            if [ "$CODE" = "up" ]; then
                set +e
                docker exec "$CTR" bash -c "poc-run \"/work/poc/$poc\" --port \"$PORT\" --out-root /work/poc-runs/$IDX"
                RC=$?
                set -e
                mkdir -p "$EVDIR"
                docker cp "$CTR:/work/poc-runs/$IDX/." "$EVDIR/" 2>/dev/null || NOTE="evidence-copy-failed"
            else
                if [ -n "$SAWUP" ]; then
                    NOTE="port $PORT answered but did not stay up ${GATE_CONFIRM}s (crash-looping/flapping boot)"
                else
                    NOTE="no tcp answer on port $PORT within ${BOOT_TIMEOUT}s after emu $MODE"
                fi
            fi
            # with retries, a kept container is replaced by the next
            # attempt's boot (same name); only the last one survives --keep
            [ -n "$KEEP" ] || docker rm -f "$CTR" >/dev/null 2>&1 || true
        else
            NOTE="container boot failed (infra)"
        fi
        case $RC in
            0) VERDICT=TRIGGERED ;;
            1) VERDICT=not_triggered ;;
            2) VERDICT=service_down ;;
            3) VERDICT=inconclusive ;;
            4) VERDICT=poc_error ;;
            *) VERDICT=boot_failed ;;
        esac
        python3 - "$EVROOT/attempt-$a.json" "$a" "$RC" "$VERDICT" "$NOTE" "evidence/$IDX-$poc/attempt-$a/" <<'EOF'
import json, sys
p, n, rc, verdict, note, ev = sys.argv[1:7]
json.dump({"attempt": int(n), "rc": int(rc), "verdict": verdict,
           "note": note or None, "evidence": ev}, open(p, "w"), indent=1)
EOF
        echo "[verify-run]   #$IDX $poc try#$a -> rc=$RC $VERDICT${NOTE:+ ($NOTE)}"
        # retry policy: hits short-circuit; rc=4 (poc_error) is a
        # deterministic defect of the poc itself and is never retried;
        # --retries bounds the extra attempts
        if [ "$RC" = 0 ] || [ "$RC" = 2 ] || [ "$RC" = 4 ] || [ "$a" -gt "$RETRIES" ]; then
            break
        fi
    done
    # round vault: the SNAPSHOT is inline (pure file ops + deterministic
    # meta build — milliseconds, and it yields the vault path for the
    # jsonl line). The REPORT AGENT is then detached: grading of the next
    # poc never waits on an LLM. Failures of either never change the rc —
    # the note records them.
    if [ -n "$REPORT_ON" ] && { [ "$RC" = 0 ] || [ "$RC" = 2 ]; }; then
        set +e
        ROUND=$(bash "$SCRIPTS/report-agent.sh" --snapshot-only --mode "$MODE" \
                    "$MODEL" "$UNIT" "$POCSDIR/$poc" "$RC" "$EVDIR" 2>>"$VOUT/report-agent.log" \
                | tail -1)
        RR=${PIPESTATUS[0]}
        set -e
        case "$ROUND" in data/round/*) ;; *) ROUND="" ;; esac
        if [ -n "$ROUND" ]; then
            ( setsid bash "$SCRIPTS/report-agent.sh" --timeout "$REPORT_TIMEOUT" --mode "$MODE" \
                  "$MODEL" "$UNIT" "$POCSDIR/$poc" "$RC" "$EVDIR" \
                  >/dev/null 2>>"$VOUT/report-agent.log" & )
            NOTE="${NOTE:+$NOTE,}report-detached"
        else
            NOTE="${NOTE:+$NOTE,}report-snapshot-rc$RR"
        fi
    fi
    # part-file line: the score of record is the LAST attempt; every
    # attempt stays in the ledger (attempts[]) for audit — best-of-N
    # inflates the per-run false-positive rate, the ledger keeps it honest
    python3 - "$poc" "$RC" "$VERDICT" "$IDX" "$NOTE" "$ROUND" "$EVROOT" "$VOUT/poc-results.$IDX.part" <<'EOF'
import json, sys, glob, os
poc, rc, verdict, idx, note, round_, evroot, res = sys.argv[1:9]
attempts = []
for p in sorted(glob.glob(os.path.join(evroot, "attempt-*.json")),
                key=lambda p: int(p.rsplit("-", 1)[1].split(".")[0])):
    try:
        attempts.append(json.load(open(p)))
    except Exception:
        pass
last = attempts[-1] if attempts else None
with open(res, "a") as f:
    f.write(json.dumps({"poc": poc, "rc": int(rc), "verdict": verdict,
                        "evidence": (last or {}).get("evidence", f"evidence/{idx}-{poc}/"),
                        "round": round_ or None, "note": note or None,
                        "attempts_used": len(attempts), "attempts": attempts}) + "\n")
EOF
    echo "[verify-run]   #$IDX $poc -> rc=$RC $VERDICT ($a attempt(s))${ROUND:+ round=$ROUND} ${NOTE:+($NOTE)}"
}

NJOBS="${#POC_LIST[@]}"
[ "$PAR" -gt "$NJOBS" ] && PAR="$NJOBS"
echo "[verify-run] $UNIT: $NJOBS poc(s), fresh boot per attempt (retries=$RETRIES, gate-confirm=${GATE_CONFIRM}s), parallel=$PAR, mode=$MODE"
IDX=0
for poc in "${POC_LIST[@]}"; do
    IDX=$((IDX + 1))
    while [ "$(jobs -rp | wc -l)" -ge "$PAR" ]; do wait -n; done
    run_poc_job "$IDX" "$poc" &
done
wait

# merge per-job parts in index order — the jsonl stays deterministic
: > "$RESULTS"
for i in $(seq 1 "$NJOBS"); do
    if [ ! -f "$VOUT/poc-results.$i.part" ]; then
        # a job that died before writing its line (crash mid-container-op):
        # never silently drop a poc from the ledger
        python3 - "${POC_LIST[$((i - 1))]}" "$i" "$VOUT" "$VOUT/poc-results.$i.part" <<'EOF'
import json, sys, os
poc, idx, vout, res = sys.argv[1:5]
d = os.path.join(vout, "evidence", f"{idx}-{poc}")
n = len([p for p in os.listdir(d) if p.startswith("attempt-")]) if os.path.isdir(d) else 0
with open(res, "a") as f:
    f.write(json.dumps({"poc": poc, "rc": -1, "verdict": "boot_failed",
                        "evidence": f"evidence/{idx}-{poc}/",
                        "round": None, "note": "job died before reporting",
                        "attempts_used": n, "attempts": []}) + "\n")
EOF
    fi
    cat "$VOUT/poc-results.$i.part" >> "$RESULTS"
    rm -f "$VOUT/poc-results.$i.part"
done
if [ -z "$KEEP" ]; then   # belt & braces: a job that died early leaves its container
    for t in $(docker ps -aq -f "name=^${CONTAINER}-" 2>/dev/null); do
        docker rm -f "$t" >/dev/null 2>&1 || true
    done
fi

write_final_result
echo "[verify-run] result: $VOUT/result.json"
[ -z "$KEEP" ] || echo "[verify-run] containers kept: $CONTAINER-1..$NJOBS"
exit 0
