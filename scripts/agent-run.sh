#!/bin/bash
# agent-scan :: dataset task runner (phase 2, v2 — data/firmware layout)
#
# Usage: agent-run.sh [--timeout <seconds>] <fw-folder>
#
#   <fw-folder>   path like data/firmware/asus/4G-AC55U — must contain
#                 task.json (brand, firmware, ...) and the firmware file
#                 named by its "firmware" field
#   --timeout     agent-phase wall-clock budget in seconds (default 7200).
#                 On timeout the agent process tree is killed inside the
#                 container; verification still runs — a partial state may
#                 already serve the web interface, the harness decides.
#
# I/O contract
#   INPUT  : <fw>/task.json, <fw>/<firmware>, $ROOT/.env (LLM credentials),
#            scripts/{agent-prompt.md,hverify.sh,emu.sh,emu-shell.sh,
#            Dockerfile.task}, image firmae-base:latest
#   OUTPUT : <fw>/result.json  — the driver's own verdict (never written by
#            the agent): status = success | fail | agent_timeout |
#            agent_error | infra_error, timestamps, agent/harness details
#            <fw>/output/      — agent-fixes.patch, agent-updated task.json,
#            harness_* verdict files, agent terminal log
#   EXIT   : 0 = harness-verified success; 1 = anything else
#
# The agent never sees Dockerfiles / .env / host infra; its write scope is
# enforced by the git repo boundary at /opt/FirmAE-pro.
set -euo pipefail

TIMEOUT=7200
while [ $# -gt 1 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "usage: agent-run.sh [--timeout <seconds>] <fw-folder>" >&2; exit 1 ;;
    esac
done
FWDIR="${1:?usage: agent-run.sh [--timeout <seconds>] <fw-folder>}"
FWDIR="$(cd "$FWDIR" 2>/dev/null && pwd)" || { echo "[-] no such folder: $1" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

RUN_START=$(date +%s)
RUN_START_ISO=$(date -Iseconds)

# minimal result.json for pre-agent (infrastructure) failures
write_early_result() {
    python3 - "$FWDIR" "$RUN_START_ISO" "$1" <<'EOF'
import json, sys, datetime
fw_dir, started, reason = sys.argv[1:4]
task = "/".join(fw_dir.rstrip("/").split("/")[-2:])
json.dump({
    "task": task,
    "status": "infra_error",
    "reason": reason,
    "started_at": started,
    "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
}, open(f"{fw_dir}/result.json", "w"), indent=2, ensure_ascii=False)
EOF
    exit 1
}

# validate inputs, derive names
[ -f "$FWDIR/task.json" ] || { echo "[-] missing task.json in $FWDIR" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE (create it from your bashrc)" >&2; exit 1; }

# parse task.json (python3: robust JSON, no quote/space pitfalls like awk)
read -r BRAND FWFILE < <(python3 -c '
import json, sys
t = json.load(open(sys.argv[1]))
print(t.get("brand", ""), t.get("firmware", ""))' "$FWDIR/task.json")
[ -n "$BRAND" ] && [ -n "$FWFILE" ] || { echo "[-] task.json must define brand and firmware" >&2; exit 1; }
[ -f "$FWDIR/$FWFILE" ] || { echo "[-] firmware missing: $FWDIR/$FWFILE" >&2; exit 1; }
case "$FWFILE" in *[[:space:]]*)
    echo "[-] firmware filename must not contain whitespace: $FWFILE" >&2; exit 1 ;; esac

VENDOR=$(basename "$(dirname "$FWDIR")")
MODEL=$(basename "$FWDIR")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODEL" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:raw"
CONTAINER="task-$TASK_ID"
OUTDIR="$FWDIR/output"

echo "[*] task=$TASK_ID brand=$BRAND firmware=$FWFILE timeout=${TIMEOUT}s"

# stale outputs from a previous run must not leak into this one's verdict
rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"

# build the task image from a clean staging context
STAGE=$(mktemp -d /tmp/agent-scan-stage.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
cp "$FWDIR/task.json" "$STAGE/"
cp "$FWDIR/$FWFILE" "$STAGE/"
docker build -f "$ROOT/scripts/Dockerfile.task" \
    --build-arg BRAND="$BRAND" \
    --build-arg FIRMWARE="$FWFILE" \
    --build-arg TASK_NAME="$TASK_ID" \
    -t "$IMAGE" "$STAGE" || write_early_result "docker-build-failed"
rm -rf "$STAGE"; trap - EXIT

# (re)start the task container
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -dit \
    --init --privileged --device /dev/kvm -v /dev:/dev \
    --env-file "$ENV_FILE" \
    --name "$CONTAINER" \
    "$IMAGE" >/dev/null || write_early_result "docker-run-failed"

for _ in $(seq 1 30); do
    docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 || write_early_result "postgres-failed"

# ship the prompt + the verification script (agent self-check uses the
#    exact same deterministic criteria the harness will apply in step 5)
# emu/emu-shell ride along so a later `docker commit` of this container
#    bakes the agent-controllable lab entrypoint into the solved image
docker cp "$ROOT/scripts/agent-prompt.md" "$CONTAINER:/opt/agent-prompt.md"
docker cp "$ROOT/scripts/hverify.sh" "$CONTAINER:/usr/local/bin/hverify"
docker cp "$ROOT/scripts/emu.sh" "$CONTAINER:/usr/local/bin/emu"
docker cp "$ROOT/scripts/emu-shell.sh" "$CONTAINER:/usr/local/bin/emu-shell"
docker exec "$CONTAINER" chmod +x /usr/local/bin/hverify /usr/local/bin/emu /usr/local/bin/emu-shell

# run the agent under a wall-clock timeout
#    The kill must run INSIDE the container (killing the docker-exec client
#    leaves the exec'd process alive). GNU timeout only signals its direct
#    child, so claude's whole subtree would survive — instead the agent runs
#    under `setsid` (own process group) and the watchdog signals the GROUP
#    (TERM, then KILL). Exit 124 = timed out; 0 = clean; else = agent error.
AGENT_START=$(date +%s)
echo "[*] starting claude agent (effort=max, ${TIMEOUT}s budget)..."
set +e
docker exec -w /root -e IS_SANDBOX=1 -e TO="$TIMEOUT" "$CONTAINER" bash -c '
set -u
rm -f /tmp/.agent-timed-out
START=$(date +%s)
setsid claude -p "$(cat /opt/agent-prompt.md)" \
    --effort max \
    --dangerously-skip-permissions &
PID=$!
(   # watchdog: enforce the budget on the whole process group. The marker
    # file (not watchdog liveness) records the verdict — `wait` returns the
    # moment the agent dies, while the watchdog is still in its kill-grace.
    while kill -0 "$PID" 2>/dev/null; do
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
' 2>&1 | tee "$OUTDIR/agent.log"
AGENT_RC=${PIPESTATUS[0]}
set -e
AGENT_END=$(date +%s)
AGENT_DUR=$((AGENT_END - AGENT_START))

# deterministic harness verification — trust nothing the agent wrote
VERIFY_START=$(date +%s)
echo "[*] harness verification: clean re-boot + independent web check..."
docker cp "$ROOT/scripts/hverify.sh" "$CONTAINER:/usr/local/bin/hverify"
VERIFY_RC=0
docker exec "$CONTAINER" bash /usr/local/bin/hverify || VERIFY_RC=1
VERIFY_END=$(date +%s)

# harvest
echo "[*] harvesting agent outputs..."
docker exec "$CONTAINER" bash -c '
set -e
mkdir -p /work/patches /work/output
cd /opt/FirmAE-pro
SHA=$(cat /opt/.firmae_pristine_sha)
git add -A 2>/dev/null || true
git diff "$SHA" > /work/patches/agent-fixes.patch || true
IID=$(ls /opt/FirmAE-pro/scratch/ 2>/dev/null | grep -E "^[0-9]+$" | sort -n | tail -1 || true)
if [ -n "$IID" ]; then
    for f in result ip web ping; do
        cp "/opt/FirmAE-pro/scratch/$IID/$f" "/work/output/$f" 2>/dev/null || true
    done
fi
# full agent transcript: `claude -p` prints only its final message, but the
# .jsonl session log holds the entire reasoning/tool trace — benchmark gold
tar -C /root -cf /work/output/agent-transcripts.tar .claude .claude.json 2>/dev/null || true
' || true
docker cp "$CONTAINER:/work/patches/agent-fixes.patch" "$OUTDIR/" 2>/dev/null || true
docker cp "$CONTAINER:/work/task.json" "$OUTDIR/task.json" 2>/dev/null || true
docker cp "$CONTAINER:/work/output/." "$OUTDIR/" 2>/dev/null || true

# result.json — the driver's own verdict
#    harness result wins (goal achieved beats how the agent ended);
#    otherwise the agent's process outcome classifies the run.
RUN_END=$(date +%s)
python3 - "$FWDIR" "$TASK_ID" "$IMAGE" "$CONTAINER" \
    "$RUN_START_ISO" "$RUN_END" "$AGENT_DUR" "$AGENT_RC" "$TIMEOUT" \
    "$VERIFY_RC" "$VERIFY_START" "$VERIFY_END" <<'EOF'
import json, sys, os, datetime
(fw_dir, task, image, container, started, ended,
 agent_dur, agent_rc, timeout, verify_rc, vstart, vend) = sys.argv[1:13]
agent_dur, agent_rc, timeout = int(agent_dur), int(agent_rc), int(timeout)
verify_rc, vstart, vend = int(verify_rc), int(vstart), int(vend)
outdir = os.path.join(fw_dir, "output")

def read(name, default=None):
    p = os.path.join(outdir, name)
    try:
        return open(p).read().strip()
    except OSError:
        return default

harness_result = read("harness_result")
har = read("harness_time_to_web")
http_size = read("harness_http_size")
patch_lines = 0
try:
    patch_lines = sum(1 for _ in open(os.path.join(outdir, "agent-fixes.patch")))
except OSError:
    pass

if harness_result == "true":
    status = "success"                     # goal state achieved
elif agent_rc == 124:
    status = "agent_timeout"
elif agent_rc != 0:
    status = "agent_error"
else:
    status = "fail"                        # agent finished, web not verified

result = {
    "task": task,
    "fw_dir": fw_dir,
    "status": status,
    "started_at": started,
    "finished_at": datetime.datetime.fromtimestamp(int(ended)).astimezone().isoformat(timespec="seconds"),
    "duration_s": int(ended) - int(datetime.datetime.fromisoformat(started).timestamp()),
    "agent": {
        "duration_s": agent_dur,
        "timed_out": agent_rc == 124,
        "exit_code": agent_rc,
        "timeout_s": timeout,
        "iterations": None,
        "fixes": None,
        "patch_lines": patch_lines,
        "log": "output/agent.log",
    },
    "harness": {
        "result": harness_result == "true",
        "exit_code": verify_rc,
        "time_to_web_s": int(har) if har and har.isdigit() else None,
        "ip": read("harness_ip"),
        "http_size": int(http_size) if http_size and http_size.isdigit() else None,
        "reason": read("harness_reason"),
    },
    "image": image,
    "container": container,
}
# agent-reported metadata, if the agent updated task.json
try:
    t = json.load(open(os.path.join(outdir, "task.json")))
    result["agent"].update({k: t.get(k) for k in
                            ("status", "iid", "ip", "diagnosis", "fixes", "iterations", "verified")
                            if k in t})
except Exception:
    pass

with open(os.path.join(fw_dir, "result.json"), "w") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(f"[result] {fw_dir}/result.json  status={status}")
EOF

# summary
STATUS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$FWDIR/result.json")
HARNESS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["harness"]["result"])' "$FWDIR/result.json")
echo
echo "===== agent-scan: $TASK_ID ====="
echo "status    : $STATUS   (exit code follows this)"
echo "harness   : $HARNESS  (independent re-boot; ground truth)"
echo "agent     : rc=$AGENT_RC duration=${AGENT_DUR}s timeout=${TIMEOUT}s"
echo "patch     : $OUTDIR/agent-fixes.patch"
echo "result    : $FWDIR/result.json"
echo "container : $CONTAINER (kept running for inspection / docker commit)"
if grep -q '"verified": *true' "$OUTDIR/task.json" 2>/dev/null && [ "$HARNESS" != "True" ]; then
    echo
    echo "WARNING: agent claims verified=true but the harness could NOT reproduce"
    echo "         the web service — treat the agent's result as unverified."
fi
[ "$STATUS" = "success" ] || exit 1
