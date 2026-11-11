#!/bin/bash
# agent-scan :: taint — Phase-1 Mapper runner (host-side)
#
# Usage: mapper-run.sh [--timeout S] <model-dir>
#
# Runs the Mapper agent (claude, effort=max) in the model folder with a
# scrubbed environment and a wall-clock watchdog. The agent's contract
# output lands in <model>/taint-work-output/ (schema in mapper-prompt.md);
# its scratch is <model>/taint-work/. The agent boots the solved image
# itself, for the auth probing only (containers are the agent's own
# responsibility; this wrapper holds none).
#
# Post-run, the driver does a CONTRACT check (shape only — files exist,
# parse, carry required fields; zero content judgment: which call sites
# are real sources is the next phase's business) and writes
# taint-work/mapper-run/result.json:
#   status: success | agent_timeout | agent_error | output_incomplete
# Exit 0 iff status=success.
#
# Preserved across re-runs: taint-work/ghidra-projects/ (the Ghidra project
# cache — a pure performance optimization; the extractor outputs are byte-
# identical either way). Everything else under taint-work/ is the previous
# agent's scratch and is cleared; taint-work-output/ is always regenerated
# from scratch. The agent runs the deterministic tools itself.
#
# Env: credentials from <repo>/.env (same policy as rehost agents).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"
ENV_FILE="$ROOT/.env"

TIMEOUT=7200
while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: mapper-run.sh [--timeout S] <model-dir>}"
[ -d "$MODEL" ] || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
MODEL="$(cd "$MODEL" && pwd)"
[ -f "$MODEL/task.json" ] || { echo "[-] not a model dir (no task.json): $MODEL" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE" >&2; exit 1; }

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' \
          | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "[-] no solved image: $IMAGE" >&2; exit 1; }

# ---- fresh scratch + contract output; tool outputs survive -------------
RUNDIR="$MODEL/taint-work/mapper-run"
rm -rf "$MODEL/taint-work-output"
find "$MODEL/taint-work" -mindepth 1 -maxdepth 1 \
        ! -name ghidra-projects \
        -exec rm -rf {} + 2>/dev/null || true
mkdir -p "$RUNDIR"
RUN_START=$(date +%s)

# ---- render the mission brief --------------------------------------------
sed -e "s|{{SCRIPTS}}|$SCRIPTS|g"   -e "s|{{TASK_ID}}|$TASK_ID|g" \
    -e "s|{{IMAGE}}|$IMAGE|g"       -e "s|{{TIMEOUT}}|$TIMEOUT|g" \
    "$SCRIPTS/mapper-prompt.md" > "$RUNDIR/prompt.rendered.md"

echo "[*] task=$TASK_ID model=$MODEL image=$IMAGE timeout=${TIMEOUT}s"
echo "[*] starting Mapper agent (effort=max)..."

# ---- run the agent (host-side, model folder as cwd) -----------------------
# The child claude must not inherit this session's inter-process state
# (messaging socket, session ids); credentials come from .env.
set +e
(
    set -a; . "$ENV_FILE"; set +a
    cd "$MODEL"
    env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH \
        -u CLAUDE_CODE_MESSAGING_SOCKET -u CLAUDE_CODE_MESSAGING_TOKEN \
        -u CLAUDE_CODE_SESSION_ID -u CLAUDE_CODE_SESSION_ATTENDED \
        -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_PID -u CLAUDE_EFFORT -u AI_AGENT \
        IS_SANDBOX=1 \
        bash -c '
set -u
TO="$2"
MARKER="/tmp/.agent-timed-out-$3"
rm -f "$MARKER"
START=$(date +%s)
setsid claude -p "$(cat "$1")" --effort max --dangerously-skip-permissions &
PID=$!
(   # watchdog: enforce the budget on the whole process group (TERM, then
    # KILL); the marker file — not watchdog liveness — records the verdict
    while kill -0 "$PID" 2>/dev/null; do
        sleep 5
        if [ $(( $(date +%s) - START )) -ge "$TO" ]; then
            touch "$MARKER"
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
[ -f "$MARKER" ] && exit 124 || exit "$RC"
' _ "$RUNDIR/prompt.rendered.md" "$TIMEOUT" "$TASK_ID"
) 2>&1 | tee "$RUNDIR/agent.log"
AGENT_RC=${PIPESTATUS[0]}
set -e
AGENT_DUR=$(( $(date +%s) - RUN_START ))
echo "[*] agent rc=$AGENT_RC duration=${AGENT_DUR}s"

# full agent transcript (best-effort): session files the child wrote live
# under ~/.claude/projects/<cwd-slug>/ — restricted to the model-dir slug so
# this driver's own (concurrently writing) session file is never included.
SLUG="-$(printf '%s' "$MODEL" | sed 's|^/||; s|[^a-zA-Z0-9_-]|-|g')"
find "$HOME/.claude/projects/$SLUG" -name '*.jsonl' -newermt "@$RUN_START" \
    -exec tar -rf "$RUNDIR/agent-transcripts.tar" {} + 2>/dev/null || true

# ---- contract check (shape only — no content judgment) --------------------
echo "[*] contract check (shape only)..."
CHECK_RC=0
python3 - "$MODEL" "$RUNDIR" "$AGENT_RC" "$AGENT_DUR" "$TIMEOUT" "$TASK_ID" <<'EOF' || CHECK_RC=$?
import glob, json, os, sys

model, rundir = sys.argv[1:3]
agent_rc, agent_dur, timeout, task = (int(sys.argv[3]), int(sys.argv[4]),
                                      int(sys.argv[5]), sys.argv[6])
out = os.path.join(model, "taint-work-output")
errors = []

def load(name):
    p = os.path.join(out, name)
    if not os.path.isfile(p):
        errors.append(f"missing {name}")
        return None
    try:
        return json.load(open(p))
    except Exception as e:
        errors.append(f"{name}: not valid JSON: {e}")
        return None

# boundary.json
b = load("boundary.json")
if isinstance(b, dict) and isinstance(b.get("binaries"), list) and b["binaries"]:
    for i, x in enumerate(b["binaries"]):
        if not (isinstance(x, dict) and x.get("path")):
            errors.append(f"boundary.json: binaries[{i}] missing 'path'")
elif isinstance(b, dict) and not errors:
    errors.append("boundary.json: empty 'binaries'")

# dispatch.json
d = load("dispatch.json")
if isinstance(d, dict) and isinstance(d.get("routes"), list) and d["routes"]:
    for i, r in enumerate(d["routes"]):
        for k in ("endpoint", "handler_function", "handler_binary"):
            if not r.get(k):
                errors.append(f"dispatch.json: routes[{i}] missing '{k}'")
elif isinstance(d, dict) and not errors:
    errors.append("dispatch.json: empty 'routes'")

# auth.json
a = load("auth.json")
if isinstance(a, dict):
    for k in ("mechanism", "acquisition", "attach",
              "no_auth_endpoints", "auth_required_endpoints", "evidence"):
        if k not in a:
            errors.append(f"auth.json: missing '{k}'")
    if a.get("tested") is not True:
        errors.append("auth.json: 'tested' is not true — recipe unproven")

# functions/<binary>__<function>/{sources,getters}.json
n_pkgs = n_src = n_get = 0
for fd in sorted(glob.glob(os.path.join(out, "functions", "*"))):
    if not os.path.isdir(fd):
        continue
    n_pkgs += 1
    fname = os.path.basename(fd)
    for kind, listkey, itemkey in (("sources.json", "sources", "field"),
                                   ("getters.json", "getters", "key")):
        p = os.path.join(fd, kind)
        if not os.path.isfile(p):
            errors.append(f"functions/{fname}/{kind}: missing")
            continue
        try:
            j = json.load(open(p))
        except Exception as e:
            errors.append(f"functions/{fname}/{kind}: not valid JSON: {e}")
            continue
        for k in ("binary", "function", "function_addr", "requests", listkey):
            if k not in j:
                errors.append(f"functions/{fname}/{kind}: missing '{k}'")
        items = j.get(listkey) or []
        if kind == "sources.json":
            n_src += len(items)
        else:
            n_get += len(items)
        for i, it in enumerate(items):
            for k in ("call_addr", "ret_site", "callee", itemkey, "callsite"):
                if k not in it:
                    errors.append(
                        f"functions/{fname}/{kind}: {listkey}[{i}] missing '{k}'")
if n_pkgs == 0:
    errors.append("functions/: no work packages")

status = ("success" if not errors and agent_rc == 0
          else "agent_timeout" if agent_rc == 124
          else "output_incomplete" if agent_rc == 0
          else "agent_error")
result = {"task": task, "status": status, "agent_rc": agent_rc,
          "duration_s": agent_dur, "timeout_s": timeout,
          "packages": n_pkgs, "sources": n_src, "getters": n_get,
          "errors": errors[:20]}
json.dump(result, open(os.path.join(rundir, "result.json"), "w"), indent=2)
print(f"[mapper-run] status={status} packages={n_pkgs} "
      f"sources={n_src} getters={n_get}")
for e in errors[:10]:
    print(f"  ! {e}")
sys.exit(0 if status == "success" else 1)
EOF

if [ "$CHECK_RC" = 0 ]; then
    echo "[mapper-run] OK -> $MODEL/taint-work-output/"
else
    echo "[mapper-run] contract unsatisfied — see $RUNDIR/result.json" >&2
fi
exit "$CHECK_RC"
