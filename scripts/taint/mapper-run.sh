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
# PRUNING (shape-level, never fabrication): records the contract defines
# as invalid are DELETED instead of failing the whole run — a dispatch
# route with a null/placeholder handler_function, a source/getter item
# missing a required key, a package left with no items (its folder is
# removed). Top-level files rewritten by pruning are archived to
# <rundir>/<name>.raw.json; all prunes are counted in result.json's
# "pruned" field. Guard against hollowing: when a class loses more than
# 10% of its records to pruning, that is systematic deviation, not
# variance — the run is output_incomplete and the fix belongs in the
# prompt, not the driver.
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
        -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
import glob, json, os, shutil, sys

model, rundir = sys.argv[1:3]
agent_rc, agent_dur, timeout, task = (int(sys.argv[3]), int(sys.argv[4]),
                                      int(sys.argv[5]), sys.argv[6])
out = os.path.join(model, "taint-work-output")
errors = []
pruned = {}
PLACEHOLDER = ("None", "null", "N/A")
PRUNE_FRAC = 0.10

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

def truthy(v):
    return bool(v) and not (isinstance(v, str) and v.strip() in PLACEHOLDER)

def guard(cls, n_pruned, n_pre):
    """anti-hollowing line: >10% pruned in a class is systematic deviation
    (fix the prompt, rerun) — never variance to trim away"""
    if n_pre and n_pruned / n_pre > PRUNE_FRAC:
        errors.append(f"{cls}: pruned {n_pruned}/{n_pre} records (>10%) "
                      "— systematic deviation, rerun")

def rewrite(name, obj):
    """archive the agent's original into the run dir, write the pruned file"""
    shutil.copyfile(os.path.join(out, name), os.path.join(rundir, name + ".raw.json"))
    json.dump(obj, open(os.path.join(out, name), "w"), indent=2, ensure_ascii=False)

# boundary.json
b = load("boundary.json")
if isinstance(b, dict) and isinstance(b.get("binaries"), list) and b["binaries"]:
    keep = [x for x in b["binaries"] if isinstance(x, dict) and truthy(x.get("path"))]
    if len(keep) < len(b["binaries"]):
        pruned["boundary.binaries"] = len(b["binaries"]) - len(keep)
        guard("boundary.json binaries", pruned["boundary.binaries"], len(b["binaries"]))
        b["binaries"] = keep
        rewrite("boundary.json", b)
    if not b["binaries"]:
        errors.append("boundary.json: empty 'binaries' after pruning")
elif isinstance(b, dict) and not errors:
    errors.append("boundary.json: empty 'binaries'")

# dispatch.json — a route with no handler answers no Verifier question:
# drop it (its reachability story belongs in auth.json, not here)
d = load("dispatch.json")
if isinstance(d, dict) and isinstance(d.get("routes"), list) and d["routes"]:
    keep = [r for r in d["routes"] if isinstance(r, dict)
            and truthy(r.get("endpoint"))
            and truthy(r.get("handler_function"))
            and truthy(r.get("handler_binary"))]
    if len(keep) < len(d["routes"]):
        pruned["dispatch.routes"] = len(d["routes"]) - len(keep)
        guard("dispatch.json routes", pruned["dispatch.routes"], len(d["routes"]))
        d["routes"] = keep
        rewrite("dispatch.json", d)
    if not d["routes"]:
        errors.append("dispatch.json: empty 'routes' after pruning")
elif isinstance(d, dict) and not errors:
    errors.append("dispatch.json: empty 'routes'")

# auth.json — no prunable shape: an unproven recipe is a real failure
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
n_items = n_pruned_items = 0
hollowed = 0
for fd in sorted(glob.glob(os.path.join(out, "functions", "*"))):
    if not os.path.isdir(fd):
        continue
    fname = os.path.basename(fd)
    n_here = 0
    both_files = True
    for kind, listkey, itemkey in (("sources.json", "sources", "field"),
                                   ("getters.json", "getters", "key")):
        p = os.path.join(fd, kind)
        if not os.path.isfile(p):
            errors.append(f"functions/{fname}/{kind}: missing")
            both_files = False
            continue
        try:
            j = json.load(open(p))
        except Exception as e:
            errors.append(f"functions/{fname}/{kind}: not valid JSON: {e}")
            both_files = False
            continue
        for k in ("binary", "function", "function_addr", "requests", listkey):
            if k not in j:
                errors.append(f"functions/{fname}/{kind}: missing '{k}'")
        items = j.get(listkey) or []
        n_items += len(items)
        keep = [it for it in items if isinstance(it, dict)
                and all(k in it for k in
                        ("call_addr", "ret_site", "callee", itemkey, "callsite"))]
        if len(keep) < len(items):
            n_pruned_items += len(items) - len(keep)
            j[listkey] = keep
            json.dump(j, open(p, "w"), indent=2, ensure_ascii=False)
        if kind == "sources.json":
            n_src += len(keep)
        else:
            n_get += len(keep)
        n_here += len(keep)
    # a folder exists iff it holds at least one site: a both-empty folder
    # (agent-written or pruned-empty) is removed with its files
    if both_files and n_here == 0:
        shutil.rmtree(fd)
        hollowed += 1
        continue
    n_pkgs += 1
if n_pruned_items:
    pruned["functions.items"] = n_pruned_items
    guard("functions items", n_pruned_items, n_items)
if hollowed:
    pruned["functions.packages_hollowed"] = hollowed
if n_pkgs == 0:
    errors.append("functions/: no work packages")

status = ("success" if not errors and agent_rc == 0
          else "agent_timeout" if agent_rc == 124
          else "output_incomplete" if agent_rc == 0
          else "agent_error")
result = {"task": task, "status": status, "agent_rc": agent_rc,
          "duration_s": agent_dur, "timeout_s": timeout,
          "packages": n_pkgs, "sources": n_src, "getters": n_get,
          "pruned": pruned, "errors": errors[:20]}
json.dump(result, open(os.path.join(rundir, "result.json"), "w"), indent=2)
print(f"[mapper-run] status={status} packages={n_pkgs} "
      f"sources={n_src} getters={n_get}")
if pruned:
    print(f"  pruned: {pruned}")
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
