#!/bin/bash
# agent-scan :: taint — stage-2 task runner (host-side agent + driver verdict)
#
# Usage: taint-run.sh [--timeout <seconds>] <model-dir>
#
#   <model-dir>   a data/firmware/<brand>/<model> folder with task.json and
#                 rootfs/, whose emulation is SOLVED (image
#                 task-<brand>__<model>:solved must exist — this stage only
#                 runs on solved tasks).
#   --timeout     agent-phase wall-clock budget in seconds (default 7200).
#
# Unlike the rehost stage (agent inside a task container), the taint agent
# runs HOST-SIDE: its tools are host tools (Ghidra in deps/, gdb-multiarch)
# and its subject is the model folder itself. The agent is launched from the
# model folder with a scrubbed environment (no inter-session CLAUDE_* vars,
# credentials sourced from $ROOT/.env).
#
# I/O contract
#   INPUT  : <model>/task.json, <model>/rootfs/, solved image, $ROOT/.env,
#            scripts/taint/{taint-prompt.md,frontend-keywords.py,
#            ghidra-index.sh,IndexExporter.java,taint-query.py,
#            verify-request.sh,gdb-recorder.py}
#   AGENT  : writes <model>/taint-source/ (intermediates; the Ghidra project
#            cache survives re-runs — it is deterministic per binary) and
#            <model>/taint-source-output/ (summary.json, functions/*.json,
#            probes.json)
#   OUTPUT : <model>/taint-run/  — agent.log, agent-transcripts.tar,
#            validation.json, verify-verdicts.json, result.json
#            <model>/taint-source-output/verified-callsites.json — the
#            driver's own dynamic-verification result (fresh canaries)
#   EXIT   : 0 = success; 1 = anything else
#
# Driver verdict (never trusting the agent):
#   1. schema validation of summary.json + functions/*.json
#   2. cross-check of every recorded call address against the Ghidra index
#      the agent itself built (fabricated call sites cannot survive this)
#   3. INDEPENDENT re-run of verify-request.sh on the agent's probes.json
#      with fresh canaries and a fresh container — only genuine request->
#      taint-source flows pass; the agent never saw these canaries
#   status: success | agent_timeout | agent_error | fail
#           (fail = schema invalid, probes missing, or verification failed)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"
ENV_FILE="$ROOT/.env"

TIMEOUT=7200
while [ $# -gt 1 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "usage: taint-run.sh [--timeout <seconds>] <model-dir>" >&2; exit 1 ;;
    esac
done
MODEL="${1:?usage: taint-run.sh [--timeout <seconds>] <model-dir>}"
MODEL="$(cd "$MODEL" 2>/dev/null && pwd)" || { echo "[-] no such folder: $1" >&2; exit 1; }
[ -f "$MODEL/task.json" ] || { echo "[-] missing task.json in $MODEL" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE" >&2; exit 1; }
command -v gdb-multiarch >/dev/null || { echo "[-] gdb-multiarch missing on host" >&2; exit 1; }

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "[-] no solved image for this task: $IMAGE (run the rehost stage first)" >&2; exit 1; }

# one run per task folder at a time (agent + verifier share the per-task
# container name); DIFFERENT tasks may run in parallel
TASKLOCK=/tmp/agent-scan-taint-$(printf '%s' "$TASK_ID" | tr -c 'a-z0-9._-' '-').lock
exec 8>"$TASKLOCK"
flock -n 8 || { echo "[-] another taint-run is already processing $TASK_ID" >&2; exit 1; }

RUN_START=$(date +%s)
RUN_START_ISO=$(date -Iseconds)
RUNDIR="$MODEL/taint-run"

echo "[*] task=$TASK_ID model=$MODEL timeout=${TIMEOUT}s"

# fresh agent outputs; the Ghidra project cache is deterministic per binary
# and expensive to rebuild, so it survives re-runs
rm -rf "$MODEL/taint-source-output" "$RUNDIR"
mkdir -p "$MODEL/taint-source-output" "$MODEL/taint-source" "$RUNDIR"
find "$MODEL/taint-source" -mindepth 1 -maxdepth 1 ! -name ghidra-projects \
    -exec rm -rf {} + 2>/dev/null || true

# ---- run the agent (host-side, model folder as cwd) ---------------------------
# The child claude must not inherit this session's inter-process state
# (messaging socket, session ids); credentials come from .env.
AGENT_START=$(date +%s)
# render the mission brief with the absolute scripts path ({{SCRIPTS}})
sed "s|{{SCRIPTS}}|$SCRIPTS|g" "$SCRIPTS/taint-prompt.md" > "$RUNDIR/prompt.rendered.md"
echo "[*] starting taint agent (effort=max, ${TIMEOUT}s budget)..."
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
AGENT_END=$(date +%s)
AGENT_DUR=$((AGENT_END - AGENT_START))

# full agent transcript (best-effort): session files the child wrote live
# under ~/.claude/projects/<cwd-slug>/ — restricted to the model-dir slug so
# this driver's own (concurrently writing) session file is never included.
# Claude slugs map every non [a-zA-Z0-9_-] char to '-' ("W30EV2.0" -> "W30EV2-0")
SLUG="-$(printf '%s' "$MODEL" | sed 's|^/||; s|[^a-zA-Z0-9_-]|-|g')"
find "$HOME/.claude/projects/$SLUG" -name '*.jsonl' -newermt "@$RUN_START" \
    -exec tar -rf "$RUNDIR/agent-transcripts.tar" {} + 2>/dev/null || true

# ---- driver validation: schema + call-site cross-check ------------------------
echo "[*] driver validation (schema + index cross-check)..."
VALIDATE_RC=0
python3 - "$MODEL" "$RUNDIR" <<'EOF' || VALIDATE_RC=$?
import glob, json, os, re, sys

model, rundir = sys.argv[1:3]
out = os.path.join(model, "taint-source-output")
errors = []

def load(path, what):
    try:
        return json.load(open(path))
    except FileNotFoundError:
        errors.append(f"missing {what}: {os.path.relpath(path, model)}")
    except json.JSONDecodeError as e:
        errors.append(f"{what} is not valid JSON: {e}")
    return None

summary = load(os.path.join(out, "summary.json"), "summary.json")
probes = load(os.path.join(out, "probes.json"), "probes.json")

def norm_addr(s):
    if isinstance(s, int):   # agents may write addresses as JSON numbers
        return format(s, "x")
    return re.sub(r"^0x", "", str(s)).lower().lstrip("0")

# 1) summary.json schema
counts = {"boundary_binaries": 0, "taint_sources": 0, "entries": 0,
          "function_records": 0, "call_sites": 0}
if summary is not None:
    for k in counts:
        v = summary.get(k)
        if not isinstance(v, list):
            errors.append(f"summary.json: '{k}' must be a list")
    for b in summary.get("boundary_binaries", []):
        if not b.get("path") or not b.get("role") or not b.get("evidence"):
            errors.append("summary.json: boundary binary entry missing path/role/evidence")
            continue
        if not os.path.isfile(os.path.join(model, b["path"])):
            errors.append(f"boundary binary does not exist: {b['path']}")
            continue
        # the index path is REQUIRED: it is the cross-check table for every
        # call address the agent records downstream
        if not b.get("index") or not os.path.isfile(os.path.join(model, b["index"])):
            errors.append(f"boundary binary entry missing/invalid 'index': {b.get('path')}")
            continue
        counts["boundary_binaries"] += 1
    for s in summary.get("taint_sources", []):
        if not s.get("binary") or not s.get("function") or s.get("kind") not in ("named", "wrapper"):
            errors.append(f"taint source entry invalid: {s}")
            continue
        counts["taint_sources"] += 1
    for e in summary.get("entries", []):
        if not e.get("binary") or not (e.get("endpoint") or e.get("key")) or not e.get("handler"):
            errors.append(f"entry record invalid: {e}")
            continue
        counts["entries"] += 1

# 2) index cross-check tables: every call address recorded in functions/*.json
#    must be a REAL call site in the Ghidra index of that binary
indexes = {}   # binary path -> {call addresses (normalized), function names}
for b in (summary or {}).get("boundary_binaries", []):
    rel = b.get("index")
    if not rel:
        continue
    idx = load(os.path.join(model, rel), f"index of {b['path']}")
    if idx is None:
        continue
    sites = set()
    fns = set()
    for f in idx.get("functions", []):
        fns.add(f["name"])
        for cs in f.get("call_sites", []):
            if cs.get("address"):
                sites.add(norm_addr(cs["address"]))
    indexes[b["path"]] = {"sites": sites, "functions": fns}

source_names = {(s["binary"], s["function"])
                for s in (summary or {}).get("taint_sources", [])}
records = []
for path in sorted(glob.glob(os.path.join(out, "functions", "*.json"))):
    rec = load(path, "function record")
    if rec is None:
        continue
    where = os.path.basename(path)
    for k in ("binary", "function", "address", "taint_source_calls"):
        if k not in rec:
            errors.append(f"{where}: missing field '{k}'")
    calls = rec.get("taint_source_calls") or []
    if not isinstance(calls, list) or not calls:
        errors.append(f"{where}: taint_source_calls must be a non-empty list")
        continue
    idx = indexes.get(rec.get("binary"))
    if rec.get("binary") not in indexes:
        errors.append(f"{where}: binary '{rec.get('binary')}' is not a "
                      f"summary-declared boundary binary (cannot cross-check)")
    for c in calls:
        if not c.get("source") or not c.get("call_address"):
            errors.append(f"{where}: call record missing source/call_address")
            continue
        if (rec.get("binary"), c["source"]) not in source_names:
            errors.append(f"{where}: source '{c['source']}' not declared in summary.json")
        if idx is not None and norm_addr(c["call_address"]) not in idx["sites"]:
            errors.append(
                f"{where}: call address {c['call_address']} not found in the "
                f"Ghidra index of {rec.get('binary')} (fabricated?)")
        counts["call_sites"] += 1
    if idx is not None and rec.get("function") not in idx["functions"]:
        errors.append(f"{where}: function '{rec.get('function')}' not in the index")
    counts["function_records"] += 1
    records.append(rec)

# 3) probes.json must be a valid verifier spec
if probes is not None:
    if not isinstance(probes.get("probes"), list) or not probes["probes"]:
        errors.append("probes.json: must hold a non-empty 'probes' list")
    elif not probes.get("binary"):
        errors.append("probes.json: missing 'binary'")
    else:
        for i, p in enumerate(probes["probes"]):
            for k in ("id", "request", "source_break"):
                if not p.get(k):
                    errors.append(f"probes.json: probe[{i}] missing {k}")

if errors:
    for e in errors:
        print(f"  [-] {e}")
ok = not errors and counts["boundary_binaries"] > 0 \
    and counts["taint_sources"] > 0 and counts["entries"] > 0 \
    and counts["function_records"] > 0
json.dump({"schema_ok": ok, "errors": errors, "counts": counts},
          open(os.path.join(rundir, "validation.json"), "w"), indent=2)
print(f"[validate] {'OK' if ok else 'FAILED'}: {counts}")
sys.exit(0 if ok else 1)
EOF

# ---- driver verification: independent re-run with fresh canaries --------------
VERIFY_RC=""
if [ "$VALIDATE_RC" = 0 ]; then
    echo "[*] driver verification: re-running the agent's probes with fresh canaries..."
    VERIFY_RC=0
    # a full probe batch (many probes, one boot) needs more than the 900s
    # default of an interactive self-check run
    bash "$SCRIPTS/verify-request.sh" \
        --budget 2400 \
        --out "$RUNDIR/verify-verdicts.json" \
        "$MODEL" "$MODEL/taint-source-output/probes.json" || VERIFY_RC=$?
else
    echo "[*] skipping dynamic verification (validation failed)"
fi

# ---- verified call sites + result.json (the driver's verdict) ------------------
python3 - "$MODEL" "$RUNDIR" "$RUN_START_ISO" "$AGENT_DUR" "$AGENT_RC" \
    "$TIMEOUT" "${VALIDATE_RC:-1}" "${VERIFY_RC:-1}" <<'EOF'
import glob, json, os, re, sys, datetime

(model, rundir, started, agent_dur, agent_rc, timeout,
 validate_rc, verify_rc) = sys.argv[1:9]
agent_dur, agent_rc, timeout = int(agent_dur), int(agent_rc), int(timeout)
validate_rc, verify_rc = int(validate_rc), int(verify_rc)
out = os.path.join(model, "taint-source-output")

def norm(s):
    if isinstance(s, int):   # addresses may arrive as JSON numbers
        return format(s, "x")
    return re.sub(r"^0x", "", str(s)).lower().lstrip("0")

def load(p, default=None):
    try:
        return json.load(open(p))
    except Exception:
        return default

validation = load(os.path.join(rundir, "validation.json"), {})
counts = validation.get("counts", {})
probes = load(os.path.join(out, "probes.json"), {"probes": []})
verdicts = load(os.path.join(rundir, "verify-verdicts.json"), {})

# map the driver's own verification outcome back onto the agent's function
# records: a passing probe proves its ret_breaks (call sites) and its
# entry_break (the handler's dispatch entry)
vcs = {"probes": {}, "verified_call_addresses": [], "by_function": {}}
if verdicts:
    for r in verdicts.get("probes", []):
        vcs["probes"][r["probe"]] = r["verdict"]
        if r["verdict"] == "pass":
            for p in probes.get("probes", []):
                if p["id"] == r["probe"]:
                    vcs["verified_call_addresses"] += [
                        norm(a) for a in p.get("ret_breaks", [])]
    vcs["verified_call_addresses"] = sorted(set(vcs["verified_call_addresses"]))
    for path in glob.glob(os.path.join(out, "functions", "*.json")):
        rec = load(path) or {}
        hits = sorted({norm(c["call_address"])
                       for c in rec.get("taint_source_calls", [])
                       if c.get("call_address") and
                       norm(c["call_address"]) in vcs["verified_call_addresses"]})
        if hits:
            key = os.path.basename(path)[:-5]
            vcs["by_function"][key] = hits
    json.dump(vcs, open(os.path.join(out, "verified-callsites.json"), "w"),
              indent=2, ensure_ascii=False)

if validate_rc == 0 and verify_rc == 0:
    status = "success"
elif agent_rc == 124:
    status = "agent_timeout"
elif agent_rc != 0:
    status = "agent_error"
else:
    status = "fail"

result = {
    "task": "/".join(model.rstrip("/").split("/")[-2:]),
    "stage": "taint",
    "status": status,
    "started_at": started,
    "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "agent": {
        "duration_s": agent_dur,
        "timed_out": agent_rc == 124,
        "exit_code": agent_rc,
        "timeout_s": timeout,
        "log": "taint-run/agent.log",
    },
    "validation": validation,
    "verification": {
        "exit_code": verify_rc if verify_rc >= 0 else None,
        "all_pass": verdicts.get("all_pass", False),
        "web_ready": verdicts.get("web_ready"),
        "probes": {k: v for k, v in vcs["probes"].items()},
    },
    "coverage": {
        "boundary_binaries": counts.get("boundary_binaries", 0),
        "taint_sources": counts.get("taint_sources", 0),
        "entries": counts.get("entries", 0),
        "function_records": counts.get("function_records", 0),
        "call_sites": counts.get("call_sites", 0),
        "verified_call_sites": len(vcs["verified_call_addresses"]),
    },
}
# NOTE: written to taint-run/ — the model root's result.json belongs to the
# REHOST stage and must survive this stage untouched
RESULT_JSON="$RUNDIR/result.json"
json.dump(result, open(RESULT_JSON, "w"), indent=2, ensure_ascii=False)
print(f"[result] {RESULT_JSON}  status={status}")
EOF

# ---- summary --------------------------------------------------------------------
STATUS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$RUNDIR/result.json")
COV=$(python3 -c 'import json,sys;c=json.load(open(sys.argv[1]))["coverage"];print(" ".join(f"{k}={v}" for k,v in c.items()))' "$RUNDIR/result.json")
echo
echo "===== agent-scan taint: $TASK_ID ====="
echo "status    : $STATUS   (exit code follows this)"
echo "agent     : rc=$AGENT_RC duration=${AGENT_DUR}s timeout=${TIMEOUT}s"
echo "validation: $RUNDIR/validation.json"
echo "verdicts  : $RUNDIR/verify-verdicts.json (fresh-canary re-run)"
echo "coverage  : $COV"
echo "result    : $RUNDIR/result.json"
[ "$STATUS" = "success" ] || exit 1
