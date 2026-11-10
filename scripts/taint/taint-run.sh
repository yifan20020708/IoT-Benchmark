#!/bin/bash
# agent-scan :: taint — stage-2 task runner (host-side agent + driver verdict)
#
# Usage: taint-run.sh [--timeout <seconds>] [--regrade] <model-dir>
#   --regrade  grade the agent artifacts already on disk (probes.json +
#              summary.json must exist) with the driver's own validation
#              and fresh-canary verification — the post-agent code path
#              only. For interrupted runs: the verdict means exactly what
#              it would have meant had the agent exited normally.
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
#            verify-request.sh,gdb-recorder.py,
#            verify-batch.sh,chunk-probes.py,merge-verdicts.py,
#            assemble-functions.py}
#   AGENT  : writes <model>/taint-source/ (intermediates; the Ghidra project
#            cache survives re-runs — it is deterministic per binary) and
#            <model>/taint-source-output/ (summary.json, functions/*.json,
#            probes.json)
#   OUTPUT : <model>/taint-run/  — agent.log, agent-transcripts.tar,
#            validation.json, verify-verdicts.json, taint-result.json
#            <model>/taint-source-output/verified-callsites.json — the
#            driver's own dynamic-verification result (fresh canaries)
#   EXIT   : 0 = success; 1 = anything else
#
# Driver verdict (never trusting the agent):
#   1. schema validation of summary.json + functions/*.json
#   2. cross-check of every recorded call address against the Ghidra index
#      the agent itself built (fabricated call sites cannot survive this)
#   3. coverage checks: every entry of the probed binary must be attempted
#      by some probe (entry_break on its handler, or its endpoint/module
#      key in a request), and every recorded call site of the probed
#      binary must be armed in some probe's ret_breaks — unattempted
#      entries or unarmed sites fail the run
#   4. INDEPENDENT re-run of the agent's probes.json with fresh canaries
#      (from a driver-named spec copy, so the agent's own self-check
#      evidence is never clobbered) — verify-batch.sh splits the spec into
#      parallel boot chunks (a full-coverage batch cannot fit one boot),
#      then a repair round re-runs failures on clean boots; only genuine
#      request->taint-source flows pass. Probes carry "expect": "pass"
#      (default) | "unreachable" | "unfed"; only pass-expected failures
#      fail the run (a no-hit on an unreachable-expected probe is
#      harness-verified PROOF of unreachability; an unfed-expected probe
#      must prove its entry dispatched — reception-negative is not unproven)
#   5. write-back: every function record's call sites get a dynamic verify
#      status (verified | reached-unfed | not-reached | not-attempted) and
#      taint-source-output/verified-callsites.json is written
#   6. assemble: the flat function records are reorganized into
#      functions/<binary__function>/ folders (genuinely-RECEIVING functions
#      only — >=1 dynamically-verified call site — the next stage's
#      starting points, indexed by functions/INDEX.json) plus
#      functions-context/ for the rest; each folder holds the record and
#      probes.json split into reception_probes (fed this function's sites)
#      and context_probes (reached/armed without feeding — read-side
#      inventory for the next stage's storage channel)
#   status: success | agent_timeout | agent_error | fail
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # no __pycache__ anywhere in the pipeline

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"
ENV_FILE="$ROOT/.env"

TIMEOUT=7200
REGRADE=0
while [ $# -gt 1 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --regrade) REGRADE=1; shift ;;
        *) echo "usage: taint-run.sh [--timeout <seconds>] [--regrade] <model-dir>" >&2; exit 1 ;;
    esac
done
MODEL="${1:?usage: taint-run.sh [--timeout <seconds>] [--regrade] <model-dir>}"
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

if [ "$REGRADE" = 1 ]; then
    # --regrade: grade the artifacts ALREADY on disk (an interrupted run's
    # agent output) with the driver's own validation + fresh-canary
    # verification. No cleaning, no agent phase — the same code path a
    # normal run takes after the agent exits, so the verdict is identical
    # in meaning. agent rc/duration are not part of a regrade (the agent's
    # liveness was settled when the run was interrupted).
    mkdir -p "$RUNDIR"
    [ -f "$MODEL/taint-source-output/probes.json" ] \
        || { echo "[-] --regrade: no taint-source-output/probes.json on disk" >&2; exit 1; }
    [ -f "$MODEL/taint-source-output/summary.json" ] \
        || { echo "[-] --regrade: no taint-source-output/summary.json on disk" >&2; exit 1; }
    echo "[*] REGRADE MODE: skipping agent phase, grading existing artifacts"
else
    # fresh agent outputs; the Ghidra project cache is deterministic per binary
    # and expensive to rebuild, so it survives re-runs
    rm -rf "$MODEL/taint-source-output" "$RUNDIR"
    mkdir -p "$MODEL/taint-source-output" "$MODEL/taint-source" "$RUNDIR"
    find "$MODEL/taint-source" -mindepth 1 -maxdepth 1 ! -name ghidra-projects \
        -exec rm -rf {} + 2>/dev/null || true
fi

# ---- run the agent (host-side, model folder as cwd) ---------------------------
# The child claude must not inherit this session's inter-process state
# (messaging socket, session ids); credentials come from .env.
AGENT_RC=0
AGENT_DUR=0
MODE_ARG="regrade"
if [ "$REGRADE" != 1 ]; then
MODE_ARG="full"
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
fi   # end of the non-regrade agent phase

# ---- driver validation: schema + call-site cross-check ------------------------
echo "[*] driver validation (schema + index cross-check)..."
VALIDATE_RC=0
python3 - "$MODEL" "$RUNDIR" <<'EOF' || VALIDATE_RC=$?
import glob, json, os, re, sys

model, rundir = sys.argv[1:3]
out = os.path.join(model, "taint-source-output")
errors = []

# The validator's whole job is judging MALFORMED agent output, so dying on
# it — and skipping validation.json — is its worst failure mode: the real
# schema errors get swallowed and result.json's validation block stays
# empty (exactly what the W30E attempt-4 postmortem showed). Last-resort
# net: an uncaught crash becomes a reported finding, partial errors kept.
def _crash_hook(exc_type, exc, tb):
    import traceback
    json.dump({"schema_ok": False,
               "errors": errors + [
                   "validation crashed on agent output: "
                   + "".join(traceback.format_exception_only(exc_type, exc)).strip()],
               "crash_traceback": traceback.format_tb(tb, limit=6)},
              open(os.path.join(rundir, "validation.json"), "w"), indent=2)
    sys.exit(1)
sys.excepthook = _crash_hook

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

def ent_key(s):
    """normalized comparison key for a handler name / *0xADDR entry_break"""
    s = str(s or "").strip().lstrip("*").lower()
    return re.sub(r"^0x", "", s)

def hex_tail(s):
    """trailing hex-digit run (>= 4 chars) — matches name vs *0xADDR forms
    ('FUN_0001ae88' vs '*0x1ae88' both end in the address)"""
    m = re.search(r"([0-9a-f]{4,})$", s)
    return m.group(1) if m else None

# 1) summary.json schema
counts = {"boundary_binaries": 0, "taint_sources": 0, "entries": 0,
          "function_records": 0, "call_sites": 0}
if summary is not None:
    # only fields summary.json actually owns; the two counts_* keys below
    # are driver-computed aggregates, not summary fields
    for k in ("boundary_binaries", "taint_sources", "entries"):
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
        idx_rel = b.get("index")
        if not idx_rel or not isinstance(idx_rel, str) \
                or not os.path.isfile(os.path.join(model, idx_rel)):
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
    if not rel or not isinstance(rel, str):
        continue
    idx = load(os.path.join(model, rel), f"index of {b['path']}")
    if idx is None:
        continue
    sites = set()
    fns = set()
    funcs = idx.get("functions") or []
    if not isinstance(funcs, list):
        errors.append(f"index of {b.get('path')}: 'functions' must be a list")
        funcs = []
    for f in funcs:
        if not isinstance(f, dict):
            continue
        fns.add(f.get("name"))
        for cs in f.get("call_sites") or []:
            if isinstance(cs, dict) and cs.get("address"):
                sites.add(norm_addr(cs["address"]))
    indexes[b.get("path")] = {"sites": sites, "functions": fns}

source_names = {(s.get("binary"), s.get("function"))
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
    rec["_path"] = os.path.basename(path)
    records.append(rec)

# 4) probes.json must be a valid verifier spec + entry coverage
unattempted = []
unarmed = []
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
            if p.get("expect") not in (None, "pass", "unreachable", "unfed"):
                errors.append(f"probes.json: probe[{i}] 'expect' must be "
                              f"'pass', 'unreachable' or 'unfed'")
            if p.get("expect") == "unfed" and not p.get("entry_break"):
                errors.append(f"probes.json: probe[{i}] expect 'unfed' "
                              f"requires 'entry_break' (dispatch proof)")
        # entry coverage (the full-dynamic contract): every entry of the
        # PROBED binary must be attempted — entry_break on its handler, or
        # its endpoint AND key present in some probe's request. Entries of
        # other boundary binaries are exempt: one spec probes one binary
        # (multi-binary dynamic coverage is documented future work)
        handlers = {ent_key(p.get("entry_break"))
                    for p in probes["probes"] if p.get("entry_break")}
        tails = {hex_tail(h) for h in handlers} - {None}
        blobs = [" ".join(str(a) for a in p.get("request", []))
                 for p in probes["probes"]]
        for e in (summary or {}).get("entries", []):
            if e.get("binary") != probes.get("binary"):
                continue
            hk = ent_key(e.get("handler"))
            tail = hex_tail(hk)
            ep, key = str(e.get("endpoint") or ""), str(e.get("key") or "")
            blob_hit = any(ep and ep in b and (not key or key in b)
                           for b in blobs)
            if not (hk in handlers or (tail and tail in tails) or blob_hit):
                unattempted.append(
                    f"{e.get('endpoint') or e.get('key')} -> {e.get('handler')}")

        # armed-site coverage: every call site of the PROBED binary must be
        # armed in some probe's ret_breaks (breakpoints are free — a site
        # that cannot execute is honestly 'not-reached', but a site never
        # armed was never tested at all). Call sites of other boundary
        # binaries are exempt: one spec probes one binary.
        armed = {norm_addr(a)
                 for p in probes["probes"] for a in (p.get("ret_breaks") or [])}
        for rec in records:
            if rec.get("binary") != probes.get("binary"):
                continue
            where = os.path.basename(rec.get("_path", "?"))
            for c in rec.get("taint_source_calls") or []:
                a = c.get("call_address")
                if a and norm_addr(a) not in armed:
                    unarmed.append(f"{where}: {a}")

if errors:
    for e in errors:
        print(f"  [-] {e}")
if unattempted:
    print(f"  [-] {len(unattempted)} entries of the probed binary are not "
          f"attempted by any probe (contract: every entry attempted); "
          f"first: {unattempted[:5]}")
if unarmed:
    print(f"  [-] {len(unarmed)} call sites of the probed binary are not "
          f"armed in any probe's ret_breaks (contract: every call site "
          f"armed); first: {unarmed[:5]}")
ok = not errors and counts["boundary_binaries"] > 0 \
    and counts["taint_sources"] > 0 and counts["entries"] > 0 \
    and counts["function_records"] > 0
json.dump({"schema_ok": ok, "errors": errors, "counts": counts,
           "entries_unattempted": unattempted,
           "call_sites_unarmed": unarmed},
          open(os.path.join(rundir, "validation.json"), "w"), indent=2)
print(f"[validate] {'OK' if ok else 'FAILED'}: {counts}")
sys.exit(0 if ok else 1)
EOF

# ---- driver verification: independent re-run with fresh canaries --------------
VERIFY_RC="skipped"
if [ "$VALIDATE_RC" = 0 ]; then
    echo "[*] driver verification: re-running the agent's probes with fresh canaries..."
    # re-run from a DRIVER-named spec copy: the verifier derives its work
    # dir from the spec stem, so the agent's own self-check evidence under
    # taint-source/verify/probes/ is never clobbered
    cp "$MODEL/taint-source-output/probes.json" "$RUNDIR/driver-probes.json"
    VERIFY_RC=0
    # a full-coverage batch (one probe per entry, every ret_break armed) is
    # far bigger than ONE boot can carry: hundreds of armed breakpoints
    # also sit on the guest's own init path and grind it to a halt.
    # verify-batch.sh splits it into parallel boot chunks (the agent's
    # optional "chunks" hint in probes.json is honored), each with fresh
    # canaries, then repairs failures on clean boots. Merged verdicts keep
    # the single-run schema, and merged events land exactly where the
    # write-back below reads them (taint-source/verify/driver-probes/)
    bash "$SCRIPTS/verify-batch.sh" \
        --budget 1200 \
        --out "$RUNDIR/verify-verdicts.json" \
        --workdir "$MODEL/taint-source/verify/driver-probes" \
        "$MODEL" "$RUNDIR/driver-probes.json" || VERIFY_RC=$?
else
    echo "[*] skipping dynamic verification (validation failed)"
fi

# ---- verified call sites + taint-result.json (the driver's verdict) -----------
python3 - "$MODEL" "$RUNDIR" "$RUN_START_ISO" "$AGENT_DUR" "$AGENT_RC" \
    "$TIMEOUT" "${VALIDATE_RC:-1}" "$VERIFY_RC" "$MODE_ARG" <<'EOF'
import glob, json, os, re, sys, datetime

(model, rundir, started, agent_dur, agent_rc, timeout,
 validate_rc, verify_rc) = sys.argv[1:9]
mode = sys.argv[9] if len(sys.argv) > 9 else "full"
agent_dur, agent_rc, timeout = int(agent_dur), int(agent_rc), int(timeout)
validate_rc = int(validate_rc)
verify_rc = None if verify_rc == "skipped" else int(verify_rc)
out = os.path.join(model, "taint-source-output")

def norm(s):
    if isinstance(s, int):   # addresses may arrive as JSON numbers
        return format(s, "x")
    return re.sub(r"^0x", "", str(s)).lower().lstrip("0")

def ent_key(s):
    s = str(s or "").strip().lstrip("*").lower()
    return re.sub(r"^0x", "", s)

def load(p, default=None):
    try:
        return json.load(open(p))
    except Exception:
        return default

validation = load(os.path.join(rundir, "validation.json"), {})
counts = validation.get("counts", {})
unattempted = validation.get("entries_unattempted") or []
unarmed = validation.get("call_sites_unarmed") or []
probes = load(os.path.join(out, "probes.json"), {})
probe_list = probes.get("probes", []) if isinstance(probes, dict) else []
verdicts = load(os.path.join(rundir, "verify-verdicts.json"), {})

probe_expect = {p.get("id"): (p.get("expect") or "pass") for p in probe_list}
probe_ret_breaks = {p.get("id"): [norm(a) for a in (p.get("ret_breaks") or [])]
                    for p in probe_list}
probe_entry = {p.get("id"): ent_key(p.get("entry_break"))
               for p in probe_list if p.get("entry_break")}
probe_outcomes = {r.get("probe"): r.get("verdict")
                  for r in verdicts.get("probes", [])}
probe_records = {r.get("probe"): r for r in verdicts.get("probes", [])}

# ---- per-call-site dynamic status from the DRIVER's own re-run -----------
# Primary source: the ret_hit EVENTS themselves — a site is 'verified' only
# when its OWN return event carried the canary (a passing probe proves its
# entry's chain, but different sites in one closure can read different
# params). Event addresses are return sites (call address + arch delay:
# 4 on arm/aarch64, 8 on mips); map back by arithmetic.
# Fallback when no events file exists: probe-level attribution.
# verified      a return event at this site matched the canary
# reached-unfed return events at this site, none carried the canary (it
#               executed but read non-canary data)
# not-reached   armed in some probe's ret_breaks, never executed
# unknown       unrecognized verdict for its probes
# not-attempted never armed (applied when writing back to the records)
ORDER = ["verified", "reached-unfed", "not-reached", "unknown"]
all_armed = {a for lst in probe_ret_breaks.values() for a in lst}
site_canary = {}   # norm(call) -> True if any ret event there hit a canary
evp = os.path.join(model, "taint-source", "verify", "driver-probes",
                   "events.jsonl")
if os.path.exists(evp):
    for line in open(evp, errors="replace"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event") != "ret_hit" or not e.get("address"):
            continue
        a = re.sub(r"^\*?0x", "", str(e["address"])).lower()
        try:
            av = int(a, 16)
        except ValueError:
            continue
        for d in (4, 8):
            call = format(av - d, "x")
            if call in all_armed:
                if e.get("canary_hits"):
                    site_canary[call] = True
                elif call not in site_canary:
                    site_canary[call] = False
                break

call_status = {}
if site_canary:
    for a in all_armed:
        if a in site_canary:
            call_status[a] = "verified" if site_canary[a] else "reached-unfed"
        else:
            call_status[a] = "not-reached"
else:
    # fallback (no events available): a passing probe credits its armed
    # sites collectively — coarser than per-site events
    for pid, vd in probe_outcomes.items():
        st = {"pass": "verified", "no-canary": "reached-unfed",
              "no-hit": "not-reached"}.get(vd, "unknown")
        for a in probe_ret_breaks.get(pid, []):
            if a not in call_status or ORDER.index(st) < ORDER.index(call_status[a]):
                call_status[a] = st
verified_handlers = {probe_entry[pid] for pid, vd in probe_outcomes.items()
                     if vd == "pass" and pid in probe_entry}

tally = {}
if verdicts:
    # write-back: each function record's call sites get their dynamic status
    # (these records are the next stage's input — the verification follows
    # them into it, so nobody downstream has to trust a static claim)
    for path in sorted(glob.glob(os.path.join(out, "functions", "*.json"))):
        rec = load(path)
        if not rec or not isinstance(rec.get("taint_source_calls"), list):
            continue
        rt = {}
        for c in rec["taint_source_calls"]:
            a = norm(c["call_address"]) if c.get("call_address") else None
            c["verify"] = call_status.get(a, "not-attempted")
            rt[c["verify"]] = rt.get(c["verify"], 0) + 1
        rec["verify_summary"] = rt
        if rec.get("entry") is not None:
            rec["entry_verified"] = \
                ent_key(rec.get("function")) in verified_handlers
        json.dump(rec, open(path, "w"), indent=2, ensure_ascii=False)
        for k, n in rt.items():
            tally[k] = tally.get(k, 0) + n
    vcs = {
        "probes": probe_outcomes,
        "verified_call_addresses": sorted(
            a for a, st in call_status.items() if st == "verified"),
        "call_site_status": call_status,
        "totals": tally,
        "by_function": {},
    }
    for path in glob.glob(os.path.join(out, "functions", "*.json")):
        rec = load(path) or {}
        hits = sorted({norm(c["call_address"])
                       for c in rec.get("taint_source_calls", [])
                       if c.get("call_address") and
                       norm(c["call_address"]) in vcs["verified_call_addresses"]})
        if hits:
            vcs["by_function"][os.path.basename(path)[:-5]] = hits
    json.dump(vcs, open(os.path.join(out, "verified-callsites.json"), "w"),
              indent=2, ensure_ascii=False)

# ---- verdict: only pass-EXPECTED failures fail the run; a no-hit on an
# unreachable-expected probe is harness-verified proof of unreachability;
# an unfed-expected probe must still prove its entry DISPATCHED (reception-
# negative ≠ unproven: the claim "reachable but not fed" needs both halves)
expected_fail = sorted(pid for pid, exp in probe_expect.items()
                       if exp == "pass" and probe_outcomes.get(pid) != "pass")
unreachable_proved = sorted(pid for pid, exp in probe_expect.items()
                            if exp == "unreachable"
                            and probe_outcomes.get(pid) == "no-hit")
unfed_fail = sorted(pid for pid, exp in probe_expect.items()
                    if exp == "unfed" and not (
                        probe_outcomes.get(pid) == "pass"
                        or (probe_outcomes.get(pid) in ("no-canary", "no-hit")
                            and (probe_records.get(pid) or {})
                            .get("entry_verified"))))

reasons = []
if agent_rc != 0:
    reasons.append(f"agent exited rc={agent_rc} (see agent.log)")
if validate_rc != 0:
    reasons.append("schema validation failed")
if verify_rc is None:
    reasons.append("dynamic verification skipped (validation failed)")
elif verify_rc == 2:
    reasons.append("verification infrastructure failure")
elif not verdicts:
    reasons.append("no verdicts recorded")
elif expected_fail:
    reasons.append(f"{len(expected_fail)} expected-pass probe(s) failed: "
                   + ", ".join(expected_fail[:10]))
if unfed_fail:
    reasons.append(f"{len(unfed_fail)} unfed-expected probe(s) failed "
                   f"dispatch proof: " + ", ".join(unfed_fail[:10]))
if unattempted:
    reasons.append(f"{len(unattempted)} entries not attempted by any probe")
if unarmed:
    reasons.append(f"{len(unarmed)} call sites not armed in any probe")

success = (validate_rc == 0 and verdicts and verify_rc is not None
           and verify_rc != 2 and not expected_fail and not unfed_fail
           and not unattempted and not unarmed)
if success:
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
    "mode": mode,   # "full" (agent ran in this invocation) | "regrade"
    "status": status,
    "status_reasons": reasons,
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
        "exit_code": verify_rc,
        "all_pass": verdicts.get("all_pass", False),
        "web_ready": verdicts.get("web_ready"),
        "probes": probe_outcomes,
        "probes_expected_pass": sum(1 for v in probe_expect.values()
                                    if v == "pass"),
        "probes_unfed": sum(1 for v in probe_expect.values() if v == "unfed"),
        "probes_pass": sum(1 for v in probe_outcomes.values() if v == "pass"),
        "expected_pass_failures": expected_fail,
        "unfed_failures": unfed_fail,
        "unreachable_proved": unreachable_proved,
    },
    "coverage": {
        "boundary_binaries": counts.get("boundary_binaries", 0),
        "taint_sources": counts.get("taint_sources", 0),
        "entries": counts.get("entries", 0),
        "entries_unattempted": len(unattempted),
        "function_records": counts.get("function_records", 0),
        "call_sites": counts.get("call_sites", 0),
        "call_sites_unarmed": len(unarmed),
        "probes": len(probe_expect),
        "verified_call_sites": tally.get("verified", 0),
        "call_sites_reached_unfed": tally.get("reached-unfed", 0),
        "call_sites_not_reached": tally.get("not-reached", 0),
        "call_sites_not_attempted": tally.get("not-attempted", 0),
    },
}
# NOTE: written to taint-run/taint-result.json — the stage-qualified name
# can never collide with the model root's result.json, which belongs to the
# REHOST stage and must survive this stage untouched
result_path = os.path.join(rundir, "taint-result.json")
json.dump(result, open(result_path, "w"), indent=2, ensure_ascii=False)
print(f"[result] {result_path}  status={status}"
      + (f"  ({'; '.join(reasons)})" if reasons else ""))
EOF

# ---- assemble per-function folders (the next stage's working dirs) -----------
# a view step, never a gate: reports orphans, moves nothing on failure
echo "[*] assembling per-function folders..."
python3 "$SCRIPTS/assemble-functions.py" "$MODEL" \
    --verdicts "$RUNDIR/verify-verdicts.json" \
    --events "$MODEL/taint-source/verify/driver-probes/events.jsonl" || true

# ---- bytecode sweep ------------------------------------------------------------
# the agent may legitimately run `python3 -I` on firmware-derived data (isolated
# mode ignores PYTHONDONTWRITEBYTECODE), so __pycache__ can appear in its work
# dir despite the export; the DELIVERED state is swept deterministically
find "$MODEL/taint-source" "$MODEL/taint-source-output" \
    -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# ---- summary --------------------------------------------------------------------
STATUS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$RUNDIR/taint-result.json")
COV=$(python3 -c 'import json,sys;c=json.load(open(sys.argv[1]))["coverage"];print(" ".join(f"{k}={v}" for k,v in c.items()))' "$RUNDIR/taint-result.json")
REASONS=$(python3 -c 'import json,sys;print("; ".join(json.load(open(sys.argv[1])).get("status_reasons",[]))[:400])' "$RUNDIR/taint-result.json")
echo
echo "===== agent-scan taint: $TASK_ID ====="
echo "status    : $STATUS   (exit code follows this)"
[ -n "$REASONS" ] && echo "reasons   : $REASONS" || true
if [ "$REGRADE" = 1 ]; then
    echo "mode      : regrade (agent phase skipped; artifacts graded as-is)"
else
    echo "agent     : rc=$AGENT_RC duration=${AGENT_DUR}s timeout=${TIMEOUT}s"
fi
echo "validation: $RUNDIR/validation.json"
echo "verdicts  : $RUNDIR/verify-verdicts.json (fresh-canary re-run)"
echo "coverage  : $COV"
echo "result    : $RUNDIR/taint-result.json"
[ "$STATUS" = "success" ] || exit 1
