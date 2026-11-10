#!/bin/bash
# agent-scan :: taint batch-run.sh — parallel scheduler over the taint stage
#
# Usage: batch-run.sh [--jobs N] [--timeout S] [--regrade] [--dry-run] <fw-root>
#
#   <fw-root>    any folder — discovery is fully recursive, so it may be
#                data/firmware (every vendor), data/firmware/tenda (one
#                vendor) or data/firmware/tenda/W30EV2.0 (one task)
#   --jobs N     parallel slots (default 2). Whenever a slot's current task
#                finishes, the next queued task starts in it immediately
#                (work-stealing, not chunked waves)
#   --timeout S  per-task agent budget, passed to taint-run.sh (default 14400)
#   --regrade    pass --regrade to taint-run.sh: grade the agent artifacts
#                already on disk instead of running the agent. Tasks WITHOUT
#                taint-source-output/probes.json are skipped (nothing to
#                grade); tasks WITH a taint-run/taint-result.json are skipped
#                like in a normal batch (already graded)
#   --dry-run    print the discovered/skipped/queued task lists and exit
#
# A TASK FOLDER = a directory containing task.json, PLUS a solved image
# (task-<id>:solved — the taint stage only runs on rehost-solved tasks;
# unsolved tasks are skipped at discovery, not failed).
#
# Resume: a folder with an existing taint-run/taint-result.json is SKIPPED —
# restart the batch any time and it picks up exactly where it stopped. Delete
# a task's taint-run/taint-result.json to force a retry. Ctrl-C is safe:
# in-flight tasks have no taint-result.json yet, so the next run rebuilds
# them from scratch; finished verdicts are never redone.
#
# Same-task concurrency is refused by taint-run.sh's per-task flock: the
# refused task fast-fails with no result file, so it stays retryable on the
# next batch invocation (run the batch again once the direct run finishes).
#
# Per-task console log: <task>/taint-batch.log (taint-run's own agent.log
# lives in <task>/taint-run/). Live START/END lines and a final summary here.
#
# Live view: scripts/taint/batch-monitor.sh <fw-root> — same root argument;
# reads the atomic state file this script maintains (separate taint-*
# namespace under /tmp/agent-scan-monitor/, so a rehost batch on the same
# root never collides with a taint batch).
set -euo pipefail

usage() { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; }

JOBS=2
TIMEOUT=14400
REGRADE=0
DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
    --jobs)    JOBS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --regrade) REGRADE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)        echo "[-] unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)         break ;;
    esac
done
ROOTDIR="${1:?usage: batch-run.sh [--jobs N] [--timeout S] [--regrade] [--dry-run] <fw-root>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -d "$ROOTDIR" ] || { echo "[-] no such folder: $ROOTDIR" >&2; exit 1; }
ROOTDIR="$(cd "$ROOTDIR" && pwd)"
case "$JOBS" in ''|*[!0-9]*|0) echo "[-] --jobs must be a positive integer" >&2; exit 1 ;; esac
case "$TIMEOUT" in ''|*[!0-9]*|0) echo "[-] --timeout must be a positive integer" >&2; exit 1 ;; esac

task_id() {   # <model-dir> -> tenda__w30ev2-0
    printf '%s__%s' "$(basename "$(dirname "$1")")" "$(basename "$1")" \
        | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g'
}

# ---- discovery (recursive; same exclusions as the rehost batch) ------------
mapfile -t ALL < <(find "$ROOTDIR" -type f -name task.json -printf '%h\n' \
    | grep -vE '/(output|rootfs|decompiled-rootfs)(/|$)' \
    | grep -vE '/output\.attempt-[^/]*(/|$)' \
    | sort -u)

TASKS=()
SKIPPED_DONE=0
SKIPPED_UNSOLVED=0
SKIPPED_NOART=0
for fw in "${ALL[@]}"; do
    tid=$(task_id "$fw")
    if [ -f "$fw/taint-run/taint-result.json" ]; then
        SKIPPED_DONE=$((SKIPPED_DONE+1))                 # graded — resume rule
    elif ! docker image inspect "task-$tid:solved" >/dev/null 2>&1; then
        SKIPPED_UNSOLVED=$((SKIPPED_UNSOLVED+1))         # rehost not solved yet
    elif [ "$REGRADE" = 1 ] && [ ! -f "$fw/taint-source-output/probes.json" ]; then
        SKIPPED_NOART=$((SKIPPED_NOART+1))               # nothing to regrade
    else
        TASKS+=("$fw")
    fi
done

echo "===== agent-scan taint batch-run ====="
echo "root     : $ROOTDIR"
echo "jobs     : $JOBS   timeout: ${TIMEOUT}s   mode: $([ $REGRADE = 1 ] && echo regrade || echo full)"
echo "discovered ${#ALL[@]} task folder(s); skipped: $SKIPPED_DONE graded, $SKIPPED_UNSOLVED unsolved${SKIPPED_NOART:+, $SKIPPED_NOART no-artifacts}; queued ${#TASKS[@]}"

if [ "$DRY" = 1 ]; then
    for fw in "${TASKS[@]}"; do echo "  RUN  $fw"; done
    exit 0
fi
[ ${#TASKS[@]} -gt 0 ] || { echo "nothing to do"; exit 0; }
for fw in "${TASKS[@]}"; do echo "  queue: $fw"; done

# ---- live state for batch-monitor.sh (taint-* namespace) -------------------
# Atomic JSON (write tmp + rename), keyed by root dir + stage so concurrent
# rehost/taint batches on the same root never collide. Survives exit: the
# monitor renders the final frame post-mortem; a NEW batch overwrites it.
mkdir -p /tmp/agent-scan-monitor
SLUG=$(printf '%s' "$ROOTDIR" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/taint-$SLUG.json"
export STATEF

state() {
    python3 - "$STATEF" "$@" <<'PYEOF'
import json, sys, os, time
path, verb = sys.argv[1], sys.argv[2]

def save(d):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, path)          # atomic: readers never see a torn file

try:
    d = json.load(open(path))
except Exception:
    d = None
if verb == "init":
    d = {"stage": "taint", "root": sys.argv[3], "jobs": int(sys.argv[4]),
         "timeout": int(sys.argv[5]), "regrade": sys.argv[6] == "1",
         "started_at": time.time(), "finished_at": None,
         "total": int(sys.argv[7]), "skipped": int(sys.argv[8]),
         "queue": json.loads(sys.argv[9]),
         "running": [], "recent": [],
         "stats": {"n": 0, "dur_s": 0, "dur_success": 0, "by_status": {}}}
elif d is None:
    sys.exit(0)
elif verb == "task-start":
    fw, pid = sys.argv[3], int(sys.argv[4])
    d["queue"] = [q for q in d["queue"] if q != fw]
    d["running"].append({"fw_dir": fw, "task": os.path.basename(fw),
                         "pid": pid, "started_at": time.time()})
elif verb == "task-end":
    fw, status, rc, dur = sys.argv[3], sys.argv[4], int(sys.argv[5]), float(sys.argv[6])
    d["running"] = [r for r in d["running"] if r["fw_dir"] != fw]
    d["recent"].insert(0, {"fw_dir": fw, "task": os.path.basename(fw),
                           "status": status, "rc": rc, "dur_s": dur,
                           "at": time.time()})
    del d["recent"][12:]
    s = d["stats"]
    s["n"] += 1; s["dur_s"] += dur
    if status == "success":
        s["dur_success"] += dur
    s["by_status"][status] = s["by_status"].get(status, 0) + 1
elif verb == "finish":
    d["finished_at"] = time.time()
save(d)
PYEOF
}
export -f state

QUEUE_JSON=$(printf '%s\n' "${TASKS[@]}" \
    | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
state init "$ROOTDIR" "$JOBS" "$TIMEOUT" "$REGRADE" "${#TASKS[@]}" \
    "$(( SKIPPED_DONE + SKIPPED_UNSOLVED + SKIPPED_NOART ))" "$QUEUE_JSON"

# ---- worker (exported; invoked by xargs, one call per queued task) ----------
CNTF=$(mktemp /tmp/agent-scan-taint-cnt.XXXXXX)
LISTF=$(mktemp /tmp/agent-scan-taint-list.XXXXXX)
trap 'rm -f "$CNTF" "$LISTF" "$CNTF.lock" 2>/dev/null' EXIT
echo 0 > "$CNTF"
printf '%s\n' "${TASKS[@]}" > "$LISTF"
export ROOT BATCH_TIMEOUT="$TIMEOUT" BATCH_REGRADE="$REGRADE" TOTAL="${#TASKS[@]}" CNTF

run_one() {
    local fw="$1" log rc=0 st="no-result" n t0
    t0=$(date +%s)
    log="$fw/taint-batch.log"
    # state mutations are serialized across workers by the state lock; the
    # pid lets the monitor flag stale entries after an interrupted batch
    exec 7>"$STATEF.lock"; flock 7
    state task-start "$fw" $$
    exec 7>&-
    echo "[batch $(date +%H:%M:%S)] START $fw"
    if [ "$BATCH_REGRADE" = 1 ]; then
        "$ROOT/scripts/taint/taint-run.sh" --regrade --timeout "$BATCH_TIMEOUT" \
            "$fw" >"$log" 2>&1 || rc=$?
    else
        "$ROOT/scripts/taint/taint-run.sh" --timeout "$BATCH_TIMEOUT" \
            "$fw" >"$log" 2>&1 || rc=$?
    fi
    if [ -f "$fw/taint-run/taint-result.json" ]; then
        st=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status","?"))' \
             "$fw/taint-run/taint-result.json" 2>/dev/null || echo "?")
    fi
    exec 7>"$STATEF.lock"; flock 7
    state task-end "$fw" "$st" "$rc" "$(( $(date +%s) - t0 ))"
    exec 7>&-
    exec 7>"$CNTF.lock"
    flock 7
    n=$(cat "$CNTF" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$CNTF"
    exec 7>&-
    echo "[batch $(date +%H:%M:%S)] END   $fw rc=$rc status=$st ($n/$TOTAL)"
}
export -f run_one

# ---- schedule: N slots, backfilled the moment a slot frees up ---------------
printf '%s\n' "${TASKS[@]}" \
    | xargs -d '\n' -P "$JOBS" -n 1 bash -c 'run_one "$1"' _ || true

state finish || true

# ---- summary ------------------------------------------------------------------
python3 - "$LISTF" <<'EOF'
import json, sys, os, collections
tasks = [l.strip() for l in open(sys.argv[1]) if l.strip()]
tally = collections.Counter()
ok, bad = [], []
for fw in tasks:
    st = "no-result"
    cov = {}
    dur = 0
    try:
        d = json.load(open(os.path.join(fw, "taint-run", "taint-result.json")))
        st = d.get("status", "?")
        cov = d.get("coverage", {}) or {}
        dur = (d.get("agent") or {}).get("duration_s") or 0
    except Exception:
        pass
    tally[st] += 1
    name = os.path.basename(fw)
    if st == "success":
        ok.append(f"{name}  probes={cov.get('probes')} verified_sites="
                  f"{cov.get('verified_call_sites')} entries={cov.get('entries')}"
                  f"  ({dur}s)")
    else:
        bad.append(f"{st:14s} {fw}")
print()
print("===== taint batch-run summary =====")
print(f"ran      : {len(tasks)}")
for st, n in sorted(tally.items()):
    print(f"  {st:14s}: {n}")
if ok:
    print("success  :")
    for s in ok:
        print(f"  {s}")
if bad:
    print("unfinished/failed (see <task>/taint-batch.log and taint-run/):")
    for d in bad:
        print(f"  {d}")
EOF
echo
echo "resume anytime: rerun this script — graded tasks are skipped"
