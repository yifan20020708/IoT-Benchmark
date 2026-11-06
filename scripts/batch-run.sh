#!/bin/bash
# agent-scan :: batch-run.sh — parallel scheduler over a firmware task tree
#
# Usage: batch-run.sh [--jobs N] [--timeout SECONDS] [--no-promote] [--dry-run] <fw-root>
#
#   <fw-root>    any folder — discovery is fully recursive, so it may be
#                data/firmware (every vendor), data/firmware/tenda (one
#                vendor) or data/firmware/tenda/TEG5328FV1.0 (one task)
#   --jobs N     parallel slots (default 2). Whenever a slot's current task
#                finishes, the next queued task starts in it immediately
#                (work-stealing, not chunked waves)
#   --timeout S  per-task agent budget, passed to agent-run.sh (default 14400)
#   --no-promote do NOT chain commit-solved.sh on success (default: promote —
#                the promotion consumes the task container and untag raw,
#                which keeps long batches from exhausting the disk)
#   --dry-run    print the discovered/skipped/queued task lists and exit
#
# A TASK FOLDER = a directory containing task.json. Discovery excludes the
# archive/harvest directories that also contain task.json COPIES or extracted
# firmware trees: output/, output.attempt-*, rootfs/, decompiled-rootfs/.
#
# Resume: a folder with an existing result.json is SKIPPED — restart the
# batch any time and it picks up exactly where it stopped. Delete a task's
# result.json to force a retry. Ctrl-C is safe: in-flight tasks have no
# result.json yet, so the next run rebuilds them from scratch (agent-run
# replaces the task container); finished verdicts are never redone.
#
# Per-task console log: <task>/batch.log (agent-run's own agent.log lives in
# <task>/output/). Live START/END/progress lines and a final summary here.
#
# Parallel-safety: the loop-shim (scripts/loop-shim/losetup.sh) is installed
# by agent-run.sh into every task container — concurrent tasks are safe.
# Without it agent-run falls back to host-wide serialization (correct, but
# --jobs > 1 then only queues). Same-task concurrency is refused by
# agent-run's per-task lock regardless.
#
# Live view: scripts/batch-monitor.sh <fw-root> — same root argument; reads
# the atomic state file this script maintains (/tmp/agent-scan-monitor/).
set -euo pipefail

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

JOBS=2
TIMEOUT=14400
PROMOTE=1
DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
    --jobs)       JOBS="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2"; shift 2 ;;
    --no-promote) PROMOTE=0; shift ;;
    --dry-run)    DRY=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    -*)           echo "[-] unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)            break ;;
    esac
done
ROOTDIR="${1:?usage: batch-run.sh [--jobs N] [--timeout S] [--no-promote] [--dry-run] <fw-root>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -d "$ROOTDIR" ] || { echo "[-] no such folder: $ROOTDIR" >&2; exit 1; }
ROOTDIR="$(cd "$ROOTDIR" && pwd)"
case "$JOBS" in ''|*[!0-9]*|0) echo "[-] --jobs must be a positive integer" >&2; exit 1 ;; esac
case "$TIMEOUT" in ''|*[!0-9]*|0) echo "[-] --timeout must be a positive integer" >&2; exit 1 ;; esac
[ "$JOBS" -gt 1 ] && [ ! -f "$ROOT/scripts/loop-shim/losetup.sh" ] && \
    echo "[!] loop-shim missing — agent-run will serialize host-wide (--jobs=$JOBS only queues)" >&2

# ---- discovery (recursive; exclude harvest copies of task.json) ---------
mapfile -t ALL < <(find "$ROOTDIR" -type f -name task.json -printf '%h\n' \
    | grep -vE '/(output|rootfs|decompiled-rootfs)(/|$)' \
    | grep -vE '/output\.attempt-[^/]*(/|$)' \
    | sort -u)

TASKS=()
SKIPPED=0
for fw in "${ALL[@]}"; do
    if [ -f "$fw/result.json" ]; then
        SKIPPED=$((SKIPPED+1))
    else
        TASKS+=("$fw")
    fi
done

echo "===== agent-scan batch-run ====="
echo "root     : $ROOTDIR"
echo "jobs     : $JOBS   timeout: ${TIMEOUT}s   promote: $([ $PROMOTE = 1 ] && echo yes || echo no)"
echo "discovered ${#ALL[@]} task folder(s); skipped $SKIPPED (result.json present); queued ${#TASKS[@]}"

if [ "$DRY" = 1 ]; then
    for fw in "${TASKS[@]}"; do echo "  RUN  $fw"; done
    exit 0
fi
[ ${#TASKS[@]} -gt 0 ] || { echo "nothing to do"; exit 0; }
for fw in "${TASKS[@]}"; do echo "  queue: $fw"; done

# ---- live state for batch-monitor.sh -------------------------------------
# Atomic JSON (write tmp + rename), keyed by the root dir so concurrent
# batches on different roots never collide. Survives exit: the monitor
# renders the final frame post-mortem; a NEW batch simply overwrites it.
mkdir -p /tmp/agent-scan-monitor
SLUG=$(printf '%s' "$ROOTDIR" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/$SLUG.json"
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
    d = {"root": sys.argv[3], "jobs": int(sys.argv[4]), "timeout": int(sys.argv[5]),
         "promote": sys.argv[6] == "1", "started_at": time.time(), "finished_at": None,
         "total": int(sys.argv[7]), "skipped": int(sys.argv[8]),
         "queue": json.loads(sys.argv[9]),
         "running": [], "recent": [],
         "stats": {"n": 0, "dur_s": 0, "dur_success": 0, "by_status": {}, "promoted": 0}}
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
                           "at": time.time(), "promoted": False})
    del d["recent"][12:]
    s = d["stats"]
    s["n"] += 1; s["dur_s"] += dur
    if status == "success":
        s["dur_success"] += dur
    s["by_status"][status] = s["by_status"].get(status, 0) + 1
elif verb == "promoted":
    fw = sys.argv[3]
    for r in d["recent"]:
        if r["fw_dir"] == fw and not r["promoted"]:
            r["promoted"] = True
            d["stats"]["promoted"] += 1
            break
elif verb == "finish":
    d["finished_at"] = time.time()
save(d)
PYEOF
}
export -f state

QUEUE_JSON=$(printf '%s\n' "${TASKS[@]}" \
    | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
state init "$ROOTDIR" "$JOBS" "$TIMEOUT" "$PROMOTE" "${#TASKS[@]}" "$SKIPPED" "$QUEUE_JSON"

# ---- worker (exported; invoked by xargs, one call per queued task) ------
CNTF=$(mktemp /tmp/agent-scan-batch-cnt.XXXXXX)
LISTF=$(mktemp /tmp/agent-scan-batch-list.XXXXXX)
trap 'rm -f "$CNTF" "$LISTF" "$CNTF.lock" 2>/dev/null' EXIT
echo 0 > "$CNTF"
printf '%s\n' "${TASKS[@]}" > "$LISTF"
export ROOT BATCH_TIMEOUT="$TIMEOUT" BATCH_PROMOTE="$PROMOTE" TOTAL="${#TASKS[@]}" CNTF

run_one() {
    local fw="$1" log rc=0 st="-" n t0 promoted=0
    t0=$(date +%s)
    log="$fw/batch.log"
    # state mutations are serialized across workers by the state lock; the
    # pid lets the monitor flag stale entries after an interrupted batch
    exec 7>"$STATEF.lock"; flock 7
    state task-start "$fw" $$
    exec 7>&-
    echo "[batch $(date +%H:%M:%S)] START $fw"
    "$ROOT/scripts/agent-run.sh" --timeout "$BATCH_TIMEOUT" "$fw" >"$log" 2>&1 || rc=$?
    if [ "$rc" = 0 ] && [ "$BATCH_PROMOTE" = 1 ]; then
        "$ROOT/scripts/commit-solved.sh" "$fw" >>"$log" 2>&1 && promoted=1 || true
    fi
    if [ -f "$fw/result.json" ]; then
        st=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status","?"))' \
             "$fw/result.json" 2>/dev/null || echo "?")
    fi
    exec 7>"$STATEF.lock"; flock 7
    state task-end "$fw" "$st" "$rc" "$(( $(date +%s) - t0 ))"
    [ "$promoted" = 1 ] && state promoted "$fw"
    exec 7>&-
    exec 7>"$CNTF.lock"
    flock 7
    n=$(cat "$CNTF" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$CNTF"
    exec 7>&-
    echo "[batch $(date +%H:%M:%S)] END   $fw rc=$rc status=$st ($n/$TOTAL)"
}
export -f run_one

# ---- schedule: N slots, backfilled the moment a slot frees up ------------
printf '%s\n' "${TASKS[@]}" \
    | xargs -d '\n' -P "$JOBS" -n 1 bash -c 'run_one "$1"' _ || true

state finish || true

# ---- summary --------------------------------------------------------------
python3 - "$LISTF" <<'EOF'
import json, sys, os, collections
tasks = [l.strip() for l in open(sys.argv[1]) if l.strip()]
tally = collections.Counter()
solved, details = [], []
for fw in tasks:
    st, img = "?", ""
    try:
        d = json.load(open(os.path.join(fw, "result.json")))
        st = d.get("status", "?")
        img = d.get("image", "") or ""
    except Exception:
        st = "no-result"
    tally[st] += 1
    if st == "success":
        solved.append(os.path.basename(fw) + ("  [promoted]" if ":solved" in img else "  [NOT promoted]"))
    elif st != "success":
        details.append(f"{st:14s} {fw}")
print()
print("===== batch-run summary =====")
print(f"ran      : {len(tasks)}")
for st, n in sorted(tally.items()):
    print(f"  {st:14s}: {n}")
if solved:
    print("solved   :")
    for s in solved:
        print(f"  {s}")
if details:
    print("unfinished/failed (containers kept for inspection):")
    for d in details:
        print(f"  {d}")
EOF
echo
echo "retained task containers: $(docker ps -a --format '{{.Names}}' | grep -c '^task-' || true)"
echo "resume anytime: rerun this script — finished tasks are skipped"
