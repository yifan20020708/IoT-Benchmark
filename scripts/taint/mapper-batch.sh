#!/bin/bash
# agent-scan :: taint — mapper-batch.sh — parallel scheduler over the model tree
#
# Phase-1 Mapper only: the batch analog of scripts/rehost/batch-run.sh, one
# mapper-run.sh invocation per model folder.
#
# Usage: mapper-batch.sh [--jobs N] [--timeout S] [--dry-run] <fw-root>
#
#   <fw-root>    any folder — discovery is fully recursive, so it may be
#                data/firmware (every vendor), data/firmware/tenda (one
#                vendor) or a single model folder
#   --jobs N     parallel mapper slots (default 1 — see Parallel-safety)
#   --timeout S  per-model agent budget, passed to mapper-run.sh (default
#                7200, mapper-run.sh's own default)
#   --dry-run    print the discovered / skipped (with reason) / queued lists
#                and exit without running anything
#
# A MODEL FOLDER = a directory containing task.json, discovered with the same
# rules as rehost batch-run.sh (harvest copies of task.json under output/ and
# the extracted trees rootfs/ / decompiled-rootfs/ are excluded).
#
# Mapper eligibility, checked per model in this order:
#   1. taint-work/mapper-run/result.json exists  -> SKIPPED (already run;
#      delete that file to force a retry — mapper-run.sh regenerates
#      taint-work-output and its scratch itself, keeping only the Ghidra
#      project cache)
#   2. no task-<vendor__model>:solved image     -> SKIPPED (not rehosted
#      yet; the Mapper boots the solved image for its auth probing)
#   3. no decompiled-rootfs/                    -> SKIPPED (the Mapper's
#      primary code-reading surface)
#   4. otherwise                                -> queued
#
# Resume: restart the batch any time — models with a result.json are never
# redone. Ctrl-C is safe: an interrupted model has no result.json yet, so
# the next run rebuilds it from scratch (mapper-run.sh wipes the previous
# attempt's outputs on start).
#
# Parallel-safety: the Mapper's static phases (agent reasoning + host-side
# Ghidra call-site-dump) parallelize fine, but EVERY solved-image boot runs
# `add_partition` against the shared host /dev loop table, and the solved
# images predate the loop-shim — two parallel mappers' auth boots use
# identical container-internal image paths and can cross-claim loops
# (silent cross-model corruption). --jobs > 1 is opt-in and on your head.
#
# Per-model console log: <model>/taint-batch.log (deliberately NOT under
# taint-work/ — mapper-run.sh clears that tree on every start).
#
# Live view: scripts/taint/mapper-batch-monitor.sh <fw-root> — same root
# argument; reads the state file this script maintains.
set -euo pipefail

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; }

JOBS=1
TIMEOUT=7200
DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
    --jobs)    JOBS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)        echo "[-] unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)         break ;;
    esac
done
ROOTDIR="${1:?usage: mapper-batch.sh [--jobs N] [--timeout S] [--dry-run] <fw-root>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -d "$ROOTDIR" ] || { echo "[-] no such folder: $ROOTDIR" >&2; exit 1; }
ROOTDIR="$(cd "$ROOTDIR" && pwd)"
case "$JOBS" in ''|*[!0-9]*|0) echo "[-] --jobs must be a positive integer" >&2; exit 1 ;; esac
case "$TIMEOUT" in ''|*[!0-9]*|0) echo "[-] --timeout must be a positive integer" >&2; exit 1 ;; esac
[ "$JOBS" -gt 1 ] && echo "[!] --jobs > 1: concurrent solved-image AUTH BOOTS share the host" \
    "/dev loop table without the loop-shim and can cross-claim loops" \
    "(static phases are safe) — see Parallel-safety in the header" >&2

# ---- discovery (recursive; same exclusions as rehost batch-run.sh) --------
mapfile -t ALL < <(find "$ROOTDIR" -type f -name task.json -printf '%h\n' \
    | grep -vE '/(output|rootfs|decompiled-rootfs)(/|$)' \
    | grep -vE '/output\.attempt-[^/]*(/|$)' \
    | sort -u)

task_id() {
    printf '%s__%s' "$(basename "$(dirname "$1")")" "$(basename "$1")" \
        | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g'
}

TASKS=()
SKIPPED_DONE=0; SKIPPED_REHOST=(); SKIPPED_DECOMP=()
for fw in "${ALL[@]}"; do
    if [ -f "$fw/taint-work/mapper-run/result.json" ]; then
        SKIPPED_DONE=$((SKIPPED_DONE+1))
    elif ! docker image inspect "task-$(task_id "$fw"):solved" >/dev/null 2>&1; then
        SKIPPED_REHOST+=("$(basename "$fw")")
    elif [ ! -d "$fw/decompiled-rootfs" ]; then
        SKIPPED_DECOMP+=("$(basename "$fw")")
    else
        TASKS+=("$fw")
    fi
done

echo "===== agent-scan taint mapper-batch ====="
echo "root     : $ROOTDIR"
echo "jobs     : $JOBS   timeout: ${TIMEOUT}s"
echo "discovered ${#ALL[@]} model folder(s)"
echo "  skipped ${SKIPPED_DONE} (mapper result.json present)"
echo "  skipped ${#SKIPPED_REHOST[@]} (no solved image yet): ${SKIPPED_REHOST[*]:-none}"
echo "  skipped ${#SKIPPED_DECOMP[@]} (no decompiled-rootfs): ${SKIPPED_DECOMP[*]:-none}"
echo "queued ${#TASKS[@]}"

if [ "$DRY" = 1 ]; then
    for fw in "${TASKS[@]}"; do echo "  RUN  $fw"; done
    exit 0
fi
[ ${#TASKS[@]} -gt 0 ] || { echo "nothing to do"; exit 0; }
for fw in "${TASKS[@]}"; do echo "  queue: $fw"; done

# ---- live state for mapper-batch-monitor.sh -------------------------------
# Atomic JSON (write tmp + rename) under the same directory the rehost
# monitor uses, but namespaced "taint-" so the two batch families never
# collide on the same fw-root. Survives exit: the monitor renders its final
# frame post-mortem; a NEW batch simply overwrites it.
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
    d = {"root": sys.argv[3], "jobs": int(sys.argv[4]), "timeout": int(sys.argv[5]),
         "started_at": time.time(), "finished_at": None,
         "total": int(sys.argv[6]), "skipped": int(sys.argv[7]),
         "queue": json.loads(sys.argv[8]),
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
    pkgs, nsrc, nget = int(sys.argv[7]), int(sys.argv[8]), int(sys.argv[9])
    d["running"] = [r for r in d["running"] if r["fw_dir"] != fw]
    d["recent"].insert(0, {"fw_dir": fw, "task": os.path.basename(fw),
                           "status": status, "rc": rc, "dur_s": dur,
                           "packages": pkgs, "sources": nsrc, "getters": nget,
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
state init "$ROOTDIR" "$JOBS" "$TIMEOUT" "${#TASKS[@]}" \
    "$((SKIPPED_DONE + ${#SKIPPED_REHOST[@]} + ${#SKIPPED_DECOMP[@]}))" "$QUEUE_JSON"

# ---- worker (exported; invoked by xargs, one call per queued model) --------
CNTF=$(mktemp /tmp/agent-scan-taint-cnt.XXXXXX)
LISTF=$(mktemp /tmp/agent-scan-taint-list.XXXXXX)
trap 'rm -f "$CNTF" "$LISTF" "$CNTF.lock" 2>/dev/null' EXIT
echo 0 > "$CNTF"
printf '%s\n' "${TASKS[@]}" > "$LISTF"
export ROOT BATCH_TIMEOUT="$TIMEOUT" TOTAL="${#TASKS[@]}" CNTF

run_one() {
    local fw="$1" log rc=0 st="no-result" n t0 pkgs=0 nsrc=0 nget=0
    t0=$(date +%s)
    log="$fw/taint-batch.log"
    # per-model lock: refuse double-scheduling of the same model (another
    # batch worker, or a second batch on an overlapping root)
    exec 8>"$fw/taint-work.lock"
    if ! flock -n 8; then
        echo "[batch $(date +%H:%M:%S)] SKIP  $fw (locked — another mapper run owns it)"
        return 0
    fi
    exec 7>"$STATEF.lock"; flock 7
    state task-start "$fw" $$
    exec 7>&-
    echo "[batch $(date +%H:%M:%S)] START $fw"
    "$ROOT/scripts/taint/mapper-run.sh" --timeout "$BATCH_TIMEOUT" "$fw" >"$log" 2>&1 || rc=$?
    if [ -f "$fw/taint-work/mapper-run/result.json" ]; then
        read -r st pkgs nsrc nget < <(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("status", "?"), d.get("packages", 0),
          d.get("sources", 0), d.get("getters", 0))
except Exception:
    print("?", 0, 0, 0)' "$fw/taint-work/mapper-run/result.json")
    fi
    exec 7>"$STATEF.lock"; flock 7
    state task-end "$fw" "$st" "$rc" "$(( $(date +%s) - t0 ))" "$pkgs" "$nsrc" "$nget"
    exec 7>&-
    exec 9>"$CNTF.lock"; flock 9
    n=$(cat "$CNTF" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$CNTF"
    exec 9>&-
    echo "[batch $(date +%H:%M:%S)] END   $fw rc=$rc status=$st" \
         "(${pkgs} pkgs / ${nsrc} src / ${nget} get) ($n/$TOTAL)"
    exec 8>&-
}
export -f run_one

# ---- schedule: N slots, backfilled the moment a slot frees up --------------
printf '%s\n' "${TASKS[@]}" \
    | xargs -d '\n' -P "$JOBS" -n 1 bash -c 'run_one "$1"' _ || true

state finish || true

# ---- summary -----------------------------------------------------------------
python3 - "$LISTF" <<'EOF'
import json, sys, os, collections
tasks = [l.strip() for l in open(sys.argv[1]) if l.strip()]
tally = collections.Counter()
good, details = [], []
for fw in tasks:
    st, pkgs, nsrc, nget, dur = "?", 0, 0, 0, 0
    try:
        d = json.load(open(os.path.join(fw, "taint-work/mapper-run/result.json")))
        st = d.get("status", "?")
        pkgs, nsrc, nget = d.get("packages", 0), d.get("sources", 0), d.get("getters", 0)
        dur = d.get("duration_s", 0)
    except Exception:
        st = "no-result"
    tally[st] += 1
    line = (f"  {os.path.basename(fw):16s} {st:18s} {dur//60:>4}m "
            f"{pkgs:>4} pkgs {nsrc:>4} src {nget:>4} get")
    (good if st == "success" else details).append(line)
print()
print("===== mapper-batch summary =====")
print(f"ran      : {len(tasks)}")
for st, n in sorted(tally.items()):
    print(f"  {st:18s}: {n}")
if good:
    print("mapped   :")
    for g in good:
        print(g)
if details:
    print("unfinished/failed (retry: delete the model's taint-work/mapper-run/result.json):")
    for d in details:
        print(d)
EOF
echo
echo "resume anytime: rerun this script — mapped models are skipped"
