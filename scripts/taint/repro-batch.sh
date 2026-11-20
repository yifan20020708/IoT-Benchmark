#!/bin/bash
# agent-scan :: taint — repro batch: CNVD reproduction packs over the vault
#
# Usage: repro-batch.sh [--parallel N] [--timeout S] [--vendor V] [--model M]
#                       [--entries e1,e2[,...]] [--novelty 0-DAY|N-DAY|any]
#                       [--force] [--prose-only]
#                       [--no-agent] [--agent-timeout S] [--retries N]
#                       [--dry-run] [vault-root]
#
#   vault-root     default data/round
#   --timeout S    per-entry wall budget in seconds (default 7200 = 2h);
#                  on expiry the worker is TERM'd — repro-run's exit trap
#                  removes its container, and the entry is booked TIMEOUT
#   selection      CONFIRMED ∩ 0-DAY entries: meta.confidence ∈ {high,medium}
#                  AND meta.novelty == 0-DAY (default). CNVD reproduction
#                  material is produced for 0-day findings only — N-day
#                  entries already carry public disclosures; --novelty
#                  N-DAY|any overrides the filter
#   resume         meta.repro.state == done is SKIPPED unless --force;
#                  missed-replay entries are retried only with --force
#                  (an automatic retry loop would burn boots on a verdict
#                  class the box keeps refusing to reproduce)
#   --prose-only   pass-through to repro-run.sh, and INVERTS the selection:
#                  state=done entries only — reuse the sealed replays and
#                  re-run just the organizer agent + render (prompt tweaks)
#   --vendor/--model/--entries   narrow the selection (entries = comma-
#                  separated entry dir basenames)
#   --parallel N   concurrent repro-run workers (default 2). Each worker
#                  boots one QEMU container (~1 core) and may run one
#                  static agent — budget accordingly next to hunt batches.
#   --no-agent / --agent-timeout S / --retries N   pass-through knobs
#   --dry-run      print the selection, execute nothing
#
# One worker per entry, entries independent:
#   repro-run.sh  -> fresh boot + grader replay + live serial capture
#                    -> organizer agent (REPRO.md + subtitles) -> video
#
# Logs:    <vault-root>/.repro-batch/<UTC-stamp>/<entry>.log
# State:   <vault-root>/.repro-batch/<UTC-stamp>/{schedule.json,events.jsonl,
#          rcs.txt} — repro-batch-monitor.sh renders these live
# Summary: <vault-root>/.repro-batch/<UTC-stamp>/summary.json (+ stdout)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"

PARALLEL=2; TIMEOUT=7200; VENDOR=""; MODEL=""; ENTRIES=""; FORCE=""; PROSE=""; DRYRUN=""
NOVELTY="0-DAY"
PASS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --parallel) PARALLEL="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --vendor) VENDOR="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        --entries) ENTRIES="$2"; shift 2 ;;
        --novelty) NOVELTY="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --prose-only) PROSE=1; PASS+=(--prose-only); shift ;;
        --no-agent) PASS+=(--no-agent); shift ;;
        --agent-timeout) PASS+=(--agent-timeout "$2"); shift 2 ;;
        --retries) PASS+=(--retries "$2"); shift 2 ;;
        --dry-run) DRYRUN=1; shift ;;
        -h|--help) awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,"");print}' "$0"; exit 0 ;;
        *) break ;;
    esac
done
VAULT="${1:-$ROOT/data/round}"
[ -d "$VAULT" ] || { echo "[-] no such vault root: $VAULT" >&2; exit 1; }
VAULT="$(cd "$VAULT" && pwd)"
case "$NOVELTY" in 0-DAY|N-DAY|any) ;; *) echo "[-] --novelty must be 0-DAY, N-DAY or any" >&2; exit 1 ;; esac

# ---- selection: CONFIRMED ∩ novelty entries needing (or, for --prose-only,
#      having) a sealed replay. The vault itself is the state file —
#      resumable by construction, no ledger to corrupt.
mapfile -t LIST < <(python3 -I - "$VAULT" "$FORCE" "$PROSE" "$VENDOR" "$MODEL" "$ENTRIES" "$NOVELTY" <<'EOF'
import json, glob, os, sys
vault, force, prose, vendor, model, entries, novelty = sys.argv[1:8]
want = set(e for e in entries.split(",") if e) if entries else None
for mp in sorted(glob.glob(os.path.join(vault, "*", "*", "*", "meta.json"))):
    ed = os.path.dirname(mp)
    try:
        m = json.load(open(mp))
    except Exception:
        continue
    if m.get("confidence") not in ("high", "medium"):
        continue
    if novelty != "any" and m.get("novelty") != novelty:
        continue
    if vendor and m.get("vendor") != vendor:
        continue
    if model and m.get("model") != model:
        continue
    if want and os.path.basename(ed) not in want:
        continue
    state = (m.get("repro") or {}).get("state")
    if prose:
        if state != "done":
            continue
    elif state == "done" and not force:
        continue
    elif state == "missed-replay" and not force:
        continue
    print(ed)
EOF
)

STAMP=$(date -u +%Y%m%d-%H%M%S)
LOGDIR="$VAULT/.repro-batch/$STAMP"
echo "[repro-batch] vault=$VAULT selected=${#LIST[@]} parallel=$PARALLEL novelty=$NOVELTY prose=${PROSE:-0} force=${FORCE:-0}"
if [ "${#LIST[@]}" -eq 0 ]; then
    echo "[repro-batch] nothing to do"
    exit 0
fi
if [ -n "$DRYRUN" ]; then
    printf '%s\n' "${LIST[@]}"
    exit 0
fi
mkdir -p "$LOGDIR"
python3 -I - "$LOGDIR/schedule.json" "$VAULT" "$NOVELTY" "$VENDOR" "$MODEL" \
          "$PROSE" "$FORCE" "$PARALLEL" "$TIMEOUT" "${LIST[@]}" <<'EOF'
import json, sys, time
out, vault, nov, vendor, model, prose, force, par, to = sys.argv[1:10]
json.dump({"vault": vault, "novelty": nov, "vendor": vendor, "model": model,
           "prose": prose == "1", "force": force == "1",
           "parallel": int(par), "timeout": int(to), "started_at": time.time(),
           "finished_at": None, "entries": sys.argv[10:]},
          open(out, "w"), indent=1)
EOF

RUN=0
for ENTRY in "${LIST[@]}"; do
    while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do sleep 3; done
    NAME=$(basename "$ENTRY")
    (
        set +e
        T0=$(date +%s)
        timeout -k 60 "$TIMEOUT" bash "$SCRIPTS/repro-run.sh" \
            ${PASS+"${PASS[@]}"} "$ENTRY" >"$LOGDIR/$NAME.log" 2>&1
        rc=$?
        DUR=$(( $(date +%s) - T0 ))
        echo "$rc $NAME" >> "$LOGDIR/rcs.txt"
        python3 -I -c 'import json,sys,time
open(sys.argv[1],"a").write(json.dumps({"ts":time.time(),"rc":int(sys.argv[2]),
    "dur_s":int(sys.argv[3]),"entry":sys.argv[4]})+"\n")' \
    "$LOGDIR/events.jsonl" "$rc" "$DUR" "$ENTRY"
        case $rc in
            0) echo "[repro-batch] done       $NAME (${DUR}s)" ;;
            3) echo "[repro-batch] MISSED     $NAME (replay did not reproduce — no video)" ;;
            124|137) echo "[repro-batch] TIMEOUT    $NAME (>${TIMEOUT}s wall budget)" ;;
            *) echo "[repro-batch] FAILED     $NAME (rc=$rc, see $LOGDIR/$NAME.log)" ;;
        esac
    ) &
    RUN=$((RUN + 1))
done
wait
python3 -I -c 'import json,sys,time
p = sys.argv[1]; d = json.load(open(p))
d["finished_at"] = time.time(); json.dump(d, open(p, "w"), indent=1)' \
    "$LOGDIR/schedule.json"

python3 -I - "$LOGDIR" "$RUN" "$PROSE" <<'EOF'
import json, os, sys, datetime
logdir, run, prose = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rcs = {}
p = os.path.join(logdir, "rcs.txt")
if os.path.exists(p):
    for l in open(p):
        l = l.split()
        if len(l) >= 2:
            rcs[l[1]] = int(l[0])
# vault truth outranks the booked rc: a bookkeeping bug (or a kill between
# landing and booking) must not mask artifacts that actually exist
try:
    sched = json.load(open(os.path.join(logdir, "schedule.json")))
    for e in sched.get("entries", []):
        name = os.path.basename(e)
        try:
            st = (json.load(open(os.path.join(e, "meta.json")))
                  .get("repro") or {}).get("state")
        except Exception:
            st = None
        if st in ("done", "missed-replay") and rcs.get(name) not in (0, 3):
            rcs[name] = 0 if st == "done" else 3
except Exception:
    pass
s = {"generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
     "mode": "prose-only" if prose == "1" else "full",
     "selected": run,
     "done": sum(1 for v in rcs.values() if v == 0),
     "missed": sum(1 for v in rcs.values() if v == 3),
     "timeout": sum(1 for v in rcs.values() if v in (124, 137)),
     "failed": sum(1 for v in rcs.values() if v not in (0, 3, 124, 137)),
     "entries": rcs}
json.dump(s, open(os.path.join(logdir, "summary.json"), "w"), indent=1)
print("[repro-batch] summary: %d/%d done, %d missed, %d timeout, %d failed -> %s/summary.json"
      % (s["done"], run, s["missed"], s["timeout"], s["failed"], logdir))
EOF
