#!/bin/bash
# agent-scan :: taint — Phase-2 batch orchestrator over a model's units
#
# Usage: hunt-batch.sh [--parallel N] [--timeout S] [--units u1,u2[,...]]
#                      [--rehunt] [--reverify] [--dry-run] [--verify-mode M]
#                      <model-dir>
#
#   <model-dir>    data/firmware/<vendor>/<model> — every directory under
#                  <model>/taint-work-output/functions/ is one work unit
#   --parallel N   concurrent unit-workers (default 2). Each worker boots
#                  its own emulation(s): budget roughly N GB RAM + N QEMU
#                  processes per model, and loop-shim keeps the kernel
#                  loop pool honest (serial fallback on failure).
#   --timeout S    hunt agent wall-clock budget per unit (default 3600),
#                  passed through to hunt-run.sh
#   --units        run exactly these units (comma-separated) instead of
#                  the whole functions/ listing
#   --rehunt       re-run the agent even where run/result.json says success
#   --reverify     re-grade archives even where verify/result.json exists
#   --verify-mode  emulation mode for verify boots (default debug)
#   --dry-run      print the schedule, execute nothing
#
# Unit pipeline (one worker per unit, units independent):
#
#   [resume: skip unit if verify/result.json exists (unless --reverify)]
#   hunt-run.sh   --timeout S   -> agent container; archive harvest
#   verify-run.sh               -> verify container; one fresh boot per
#                                  archived poc, deterministic verdicts
#
# Resume semantics: a unit whose HUNT already succeeded (run/result.json
# status=success) skips the agent and goes straight to verify — after an
# interruption, restarting the batch costs only the unfinished stages.
# The pair per unit is what the user-facing table reports at the end.
#
# Logs: <model>/hunt-output/_batch/<UTC-stamp>/<unit>.driver.log
# Summary: <model>/hunt-output/_batch/<UTC-stamp>/summary.json (+ stdout)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"

PARALLEL=2; TIMEOUT=3600; UNITS=""; REHUNT=""; REVERIFY=""; DRYRUN=""; VMODE="debug"
while [ $# -gt 0 ]; do
    case "$1" in
        --parallel) PARALLEL="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --units) UNITS="$2"; shift 2 ;;
        --rehunt) REHUNT=1; shift ;;
        --reverify) REVERIFY=1; shift ;;
        --verify-mode) VMODE="$2"; shift 2 ;;
        --dry-run) DRYRUN=1; shift ;;
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: hunt-batch.sh [options] <model-dir>}"
[ -d "$MODEL" ] || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
MODEL="$(cd "$MODEL" && pwd)"
FUNCS="$MODEL/taint-work-output/functions"
[ -d "$FUNCS" ] || { echo "[-] no Phase-1 output: $FUNCS (run mapper-run.sh first)" >&2; exit 1; }
# hunt containers need credentials; verify containers do not (no LLM)
[ -f "$ROOT/.env" ] || { echo "[-] missing $ROOT/.env (hunt stage needs it)" >&2; exit 1; }

# unit list
if [ -n "$UNITS" ]; then
    IFS=',' read -r -a LIST <<< "$UNITS"
else
    mapfile -t LIST < <(find "$FUNCS" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
fi
[ "${#LIST[@]}" -gt 0 ] || { echo "[-] no units to run" >&2; exit 1; }

STAMP=$(date -u +%Y%m%d-%H%M%S)
BLOGDIR="$MODEL/hunt-output/_batch/$STAMP"
mkdir -p "$BLOGDIR"

# ---- live state for hunt-batch-monitor.sh (same pattern as mapper-batch) ----
mkdir -p /tmp/agent-scan-monitor
MSLUG=$(printf '%s' "$MODEL" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/hunt-$MSLUG.json"
state() {
    python3 - "$STATEF" "$@" <<'PYEOF'
import json, sys, os, time
path, verb = sys.argv[1], sys.argv[2]
def save(d):
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(d, f)
    os.replace(tmp, path)          # atomic: readers never see a torn file
try:
    d = json.load(open(path))
except Exception:
    d = None
if verb == "init":
    d = {"model": sys.argv[3], "jobs": int(sys.argv[4]), "timeout": int(sys.argv[5]),
         "started_at": time.time(), "finished_at": None,
         "total": int(sys.argv[6]), "queue": json.loads(sys.argv[7]),
         "running": []}
elif d is None:
    sys.exit(0)
elif verb == "stage":            # unit, stage (hunt|verify|None=finished)
    u, stage = sys.argv[3], sys.argv[4]
    d["queue"] = [q for q in d.get("queue", []) if q != u]
    d["running"] = [r for r in d.get("running", []) if r["unit"] != u]
    if stage:
        d["running"].append({"unit": u, "stage": stage, "started_at": time.time()})
elif verb == "finish":
    d["finished_at"] = time.time()
save(d)
PYEOF
}

hunt_ok() {  # previous hunt succeeded (skip marker)
    local u="$1" f="$MODEL/hunt-output/functions/$u/run/result.json"
    [ -f "$f" ] && [ "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status",""))' "$f" 2>/dev/null)" = "success" ]
}
verify_done() {
    [ -f "$MODEL/hunt-output/functions/$1/verify/result.json" ]
}

echo "[batch] model=$(basename "$MODEL") units=${#LIST[@]} parallel=$PARALLEL timeout=${TIMEOUT}s verify-mode=$VMODE"
echo "[batch] logs: $BLOGDIR"

run_unit() {   # full pipeline for ONE unit; both stages always attempted
    local u="$1" log="$BLOGDIR/$u.driver.log" RC=0
    {
        echo "[batch] === $u ==="
        if ! hunt_ok "$u" || [ -n "$REHUNT" ]; then
            exec 7>"$STATEF.lock"; flock 7; state stage "$u" hunt; exec 7>&-
            "$SCRIPTS/hunt-run.sh" --timeout "$TIMEOUT" "$MODEL" "$u" || RC=$?
            echo "[batch] hunt rc=$RC"
        else
            echo "[batch] hunt skipped (run/result.json success; --rehunt to override)"
        fi
        exec 7>"$STATEF.lock"; flock 7; state stage "$u" verify; exec 7>&-
        RC=0
        "$SCRIPTS/verify-run.sh" --mode "$VMODE" "$MODEL" "$u" || RC=$?
        echo "[batch] verify rc=$RC"
        exec 7>"$STATEF.lock"; flock 7; state stage "$u" ""; exec 7>&-
    } >"$log" 2>&1
}

# ---- schedule ---------------------------------------------------------------
# pass 1: decide scope (skips are final; everything else is the queue)
N_SKIPPED=0
SCHED=()
for u in "${LIST[@]}"; do
    if verify_done "$u" && [ -z "$REVERIFY" ]; then
        echo "[batch] skip $u (verify/result.json exists; --reverify to override)"
        N_SKIPPED=$((N_SKIPPED + 1))
        continue
    fi
    SCHED+=("$u")
done
if [ -n "$DRYRUN" ]; then
    for u in "${SCHED[@]}"; do
        printf '[dry] %-55s hunt:%s verify:RUN\n' "$u" \
            "$(hunt_ok "$u" && echo skip || echo RUN)"
    done
    echo "[dry] queued=${#SCHED[@]} skipped=$N_SKIPPED total=${#LIST[@]}"
    exit 0
fi

# pass 2: publish live state (monitor input), then fill the pool
QUEUE_JSON=$(printf '%s\n' "${SCHED[@]}" \
    | python3 -c 'import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
exec 7>"$STATEF.lock"; flock 7
state init "$MODEL" "$PARALLEL" "$TIMEOUT" "${#SCHED[@]}" "$QUEUE_JSON"
exec 7>&-
echo "[batch] queued=${#SCHED[@]} skipped=$N_SKIPPED — running..."
for u in "${SCHED[@]}"; do
    while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do sleep 5; done
    run_unit "$u" &
done

wait
exec 7>"$STATEF.lock"; flock 7; state finish; exec 7>&-

# ---- summary ----------------------------------------------------------------
python3 - "$MODEL" "$BLOGDIR" <<'EOF'
import glob, json, os, sys
model, blogdir = sys.argv[1:3]
rows, agg = [], {}
for ud in sorted(glob.glob(os.path.join(model, "hunt-output", "functions", "*"))):
    u = os.path.basename(ud)
    h = v = None
    try: h = json.load(open(os.path.join(ud, "run", "result.json"))).get("status")
    except Exception: pass
    try: v = json.load(open(os.path.join(ud, "verify", "result.json")))
    except Exception: pass
    counts = (v or {}).get("counts", {})
    trig = sum(n for k, n in counts.items() if k in ("TRIGGERED", "service_down"))
    rows.append({"unit": u, "hunt": h, "verify": (v or {}).get("status"),
                 "triggered_or_dos": trig, "counts": counts})
    for k, n in counts.items():
        agg[k] = agg.get(k, 0) + n
done = [r for r in rows if r["verify"]]
hits = [r for r in done if r["triggered_or_dos"]]
summary = {"units_verified": len(done), "units_with_hits": len(hits),
           "verdict_histogram": agg,
           "hits": [{"unit": r["unit"], **r["counts"]} for r in hits]}
json.dump(summary, open(os.path.join(blogdir, "summary.json"), "w"), indent=2)
print(f"\n===== batch summary =====")
print(f"units verified : {len(done)} / {len(rows)}")
print(f"histogram      : {agg}")
for r in hits:
    print(f"HIT  {r['unit']}: {r['counts']}")
EOF
echo "[batch] summary: $BLOGDIR/summary.json"
