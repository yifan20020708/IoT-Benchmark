#!/bin/bash
# agent-scan :: taint — live monitor for hunt-batch.sh
#
# Usage: hunt-monitor.sh [--interval S] [--once] [--json] [--batch STAMP]
#                        [--all] <model-dir>
#
# The unit of work here is not a process outcome — it is a POC. A worker
# is never "succeeded" or "failed": what matters is how many pocs its
# agent archived, and of those, how many the paired verify container
# graded and into what verdicts. No success-rate concept anywhere —
# only counts, per unit and on the scoreboard footer.
#
# STAGE       what the row means:
#   HUNT      agent container live    (POC col = archive-so-far, live)
#   VERIFY    verify container live   (graded-so-far, streamed from
#                                      verify/poc-results.jsonl)
#   MID       between stages (recreate/boot/staging happens here)
#   DONE      verify/result.json written — worker closed
#   (+ with --all: WAIT = no driver.log yet, still in the bash queue)
#
# POC column  archived/graded counts (not an accuracy claim).
# VERDICT histogram: T=TRIGGERED  S=service_down  n=not_triggered
#                    I=inconclusive  P=poc_error  B=boot_failed
# Footer scoreboard: units closed · pocs archived · pocs graded ·
#                    hits (T+S) — the only totals that matter.
#
#   --interval  redraw seconds, loop in place (default 10)
#   --once      single snapshot, no loop
#   --json      machine-readable snapshot (one document; with --interval
#               it keeps appending documents, one per tick)
#   --batch     which hunt-output/_batch/<stamp> to watch (default newest)
#   --all       include every unit under functions/ even with no activity
set -euo pipefail

INTERVAL=10; ONCE=0; JSON=0; BATCH=""; ALL=0; MODEL=""
while [ $# -gt 0 ]; do
    case "$1" in
        --interval) INTERVAL="$2"; shift 2 ;;
        --once) ONCE=1; shift ;;
        --json) JSON=1; shift ;;
        --batch) BATCH="$2"; shift 2 ;;
        --all) ALL=1; shift ;;
        -h|--help) sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) MODEL="$1"; shift ;;
    esac
done
[ -n "$MODEL" ] || { echo "usage: hunt-monitor.sh [--interval S] [--once] [--json] [--batch STAMP] [--all] <model-dir>" >&2; exit 1; }
[ "$ONCE" = 1 ] && INTERVAL=0
MODEL="$(cd "$MODEL" && pwd)"

exec python3 - "$MODEL" "$INTERVAL" "$JSON" "$BATCH" "$ALL" <<'PYEOF'
import json, os, subprocess, sys, time, datetime

model, interval, want_json, batch, want_all = sys.argv[1:6]
interval = int(interval); want_json = int(want_json); want_all = int(want_all)

def snapshot():
    hroot = os.path.join(model, "hunt-output")
    fout  = os.path.join(model, "taint-work-output", "functions")

    # live containers
    ctr = {}
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                             capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            name, status = line.split("\t", 1)
            if name.startswith(("hunt-", "verify-")):
                ctr[name] = status
    except Exception:
        pass

    # batch scope: units with a driver.log under the watched _batch stamp
    bdir = None
    if os.path.isdir(os.path.join(hroot, "_batch")):
        stamps = sorted(os.listdir(os.path.join(hroot, "_batch")))
        bdir = os.path.join(hroot, "_batch", batch or (stamps[-1] if stamps else "")) \
               if stamps else None
    drivers = set()
    if bdir and os.path.isdir(bdir):
        drivers = {f[:-len(".driver.log")] for f in os.listdir(bdir) if f.endswith(".driver.log")}

    units = sorted(os.listdir(fout)) if os.path.isdir(fout) else []
    rows = []
    tot_pocs = tot_graded = tot_hits = closed = 0
    for u in units:
        ud   = os.path.join(hroot, "functions", u)
        pd   = os.path.join(ud, "pocs")
        vres = os.path.join(ud, "verify", "result.json")
        vjl  = os.path.join(ud, "verify", "poc-results.jsonl")
        # live container for this unit: hunt-/verify-<task>-<unit-slug>
        live_hunt   = any(n.startswith("hunt-")   and u.replace("_", "-") in n for n in ctr)
        live_verify = any(n.startswith("verify-") and u.replace("_", "-") in n for n in ctr)

        n_pocs = 0
        if os.path.isdir(pd):
            n_pocs = sum(1 for f in os.listdir(pd)
                         if f.endswith((".py", ".c")) and os.path.isfile(os.path.join(pd, f)))
        graded = []
        if os.path.isfile(vjl):
            try:
                graded = [json.loads(l) for l in open(vjl) if l.strip()]
            except Exception:
                graded = []
        elif os.path.isfile(vres):
            try:
                graded = json.load(open(vres)).get("pocs", [])
            except Exception:
                graded = []
        viol = 0
        vf = os.path.join(ud, "verify", "violations.txt")
        if os.path.isfile(vf):
            viol = sum(1 for l in open(vf) if l.strip())

        stage = ("DONE" if os.path.isfile(vres) else
                 "VERIFY" if live_verify else
                 "HUNT" if live_hunt else
                 "MID" if (u in drivers or os.path.isfile(vjl) or n_pocs) else None)
        if stage is None and not want_all:
            continue
        if stage is None:
            stage = "WAIT"

        counts = {}
        for g in graded:
            v = g.get("verdict", "?")
            k = {"TRIGGERED": "T", "service_down": "S", "not_triggered": "n",
                 "inconclusive": "I", "poc_error": "P", "boot_failed": "B"}.get(v, "?")
            counts[k] = counts.get(k, 0) + 1
        hits = counts.get("T", 0) + counts.get("S", 0)

        started = ""
        dl = os.path.join(bdir or "/", u + ".driver.log") if bdir else ""
        if dl and os.path.isfile(dl):
            started = datetime.datetime.fromtimestamp(os.path.getmtime(dl),
                     datetime.timezone.utc).strftime("%H:%M")
        rows.append({"unit": u, "stage": stage, "started": started,
                     "pocs": n_pocs, "graded": len(graded), "hits": hits,
                     "hist": "".join("%s%d" % (k, counts[k]) for k in "TSnPIBv" if counts.get(k)),
                     "violations": viol})
        tot_pocs += n_pocs
        tot_graded += len(graded)
        tot_hits += hits
        if stage == "DONE":
            closed += 1

    return {"model": os.path.basename(model), "batch": os.path.basename(bdir) if bdir else None,
            "at": datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
            "live_containers": ctr, "units_closed": closed,
            "units_in_scope": len(rows), "pocs_archived": tot_pocs,
            "pocs_graded": tot_graded, "hits": tot_hits, "rows": rows}

def task_slug_get():
    v, m = os.path.basename(os.path.dirname(model)), os.path.basename(model)
    import re
    return re.sub(r"[^a-z0-9._-]", "-", ("%s__%s" % (v, m)).lower())
task_slug = task_slug_get()

FIRST = True
while True:
    s = snapshot()
    if want_json:
        print(json.dumps(s, separators=(",", ":")), flush=True)   # NDJSON: one doc per tick
    else:
        if not FIRST: print("\033[2J\033[H", end="")
        live = " ".join(sorted(s["live_containers"])) or "-"
        print("hunt-monitor :: %s :: %s UTC   batch=%s" % (s["model"], s["at"], s["batch"]))
        print("live: %s" % live[:110])
        print("%-12s %s %6s %6s %4s  %s" % ("STAGE", "UNIT", "POC", "GRADE", "HIT", "HIST/T-S-n-I-P-B"))
        order = {"VERIFY": 0, "HUNT": 1, "MID": 2, "DONE": 3, "WAIT": 4}
        for r in sorted(s["rows"], key=lambda x: (order.get(x["stage"], 9), -x["hits"], x["unit"]))[:30]:
            print("%-12s %s %6d %6d %4d  %s%s" % (r["stage"], r["unit"][:46],
                  r["pocs"], r["graded"], r["hits"], r["hist"],
                  ("  v%d" % r["violations"]) if r["violations"] else ""))
        if len(s["rows"]) > 30:
            print("... %d more rows (--all/--json for full scope)" % (len(s["rows"]) - 30))
        print("-" * 60)
        print("SCOREBOARD  units closed: %d   pocs archived: %d   pocs graded: %d   HITS(T+S): %d"
              % (s["units_closed"], s["pocs_archived"], s["pocs_graded"], s["hits"]))
    FIRST = False
    if interval == 0:
        break
    time.sleep(interval)
PYEOF
