#!/bin/bash
# agent-scan :: taint — hunt-batch-monitor.sh — live dashboard over a
# model's unit tree for the Phase-2 Hunt batch. Same visual language as
# scripts/rehost/batch-monitor.sh and scripts/taint/mapper-batch-monitor.sh
# (four rounded boxes, colored bar, spinner, budget gauge, recent list) —
# but the scoreboard counts POCs, never a success rate: a worker is not
# success/failed, it is "how many pocs did the agent archive, how many did
# the paired verify container grade, and what verdicts came out".
#
# Usage: hunt-batch-monitor.sh [--interval N] [--once] <model-dir>
#   <model-dir>   the folder hunt-batch.sh schedules
#   --interval N  refresh seconds (default 5)
#   --once        single frame and exit
#
# Everything shown is derived from REAL state, nothing cached or faked:
#   running  = hunt-batch's live state file (/tmp/agent-scan-monitor),
#              stage (hunt/verify) from the per-unit containers docker ps
#              shows (hunt-…/verify-…) — elapsed from the worker's start
#   results  = per unit: hunt-output/functions/<unit>/{run,verify}/result.json
#   scope    = units under taint-work-output/functions/ (the work list);
#              a unit is "graded" once verify/result.json exists
#   batch    = state file adds jobs/timeout/queue/ETA context on top; the
#              monitor works without it too (pure filesystem + docker frame)
#
# Layout: four rounded boxes — header / progress+stats / running / recent.
set -euo pipefail

INTERVAL=5
ONCE=0
while [ $# -gt 0 ]; do
    case "$1" in
    --interval) INTERVAL="$2"; shift 2 ;;
    --once)     ONCE=1; shift ;;
    -h|--help)  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          break ;;
    esac
done
MODEL="${1:?usage: hunt-batch-monitor.sh [--interval N] [--once] <model-dir>}"
[ -d "$MODEL" ] || { echo "[-] no such folder: $MODEL" >&2; exit 1; }
MODEL="$(cd "$MODEL" && pwd)"
case "$INTERVAL" in ''|*[!0-9]*|0) echo "[-] --interval must be a positive integer" >&2; exit 1 ;; esac

SLUG=$(printf '%s' "$MODEL" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/hunt-$SLUG.json"

render() {
    FR=$FR python3 - "$STATEF" "$MODEL" <<'PYEOF'
import json, os, re, sys, time, subprocess, shutil, glob
from datetime import datetime

STATEF, MODEL = sys.argv[1], sys.argv[2]
now = time.time()
FR = int(os.environ.get("FR", "0"))

R, B = "\033[0m", "\033[1m"
BOX = "\033[38;5;240m"
D   = "\033[38;5;243m"
D2  = "\033[38;5;238m"
GOOD, GOLD, BAD, TEAL = "\033[38;5;108m", "\033[38;5;179m", "\033[38;5;167m", "\033[38;5;109m"

BW = min(max(shutil.get_terminal_size((80, 24)).columns, 62), 80)
IN = BW - 4

def vlen(s): return len(re.sub(r"\033\[[0-9;?]*[a-zA-Z]", "", s))
def pad(s, n): return s + " " * max(0, n - vlen(s))
def cut(s, n):
    return s if vlen(s) <= n else re.sub(r"\033\[[0-9;?]*[a-zA-Z]", "", s)[: n - 1] + "…"

def fmt_dur(s):
    s = int(s)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m{str(s%60).zfill(2)}s"
    return f"{s//3600}h{str((s%3600)//60).zfill(2)}m"

def hms(t): return time.strftime("%H:%M:%S", time.localtime(t))
def dt_short(ts):
    try: return datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
    except Exception: return ""

# ---- scope: units = taint-work-output/functions/ ----------------------------
FDIR = os.path.join(MODEL, "taint-work-output", "functions")
units = sorted(os.path.basename(d) for d in glob.glob(os.path.join(FDIR, "*"))
               if os.path.isdir(d))
n = len(units)
OUT = os.path.join(MODEL, "hunt-output", "functions")

# ---- per-unit state (pure filesystem — the truth of record) -----------------
HIST = {"TRIGGERED": "T", "service_down": "S", "not_triggered": "n",
        "inconclusive": "I", "poc_error": "P", "boot_failed": "B"}
uinfo = {}
for u in units:
    d = os.path.join(OUT, u)
    info = {"hunt": None, "verify": None, "graded": [], "pocs": 0,
            "h_mtime": 0.0, "v_mtime": 0.0}
    try:
        info["hunt"] = json.load(open(os.path.join(d, "run", "result.json")))
        info["h_mtime"] = os.path.getmtime(os.path.join(d, "run", "result.json"))
    except Exception:
        pass
    try:
        vr = os.path.join(d, "verify", "result.json")
        info["verify"] = json.load(open(vr))
        info["v_mtime"] = os.path.getmtime(vr)
        for p in info["verify"].get("pocs", []):
            info["graded"].append(p.get("verdict", "?"))
    except Exception:
        # verify in flight: per-poc lines stream before result.json exists
        try:
            for l in open(os.path.join(d, "verify", "poc-results.jsonl")):
                if l.strip():
                    info["graded"].append(json.loads(l).get("verdict", "?"))
        except Exception:
            pass
    try:
        info["pocs"] = sum(1 for f in os.listdir(os.path.join(d, "pocs"))
                           if os.path.isfile(os.path.join(d, "pocs", f)))
    except Exception:
        pass
    uinfo[u] = info

# ---- live containers (docker ps) ---------------------------------------------
live = {}
try:
    out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                         capture_output=True, text=True, timeout=10).stdout
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("hunt-") or s.startswith("verify-"):
            # hunt-<task>-<unit-slug> — unit underscores became dashes
            kind = s.split("-", 1)[0]
            live[re.sub(r"^.*?(?:hunt|verify)-", "", s)] = kind
except Exception:
    pass

def unit_live(u):
    us = u.replace("_", "-")
    # anchor at the END of the container slug (optionally its verify -<idx>
    # suffix): substring matching cross-matched units that are prefixes of
    # others (getIpSecTunnel vs getIpSecTunnelAutoParameters)
    tail = re.compile(r"-" + re.escape(us) + r"(-\d+)?$")
    for slug, kind in live.items():
        if tail.search(slug):
            return kind
    return None

# ---- optional batch state ------------------------------------------------------
try:
    st = json.load(open(STATEF))
except Exception:
    st = None
batch_fresh = (st is not None and st.get("model") == MODEL
               and now - os.path.getmtime(STATEF) < 7200)

# ---- running roster: state file if fresh, else containers --------------------
run = []                                        # (unit, kind, elapsed, timeout)
running_units = set()
if batch_fresh:
    for r in st.get("running", []):
        u, kind, el = r["unit"], r.get("stage") or "hunt", now - r["started_at"]
        live_kind = unit_live(u)
        run.append((u, kind, el, st.get("timeout")))
        running_units.add(u)
for u in units:                                 # containers with no state file
    k = unit_live(u)
    if k and u not in running_units:
        run.append((u, k, 0, st.get("timeout") if st else 3600))
        running_units.add(u)
run.sort(key=lambda r: -r[2])

# ---- scoreboard ----------------------------------------------------------------
# scope: when a batch is live, the batch's own worklist is the denominator
# (st["total"], graded = its units with a fresh verify/result.json); without
# batch state we fall back to the full functions/ tree
if batch_fresh:
    b_total = st.get("total", n)
    b_started = st.get("started_at", 0)
    # in-batch = this batch RAN the unit's hunt (fresh run/result.json):
    # an out-of-scope unit whose verify/result.json was refreshed later by
    # e.g. a standalone verify-run --no-report replay must not inflate the
    # batch scoreboard (else "18/16 graded")
    graded_units = [u for u in units if uinfo[u]["verify"]
                    and uinfo[u]["v_mtime"] >= b_started
                    and (uinfo[u].get("h_mtime") or 0) >= b_started
                    and u not in running_units]
else:
    b_total = n
    graded_units = [u for u in units if uinfo[u]["verify"] and u not in running_units]
running_now  = [u for u in units if u in running_units]
pending      = max(0, b_total - len(graded_units) - len(running_now))
tot_pocs     = sum(info["pocs"] for info in uinfo.values())
all_verdicts = [v for info in uinfo.values() for v in info["graded"]]
hits         = sum(1 for v in all_verdicts if v in ("TRIGGERED", "service_down"))
hist_counts  = {HIST[k]: sum(1 for v in all_verdicts if v == k)
                for k in HIST}

def box(rows):
    print(f"{BOX}╭{'─' * (BW - 2)}╮{R}")
    for r in rows:
        print(f"{BOX}│{R} " + pad(cut(r, IN), IN) + f" {BOX}│{R}")
    print(f"{BOX}╰{'─' * (BW - 2)}╯{R}")

# ---- 1 · header ---------------------------------------------------------------
model_name = os.path.basename(MODEL)
rows = [f"{B}agent-scan{R} {D}·{R} {D}taint hunt{R} · {model_name}   {D}{hms(now)}{R}",
        (f"{D}{n} units{R} {D}in scope{R}" if not batch_fresh
         else f"{D}{n} units{R} {D}in tree{R} {D}·{R} {B}{b_total}{R} {D}in this batch{R}")]
if batch_fresh:
    q = len(st.get("queue", []))
    fin = st.get("finished_at")
    el = (fin or now) - st["started_at"]
    line = (f"{D}batch{R}  jobs {st['jobs']}   {D}timeout{R} {fmt_dur(st['timeout'])}"
            f"   {D}queue{R} {q}   {D}{'finished' if fin else 'elapsed'}{R} {fmt_dur(el)}")
    if not fin and q and graded_units and el > 600:
        thr = len(graded_units) / (el / 3600)
        if thr > 0:
            line += f"   {D}eta{R} {GOLD}~{fmt_dur((q + len(running_now)) / thr * 3600)}{R}"
    rows.append(line)
box(rows)
print()

# ---- 2 · progress + scoreboard ---------------------------------------------------
BARW = IN - 26
segs = [(len(graded_units), GOOD), (len(running_now), GOLD), (pending, D2)]
total = sum(k for k, _ in segs)
scaled = [round(k / total * BARW) for k, _ in segs] if total else [0] * len(segs)
if total:
    i = scaled.index(max(scaled))
    scaled[i] += BARW - sum(scaled)
bar = "".join(col + "█" * s + R for (k, col), s in zip(segs, scaled) if s > 0) \
      or D2 + "░" * BARW + R
annot = f"{B}{len(graded_units)}/{b_total}{R} {D}graded{R}"
if running_now:
    annot += f" {D}·{R} {GOLD}{len(running_now)} running{R}"
hist_str = " ".join(f"{col}{v}{D}{k}{R}" for k, v, col in
    ((k, hist_counts[k], c) for k, c in (("T", GOOD), ("S", GOLD), ("n", D),
                                         ("I", D), ("P", BAD), ("B", BAD))
     if hist_counts[k])) or f"{D2}no verdicts yet{R}"
box([f"{bar}  {annot}",
     "",
     f"{D}pocs archived{R}  {B}{tot_pocs}{R}",
     f"{D}pocs graded{R}     {B}{len(all_verdicts)}{R} {D}·{R} "
     f"{D}hits{R} {GOOD if hits else D2}{hits}{R}",
     f"{D}verdicts{R}       {hist_str}"])
print()

# ---- 3 · running ---------------------------------------------------------------
if run:
    spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[FR % 10]
    rows = [f"{D}running{R} {D}({len(run)}){R}"]
    for u, kind, el, to in run:
        stage = (f"{TEAL}hunt{R}" if kind == "hunt" else f"{TEAL}verify{R}")
        info = uinfo.get(u, {})
        poc_line = (f" {D}pocs{R} {TEAL}{info.get('pocs', 0)}{R}" if kind == "hunt"
                    else f" {D}graded{R} {TEAL}{len(info.get('graded', []))}"
                         f"{R}{D}/{info.get('pocs', 0)}{R}")
        gauge = ""
        if to and kind == "hunt":        # budget gauge only for the agent stage
            frac = min(el / to, 1.0)
            col = TEAL if frac < 0.75 else (GOLD if frac < 0.90 else BAD)
            gw = 10
            gauge = f" {D2}▏{R}{col}{'█' * round(frac * gw)}{R}{D2}{'░' * (gw - round(frac * gw))}▎{R}"
        et = f"{fmt_dur(el):>8}" if el else " " * 8
        rows.append(f"{TEAL}{spin}{R} {cut(u, 26):<26}{et}{gauge} {stage}{poc_line}")
    box(rows)
else:
    box([f"{D}running{R}  {D2}nothing running{R}"])
print()

# ---- 4 · recent (units by last hunt/verify write) -------------------------------
def recent_key(u):
    i = uinfo[u]
    return max(i["v_mtime"], i["h_mtime"])
recent = sorted((u for u in units if uinfo[u]["hunt"] or uinfo[u]["verify"]),
                key=recent_key, reverse=True)[:8]
if recent:
    rows = [f"{D}recent{R}"]
    for u in recent:
        i = uinfo[u]
        vs = {}
        for v in i["graded"]:
            vs[HIST.get(v, "?")] = vs.get(HIST.get(v, "?"), 0) + 1
        h = vs.get("T", 0) + vs.get("S", 0)
        icon = f"{GOOD}{h} hit{R}" if h else f"{D2}—{R}"
        hist = " ".join(f"{col}{vs[k]}{D}{k}{R}" for k, col in
            (("T", GOOD), ("S", GOLD), ("n", D), ("I", D), ("P", BAD), ("B", BAD)) if vs.get(k))
        rr = f" {GOLD}↑ running{R}" if u in running_units else ""
        rows.append(f"{D}{dt_short(recent_key(u))}{R}  {cut(u, 26):<26} "
                    f"{D}pocs{R} {B}{i['pocs']}{R} {D}/{len(i['graded'])} graded{R}  "
                    f"{icon} {hist}{rr}")
    box(rows)
else:
    box([f"{D}recent{R}  {D2}no results yet{R}"])
PYEOF
}

if [ "$ONCE" = 1 ]; then
    FR=0 render
    exit 0
fi

FR=0
printf '\033[?25l'
trap 'printf "\033[?25h\n"' EXIT
trap 'exit 130' INT TERM
while :; do
    printf '\033[H\033[J'
    FR=$FR render || true
    FR=$((FR + 1))
    sleep "$INTERVAL"
done
