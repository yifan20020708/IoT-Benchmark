#!/bin/bash
# agent-scan :: taint — repro-batch-monitor.sh — live dashboard over a
# repro-batch run (the analog of mapper-batch-monitor.sh / hunt-batch-monitor.sh).
#
# Usage: repro-batch-monitor.sh [--interval N] [--once] [vault-root|logdir]
#   [vault-root|logdir]  default data/round. Either a batch logdir (holds
#                        schedule.json) or a vault root — then the NEWEST
#                        .repro-batch/<stamp>/ schedule wins
#   --interval N         refresh seconds in continuous mode (default 5)
#   --once               single frame and exit
#
# Everything shown is derived from REAL state, nothing is cached or faked:
#   schedule = the batch's schedule.json (entries, parallel, timeout, filters)
#   running  = host /proc scan for repro-run.sh wrapper processes, elapsed
#              from the wrapper's process start; phase = "render" when a
#              repro-video.py is drawing that entry, "agent" when any host
#              claude process has its cwd inside it (the static organizer),
#              else "replay" (boot/gate/poc/serial capture)
#   results  = the batch's events.jsonl (rc + wall time per completion), and
#              for entries with no event yet the vault's own meta.repro
#   rc map   = 0 done (video) · 3 missed-replay (NO video, refused) ·
#              124/137 timeout (wall budget) · anything else failed
#
# Layout: four rounded boxes — header / progress+stats / running / recent.
set -euo pipefail

INTERVAL=5
ONCE=0
while [ $# -gt 0 ]; do
    case "$1" in
    --interval) INTERVAL="$2"; shift 2 ;;
    --once)     ONCE=1; shift ;;
    -h|--help)  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          break ;;
    esac
done
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-$ROOT/data/round}"
[ -d "$TARGET" ] || { echo "[-] no such folder: $TARGET" >&2; exit 1; }
TARGET="$(cd "$TARGET" && pwd)"
case "$INTERVAL" in ''|*[!0-9]*|0) echo "[-] --interval must be a positive integer" >&2; exit 1 ;; esac

render() {
    FR=$FR python3 - "$TARGET" "$ROOT" <<'PYEOF'
import json, os, re, sys, time, glob, shutil
from datetime import datetime

TARGET, ROOT = sys.argv[1], sys.argv[2]
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
def hm(t): return datetime.fromtimestamp(t).strftime("%m-%d %H:%M")

# ---- locate the batch schedule -------------------------------------------------
sched_p = None
if os.path.isfile(os.path.join(TARGET, "schedule.json")):
    sched_p = os.path.join(TARGET, "schedule.json")
else:
    cands = sorted(glob.glob(os.path.join(TARGET, ".repro-batch", "*", "schedule.json")),
                   key=os.path.getmtime, reverse=True)
    sched_p = cands[0] if cands else None
if not sched_p:
    print(f"{BAD}[-] no schedule.json under {TARGET} — start repro-batch.sh first{R}")
    sys.exit(0)
LOGDIR = os.path.dirname(sched_p)
try:
    st = json.load(open(sched_p))
except Exception as e:
    print(f"{BAD}[-] unreadable schedule.json: {e}{R}")
    sys.exit(1)
entries = [e for e in st.get("entries", [])]
eset = set(entries)

# ---- completion events ----------------------------------------------------------
ev = {}                                   # entry -> {ts, rc, dur_s} (LAST wins)
try:
    for l in open(os.path.join(LOGDIR, "events.jsonl")):
        if not l.strip():
            continue
        d = json.loads(l)
        if d.get("entry") in eset and d.get("ts", 0) >= ev.get(d["entry"], {}).get("ts", 0):
            ev[d["entry"]] = d
except FileNotFoundError:
    pass

# ---- /proc scan: running repro-run.sh wrappers + agent-phase claude cwds --------
def proc_scan():
    runs = {}                               # entry -> elapsed (oldest wins)
    agent_entries = set()
    render_entries = set()
    try:
        up = float(open("/proc/uptime").read().split()[0])
    except Exception:
        return runs, agent_entries, render_entries
    hz = os.sysconf("SC_CLK_TCK")
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            raw = open(f"/proc/{pid}/cmdline", "rb").read()
        except OSError:
            continue
        if not raw:
            continue
        argv = [a.decode(errors="ignore") for a in raw.split(b"\0") if a]
        if any(a.endswith("repro-run.sh") for a in argv):
            cand = [a for a in argv if a in eset]
            if cand:
                try:
                    s = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
                    el = up - int(s[19]) / hz
                except Exception:
                    continue
                e = cand[-1]
                if el > runs.get(e, -1):
                    runs[e] = el
        elif any(a.endswith("repro-video.py") for a in argv):
            cand = [a for a in argv if a in eset]
            if cand:
                render_entries.add(cand[-1])
        elif b"claude" in raw:
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                continue
            for e in runs:                  # only running entries matter
                if cwd == e or cwd.startswith(e + os.sep):
                    agent_entries.add(e)
    return runs, agent_entries, render_entries

runs, agent_entries, render_entries = proc_scan()

# ---- classify --------------------------------------------------------------------
def status_of(e):
    if e in runs:
        return "running"
    # VAULT TRUTH FIRST: a landed pack (meta.repro) outranks the batch event —
    # an entry can be complete on disk while its recorded rc is wrong (e.g. an
    # exit-status bug books a finished run as failed); the artifacts are the
    # ground truth the page and CNVD see.
    try:
        m = json.load(open(os.path.join(e, "meta.json")))
        state = (m.get("repro") or {}).get("state")
        if state == "done":
            return "done"
        if state == "missed-replay":
            return "missed"
    except Exception:
        pass
    d = ev.get(e)
    if d:
        rc = d.get("rc")
        return {0: "done", 3: "missed"}.get(rc, "timeout" if rc in (124, 137) else "failed")
    return "pending"

STAT = {e: status_of(e) for e in entries}
n = len(entries)
done    = [e for e in entries if STAT[e] == "done"]
missed  = [e for e in entries if STAT[e] == "missed"]
timeout = [e for e in entries if STAT[e] == "timeout"]
failed  = [e for e in entries if STAT[e] == "failed"]
running = [e for e in entries if STAT[e] == "running"]
pending = [e for e in entries if STAT[e] == "pending"]
finished = st.get("finished_at")
elapsed = (finished or now) - st.get("started_at", now)

# video bytes of the done entries (cheap: repro.json is small)
vbytes = 0
for e in done:
    try:
        vbytes += (json.load(open(os.path.join(e, "repro", "repro.json")))
                   .get("video", {}).get("bytes", 0))
    except Exception:
        pass

def box(rows):
    print(f"{BOX}╭{'─' * (BW - 2)}╮{R}")
    for r in rows:
        print(f"{BOX}│{R} " + pad(cut(r, IN), IN) + f" {BOX}│{R}")
    print(f"{BOX}╰{'─' * (BW - 2)}╯{R}")

def ename(e):
    parts = e.rstrip("/").split("/")
    return f"{parts[-2]}/{parts[-1]}"

# ---- 1 · header -------------------------------------------------------------------
flt = " · ".join(x for x in (st.get("vendor"), st.get("model"),
                             None if st.get("novelty") == "any" else st.get("novelty"),
                             "prose-only" if st.get("prose") else None) if x)
rows = [f"{B}agent-scan{R} {D}·{R} {D}taint repro-batch{R} · {flt or 'whole vault'}   {D}{hms(now)}{R}",
        f"{D}{n} scheduled{R} · {D}logdir{R} {cut(LOGDIR.replace(ROOT + '/', ''), 40)}"]
q = len(running) + len(pending)
line = (f"{D}batch{R}  jobs {st.get('parallel', '?')}   {D}timeout{R} {fmt_dur(st.get('timeout', 0))}"
        f"   {D}queue{R} {q}   {D}{'finished' if finished else 'elapsed'}{R} {fmt_dur(elapsed)}")
completed = len(done) + len(missed) + len(timeout) + len(failed)
if not finished and q and completed and elapsed > 300:
    thr = completed / (elapsed / 3600)
    if thr > 0:
        line += f"   {D}eta{R} {GOLD}~{fmt_dur(q / thr * 3600)}{R}"
rows.append(line)
box(rows)
print()

# ---- 2 · progress + stats ----------------------------------------------------------
annot = f"{B}{completed}/{n}{R} {D}settled{R}"
if running:
    annot += f" {D}·{R} {GOLD}{len(running)} running{R}"
BARW = max(10, IN - 2 - vlen(annot) - 2)
segs = [(len(done), GOOD), (len(running), GOLD),
        (len(missed) + len(timeout) + len(failed), BAD), (len(pending), D2)]
total = sum(k for k, _ in segs)
scaled = [round(k / total * BARW) for k, _ in segs] if total else [0] * len(segs)
if total:
    i = scaled.index(max(scaled))
    scaled[i] += BARW - sum(scaled)
bar = "".join(col + "█" * s + R for (k, col), s in zip(segs, scaled) if s > 0) \
      or D2 + "░" * BARW + R
rate = (len(done) / completed * 100) if completed else 0.0
durs = [d["dur_s"] for d in ev.values() if d.get("dur_s")]
avg = sum(durs) / len(durs) if durs else 0
box([f"{bar}  {annot}",
     "",
     f"{D}video rate{R}   {B}{rate:.0f}%{R} {D}({len(done)} done · {len(missed)} missed · "
     f"{len(timeout)} timeout · {len(failed)} failed){R}",
     f"{D}avg wall{R}     {B}{fmt_dur(avg) if durs else '—'}{R}"
     f"   {D}video total{R} {B}{vbytes / 1048576:.1f} MB{R}"])
print()

# ---- 3 · running --------------------------------------------------------------------
if running:
    spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[FR % 10]
    rows = [f"{D}running{R} {D}({len(running)}){R}"]
    for e in sorted(running, key=lambda x: -runs[x]):
        el = runs[e]
        ph = (f"{GOLD}render{R}" if e in render_entries else
              f"{TEAL}agent{R}" if e in agent_entries else f"{D}replay{R}")
        gauge = ""
        to = st.get("timeout") or 0
        if to:
            frac = min(el / to, 1.0)
            col = TEAL if frac < 0.75 else (GOLD if frac < 0.90 else BAD)
            gw = 12
            gauge = (f" {D2}▏{R}{col}{'█' * round(frac * gw)}{R}"
                     f"{D2}{'░' * (gw - round(frac * gw))}▎{R} {int(frac * 100):>3}%")
        rows.append(f"{TEAL}{spin}{R} {cut(ename(e), 34):<34}{fmt_dur(el):>8}{gauge}   {ph}")
    box(rows)
else:
    box([f"{D}running{R}  {D2}nothing running{R}"])
print()

# ---- 4 · recent ----------------------------------------------------------------------
recent = sorted(ev.values(), key=lambda d: d.get("ts", 0), reverse=True)[:8]
if recent:
    rows = [f"{D}recent{R}"]
    for d in recent:
        rc = d.get("rc")
        # same rule as the stats box: the VAULT decides, the booked rc is a hint
        s = STAT.get(d.get("entry")) or (
            "done" if rc == 0 else "missed" if rc == 3
            else "timeout" if rc in (124, 137) else "failed")
        icon, lab, col = {"done": ("✓", "done", GOOD),
                          "missed": ("✖", "missed — no video", BAD),
                          "timeout": ("⧗", "timeout", BAD)}.get(
                              s, ("✖", f"failed rc={rc}", BAD))
        rows.append(f"{D}{hm(d.get('ts', 0))}{R}  {col}{icon}{R} "
                    f"{cut(ename(d.get('entry', '?')), 34):<34}"
                    f"{fmt_dur(d.get('dur_s', 0)):>8}   {col}{lab}{R}")
    box(rows)
else:
    box([f"{D}recent{R}  {D2}no completions yet{R}"])
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
