#!/bin/bash
# agent-scan :: batch-monitor.sh — live dashboard over the task tree
#
# Usage: batch-monitor.sh [--interval N] [--once] <fw-root>
#   <fw-root>     the folder batch-run.sh schedules (or any task folder /
#                 the whole data/firmware tree)
#   --interval N  refresh seconds in continuous mode (default 5)
#   --once        single frame and exit
#
# Everything shown is derived from REAL state, nothing is cached or faked:
#   running  = `docker ps` task-* containers (works for agent-run.sh direct
#              runs AND batch-run.sh; phase emu/agent from a host /proc scan:
#              qemu-system pid -> cgroup -> container name)
#   results  = each task folder's result.json (status, duration, promoted)
#   batch    = batch-run.sh's state file, if present, adds queue/timeout/
#              ETA context on top
#
# Layout: four rounded boxes — header / progress+stats / running / recent.
set -euo pipefail

INTERVAL=5
ONCE=0
while [ $# -gt 0 ]; do
    case "$1" in
    --interval) INTERVAL="$2"; shift 2 ;;
    --once)     ONCE=1; shift ;;
    -h|--help)  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          break ;;
    esac
done
ROOTDIR="${1:?usage: batch-monitor.sh [--interval N] [--once] <fw-root>}"
[ -d "$ROOTDIR" ] || { echo "[-] no such folder: $ROOTDIR" >&2; exit 1; }
ROOTDIR="$(cd "$ROOTDIR" && pwd)"
case "$INTERVAL" in ''|*[!0-9]*|0) echo "[-] --interval must be a positive integer" >&2; exit 1 ;; esac

SLUG=$(printf '%s' "$ROOTDIR" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/$SLUG.json"

render() {
    FR=$FR python3 - "$STATEF" "$ROOTDIR" <<'PYEOF'
import json, os, re, sys, time, subprocess, shutil
from datetime import datetime, timezone

STATEF, ROOTDIR = sys.argv[1], sys.argv[2]
now = time.time()
FR = int(os.environ.get("FR", "0"))

R, B = "\033[0m", "\033[1m"
BOX = "\033[38;5;240m"     # border ink
D   = "\033[38;5;243m"     # labels
D2  = "\033[38;5;238m"     # empty track / deep dim
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
def dt_short(iso):
    try: return datetime.fromisoformat(iso).astimezone().strftime("%m-%d %H:%M")
    except Exception: return (iso or "")[:16]

# ---- discovery: same rules as batch-run.sh ---------------------------------
tasks = {}                                   # fw dir -> task id
for dp, dns, fns in os.walk(ROOTDIR):
    base = os.path.basename(dp)
    if base in ("output", "rootfs", "decompiled-rootfs") or base.startswith("output.attempt-"):
        dns[:] = []
        continue
    if "task.json" in fns:
        dns[:] = []
        parts = dp.rstrip("/").split("/")
        tasks[dp] = re.sub(r"[^a-z0-9._-]", "-", f"{parts[-2]}__{parts[-1]}".lower())

res = {}                                     # task id -> result.json
for fw, tid in tasks.items():
    try: res[tid] = json.load(open(os.path.join(fw, "result.json")))
    except Exception: pass

# ---- real running containers -----------------------------------------------
def workers():
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.CreatedAt}}"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    ws = {}
    for line in out.splitlines():
        name, _, created = line.partition("\t")
        if not name.startswith("task-"):
            continue
        try:
            t = datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S") \
                    .replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
        ws[name[5:]] = t
    return ws

def qemu_pids_by_container():
    out = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd0 = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")[0]
            if not os.path.basename(cmd0.decode(errors="ignore")).startswith("qemu-system"):
                continue
            cg = open(f"/proc/{pid}/cgroup").read()
        except OSError:
            continue
        m = re.search(r"/docker[-/]([0-9a-f]{12,64})", cg)
        if m:
            out.add(m.group(1)[:12])
    if not out:
        return set()
    try:
        ps = subprocess.run(["docker", "ps", "--no-trunc", "--format",
                             "{{.ID}} {{.Names}}"], capture_output=True, text=True,
                            timeout=10).stdout
    except Exception:
        return set()
    return {l.split(" ", 1)[1] for l in ps.splitlines()
            if " " in l and l.split(" ", 1)[0][:12] in out}

# ---- optional batch state ----------------------------------------------------
try:
    st = json.load(open(STATEF))
except Exception:
    st = None
batch_fresh = st is not None and st.get("root") == ROOTDIR \
    and now - os.path.getmtime(STATEF) < 7200

ws = workers()
emu_cts = qemu_pids_by_container() if ws is not None else set()
run = []                                     # (tid, elapsed, phase)
running_ids = set()
if ws is not None:
    for tid, created in ws.items():
        if tid in tasks.values():
            run.append((tid, now - created, "emu" if f"task-{tid}" in emu_cts else "agent"))
            running_ids.add(tid)
    run.sort(key=lambda r: -r[1])

n = len(tasks)
succ = [res[t] for t in res if res[t].get("status") == "success" and t not in running_ids]
fail = [res[t] for t in res if res[t].get("status") != "success" and t not in running_ids]
promoted = sum(1 for r in res.values() if ":solved" in (r.get("image") or ""))
pending = n - len(succ) - len(fail) - len(run)

def box(rows):
    print(f"{BOX}╭{'─' * (BW - 2)}╮{R}")
    for r in rows:
        print(f"{BOX}│{R} " + pad(cut(r, IN), IN) + f" {BOX}│{R}")
    print(f"{BOX}╰{'─' * (BW - 2)}╯{R}")

# ---- 1 · header ---------------------------------------------------------------
rows = [f"{B}agent-scan{R} {D}·{R} {os.path.basename(ROOTDIR)}   {D}{hms(now)}{R}",
        f"{D}{ROOTDIR}{R} · {n} tasks"]
if batch_fresh:
    q = len(st.get("queue", []))
    fin = st.get("finished_at")
    el = (fin or now) - st["started_at"]
    line = (f"{D}batch{R}  jobs {st['jobs']}   {D}timeout{R} {fmt_dur(st['timeout'])}"
            f"   {D}queue{R} {q}   {D}{'finished' if fin else 'elapsed'}{R} {fmt_dur(el)}")
    if not fin and q and len(res) and el > 600:
        thr = (len(succ) + len(fail)) / (el / 3600)
        if thr > 0:
            line += f"   {D}eta{R} {GOLD}~{fmt_dur((q + len(run)) / thr * 3600)}{R}"
    rows.append(line)
box(rows)
print()

# ---- 2 · progress + stats ------------------------------------------------------
BARW = IN - 28                               # fixed bar width, task-count independent
segs = [(len(succ), GOOD), (len(run), GOLD), (len(fail), BAD), (pending, D2)]
total = sum(k for k, _ in segs)
scaled = [round(k / total * BARW) for k, _ in segs] if total else [0] * len(segs)
if total:                                    # rounding drift lands on the widest segment
    i = scaled.index(max(scaled))
    scaled[i] += BARW - sum(scaled)
bar = "".join(col + "█" * s + R for (k, col), s in zip(segs, scaled) if s > 0) \
      or D2 + "░" * BARW + R
annot = f"{B}{len(succ) + len(fail)}/{n}{R} {D}done{R}"
if run:
    annot += f" {D}·{R} {GOLD}{len(run)} running{R}"
rate = (len(succ) / (len(succ) + len(fail)) * 100) if (succ or fail) else 0.0
avg = sum(r.get("duration_s") or 0 for r in res.values()) / len(res) if res else 0
box([f"{bar}  {annot}",
     "",
     f"{D}success rate{R}  {B}{rate:.0f}%{R}",
     f"{D}avg time{R}      {B}{fmt_dur(avg) if res else '—'}{R}"])
print()

# ---- 3 · running ---------------------------------------------------------------
if run:
    spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[FR % 10]
    rows = [f"{D}running{R} {D}({len(run)}){R}"]
    for tid, el, phase in run:
        vendor, _, model = tid.partition("__")
        ph = f"{TEAL}emu{R}" if phase == "emu" else f"{D}agent{R}"
        gauge = ""
        if batch_fresh and st.get("timeout"):
            frac = min(el / st["timeout"], 1.0)
            col = TEAL if frac < 0.75 else (GOLD if frac < 0.90 else BAD)
            gw = 12
            gauge = f" {D2}▏{R}{col}{'█' * round(frac * gw)}{R}{D2}{'░' * (gw - round(frac * gw))}▎{R} {int(frac * 100):>3}%"
        rows.append(f"{TEAL}{spin}{R} {D}{vendor}{R} {cut(model, 18):<18}{fmt_dur(el):>8}{gauge}   {ph}")
    box(rows)
else:
    box([f"{D}running{R}  {D2}nothing running{R}"])
print()

# ---- 4 · recent -----------------------------------------------------------------
recent = sorted(res.items(), key=lambda kv: kv[1].get("finished_at") or "",
                reverse=True)[:8]
if recent:
    rows = [f"{D}recent{R}"]
    for tid, d in recent:
        vendor, _, model = tid.partition("__")
        ok = d.get("status") == "success"
        icon = f"{GOOD}✓{R}" if ok else f"{BAD}✖{R}"
        stat = f"{GOOD}promoted{R}" if ":solved" in (d.get("image") or "") \
               else f"{D}{d.get('status', '?')}{R}"
        rr = f" {GOLD}↑ rerunning{R}" if tid in running_ids else ""
        rows.append(f"{D}{dt_short(d.get('finished_at', ''))}{R}  {icon} "
                    f"{cut(model, 20):<20}{fmt_dur(d.get('duration_s') or 0):>8}   {stat}{rr}")
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
