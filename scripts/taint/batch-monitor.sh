#!/bin/bash
# agent-scan :: taint batch-monitor.sh — live dashboard over the taint stage
#
# Usage: batch-monitor.sh [--interval N] [--once] <fw-root>
#   <fw-root>     the folder batch-run.sh schedules (or any task folder /
#                 the whole data/firmware tree)
#   --interval N  refresh seconds in continuous mode (default 5)
#   --once        single frame and exit
#
# Everything shown is derived from REAL state, nothing is cached or faked:
#   running  = host /proc scan: the stage agent is a `claude -p` process
#              whose cwd is the model dir; the verification phase shows as
#              the task's taint-verify-* containers (docker ps). Works for
#              taint-run.sh direct runs AND batch-run.sh (--regrade too)
#   results  = each task folder's taint-run/taint-result.json (status,
#              coverage, duration)
#   batch    = batch-run.sh's state file (taint-* namespace under
#              /tmp/agent-scan-monitor/), if present, adds queue/timeout/
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
    -h|--help)  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          break ;;
    esac
done
ROOTDIR="${1:?usage: batch-monitor.sh [--interval N] [--once] <fw-root>}"
[ -d "$ROOTDIR" ] || { echo "[-] no such folder: $ROOTDIR" >&2; exit 1; }
ROOTDIR="$(cd "$ROOTDIR" && pwd)"
case "$INTERVAL" in ''|*[!0-9]*|0) echo "[-] --interval must be a positive integer" >&2; exit 1 ;; esac

SLUG=$(printf '%s' "$ROOTDIR" | sed 's|^/||; s|/|-|g; s|[^a-zA-Z0-9._-]|-|g')
STATEF="/tmp/agent-scan-monitor/taint-$SLUG.json"

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

# ---- discovery: same rules as batch-run.sh ----------------------------------
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

res = {}                                     # task id -> taint-result.json
for fw, tid in tasks.items():
    try: res[tid] = json.load(open(os.path.join(fw, "taint-run", "taint-result.json")))
    except Exception: pass

# ---- real running state: /proc agents + verify containers -------------------
def live_agent_tasks():
    """task ids with a live `claude -p` whose cwd is the model dir."""
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd0 = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")[0]
            if os.path.basename(cmd0.decode(errors="ignore")) != "claude":
                continue
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
            if b"-p" not in args:
                continue                       # interactive sessions excluded
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            continue
        if cwd in tasks:
            out[cwd] = now
    return out

def verify_containers():
    """task id -> live taint-verify-<taskid>-* container count."""
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.CreatedAt}}"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    ct = {}
    for line in out.splitlines():
        name, _, created = line.partition("\t")
        if not name.startswith("taint-verify-"):
            continue
        tid = name[len("taint-verify-"):]
        for cand in tasks.values():           # strip the chunk-stem suffix
            if tid.startswith(cand + "-") or tid == cand:
                ct[cand] = ct.get(cand, 0) + 1
                break
        else:
            try:                           # unknown task: first -<stem> cut
                tid = re.sub(r"-[^-]*$", "", tid)
                ct[tid] = ct.get(tid, 0) + 1
            except Exception:
                pass
    return ct

agents = live_agent_tasks()
vcs = verify_containers()

# ---- optional batch state ------------------------------------------------------
try:
    st = json.load(open(STATEF))
except Exception:
    st = None
batch_fresh = st is not None and st.get("root") == ROOTDIR \
    and now - os.path.getmtime(STATEF) < 7200

# running: batch-state entries (pid liveness-checked) + directly-run agents
# + tasks with live verify containers — phases: agent > verify > driver
run = []                                     # (tid, elapsed, phase, extra)
running_ids = set()
if st is not None:
    for r in st.get("running", []):
        fw, pid = r.get("fw_dir"), r.get("pid")
        alive = False
        try:
            os.kill(pid, 0)
            alive = True
        except OSError:
            pass
        tid = tasks.get(fw)
        if tid and alive and (fw not in agents or pid):
            running_ids.add(tid)
agent_fws = {fw: t for fw, t in agents.items()}
for fw in list(agent_fws):
    tid = tasks.get(fw)
    if tid:
        running_ids.add(tid)
if vcs:
    for tid in vcs:
        if tid in tasks.values():
            running_ids.add(tid)

for tid in running_ids:
    fw = next(f for f, t in tasks.items() if t == tid)
    el = 0
    if st is not None:
        for r in st.get("running", []):
            if r.get("fw_dir") == fw and st.get("started_at"):
                try:
                    os.kill(r.get("pid"), 0)
                    el = max(el, now - r.get("started_at", now))
                except OSError:
                    pass
    if not el:
        try:
            el = now - os.path.getmtime(os.path.join(fw, "taint-run", "agent.log"))
        except OSError:
            el = 0
    phase, extra = "driver", ""
    if fw in agent_fws:
        phase = "agent"
    elif vcs and vcs.get(tid):
        phase = "verify"
        extra = f"{TEAL}×{vcs[tid]}{R}"
    run.append((tid, el, phase, extra))
run.sort(key=lambda r: -r[1])

n = len(tasks)
succ = [res[t] for t in res if res[t].get("status") == "success" and t not in running_ids]
fail = [res[t] for t in res if res[t].get("status") != "success" and t not in running_ids]
pending = n - len(succ) - len(fail) - len(run)

def box(rows):
    print(f"{BOX}╭{'─' * (BW - 2)}╮{R}")
    for r in rows:
        print(f"{BOX}│{R} " + pad(cut(r, IN), IN) + f" {BOX}│{R}")
    print(f"{BOX}╰{'─' * (BW - 2)}╯{R}")

# ---- 1 · header ---------------------------------------------------------------
rows = [f"{B}agent-scan{R} {D}·{R} taint {D}·{R} {os.path.basename(ROOTDIR)}   {D}{hms(now)}{R}",
        f"{D}{ROOTDIR}{R} · {n} tasks"]
if batch_fresh:
    q = len(st.get("queue", []))
    fin = st.get("finished_at")
    el = (fin or now) - st["started_at"]
    line = (f"{D}batch{R}  jobs {st['jobs']}   {D}timeout{R} {fmt_dur(st['timeout'])}"
            f"   {D}queue{R} {q}   {D}{'finished' if fin else 'elapsed'}{R} {fmt_dur(el)}")
    if st.get("regrade"):
        line += f"   {TEAL}regrade{R}"
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
avg = sum((r.get("agent") or {}).get("duration_s") or 0 for r in res.values()) \
      / len(res) if res else 0
box([f"{bar}  {annot}",
     "",
     f"{D}success rate{R}  {B}{rate:.0f}%{R}",
     f"{D}avg agent{R}     {B}{fmt_dur(avg) if res else '—'}{R}"])
print()

# ---- 3 · running ---------------------------------------------------------------
if run:
    spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[FR % 10]
    rows = [f"{D}running{R} {D}({len(run)}){R}"]
    for tid, el, phase, extra in run:
        vendor, _, model = tid.partition("__")
        ph = {"agent": f"{D}agent{R}", "verify": f"{TEAL}verify{R}",
              "driver": f"{GOLD}driver{R}"}[phase]
        gauge = ""
        if batch_fresh and st.get("timeout") and phase in ("agent", "driver"):
            frac = min(el / st["timeout"], 1.0)
            col = TEAL if frac < 0.75 else (GOLD if frac < 0.90 else BAD)
            gw = 12
            gauge = f" {D2}▏{R}{col}{'█' * round(frac * gw)}{R}{D2}{'░' * (gw - round(frac * gw))}▎{R} {int(frac * 100):>3}%"
        rows.append(f"{TEAL}{spin}{R} {D}{vendor}{R} {cut(model, 18):<18}{fmt_dur(el):>8}{gauge}   {ph}{extra}")
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
        cov = d.get("coverage") or {}
        stat = f"{D}{d.get('status', '?')}{R}"
        if ok:
            stat = (f"{GOOD}✓{R} sites {cov.get('verified_call_sites', '?')}"
                    f"/{cov.get('call_sites', '?')} {D}·{R} probes {cov.get('probes', '?')}")
        dur = (d.get("agent") or {}).get("duration_s") or 0
        mode = f" {D}regrade{R}" if d.get("mode") == "regrade" else ""
        rr = f" {GOLD}↑ rerunning{R}" if tid in running_ids else ""
        rows.append(f"{D}{dt_short(d.get('finished_at', ''))}{R}  {icon} "
                    f"{cut(model, 20):<20}{fmt_dur(dur):>8}   {stat}{mode}{rr}")
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
