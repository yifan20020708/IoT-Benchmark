#!/bin/bash
# poc-run.sh — agent-scan Phase-2: deterministic PoC executor + trigger oracle.
#
# Contract (for the hunting agent):
#   * You write your PoC as a normal .py or .c program (sockets, payloads,
#     parsing, printing — all yours). Env vars provided to your poc:
#       TARGET_IP / TARGET_PORT  — the emulated firmware's interface
#       POC_MARKER               — a token unique to this run
#     Runtime or compile errors are reported back verbatim — fix them yourself.
#   * This script runs your poc once, deterministically (.py -> python3 -u,
#     .c -> gcc -O0 + run), under a hard timeout, and then applies the
#     FirmAE-fuzzer + STAFF trigger oracle on the emulation's signal layer:
#       CI  triggered : POC_MARKER appears in an [ANALYZE] execve line, or
#                       the /bin/a canary executes, during the run window.
#                       (embed the marker in your injected command, e.g.  ;$POC_MARKER )
#       BOF triggered : a fatal-signal/panic serial line appears in the run
#                       window that was not already crashing before the run
#                       (pre-run crashers are fingerprinted and ignored —
#                       STAFF's dry-run ignore list, automated).
#       SERVICE DOWN  : service was alive, is dead after, no crash line AND
#                       no guest reboot in the window (hang/DoS). If the
#                       window shows the kernel's own reboot signatures
#                       (firmadyne sys_reboot hook / "Requesting system
#                       reboot" — note: FirmAE restarts init IN PLACE, no
#                       second Linux-version banner), the box died from a
#                       REBOOT, not your hang — that is graded inconclusive
#                       (rc 3), never service_down: vendor "config apply ->
#                       reboot" endpoints are common and would hand free
#                       DoS credit to benign requests (proven on Tenda
#                       AC15 SetIPTVCfg). Replay on a fresh boot.
#   * Everything (your stdout/stderr, the serial window, the raw segment)
#     is kept in the evidence dir for your own analysis.
#   * The emulation must be booted in ANALYZE mode (firmadyne.syscall=32,
#     e.g. `emu analyze`); the crash channel is on in every boot mode.
#
# Grading protocol (host-harness contract — verdict correctness DEPENDS on
# this, it is not deployment advice):
#   * FINAL grading replays each agent poc on its OWN fresh boot (or a QEMU
#     snapshot restore to a post-ready state). Reasons: a boot consumed by a
#     destructive poc (crash w/o respawn, CI reboot, DoS) is refused later by
#     the baseline gate, and same-boot replay of an already-crashed BOF is
#     suppressed by the pre-run fingerprint -> false negative (rc 1).
#   * EXPLORATION may chain pocs on one boot: every run mints its own
#     POC_MARKER, so the token channel is self-pollution-proof; rc 3 output
#     tells you the box stopped being gradeable.
#   * CI grading wants an ANALYZE boot; if unavailable, the /bin/a canary-log
#     channel is the fallback (window attribution only, needs the debug
#     backdoor tcp/31338) — a CI poc that only embeds the marker token is
#     invisible there. Convention for fallback envs: make the injected
#     command also exec the canary (e.g.  ";a;$POC_MARKER;#" ).
#
# Usage:
#   poc-run.sh <poc.py|poc.c> [poc args...] [--timeout S] [--port P]
#              [--serial PATH] [--out-root DIR] [--verbose]
# Output contract: stdout/stderr are SILENT unless --verbose. The exit code
#   is the only immediate signal; the full human-readable report lands at
#   <out>/report.txt (machine copy report.json beside it) and
#   <out-root>/latest always symlinks to the newest run, so:
#       poc-run.sh /work/poc/poc.py || cat /tmp/poc-runs/latest/report.txt
# Exit:   0 TRIGGERED | 1 not triggered | 2 service down | 3 infra error or
#         inconclusive (guest rebooted mid-window — replay on a fresh boot)
#         4 input error (bad usage / poc compile error)

set -u

TIMEOUT=120
PORT=80
OUT_ROOT=/tmp/poc-runs
SERIAL_ARG=""
VERBOSE=0
POC=""
POC_ARGS=()

OUT=""
fail() {  # fail <exit_code> <message> — details always go to a report file
  local m="poc-run: $2"
  [ "$VERBOSE" = 1 ] && echo "$m" >&2
  if [ -n "$OUT" ]; then
    {
      echo "=== poc-run ==="
      echo "VERDICT:  ERROR (rc $1)"
      echo "$m"
    } > "$OUT/report.txt"
  else  # argument-level failure: no evidence dir yet — use a stable path
    mkdir -p "$OUT_ROOT" 2>/dev/null || true
    {
      echo "=== poc-run ==="
      echo "VERDICT:  ERROR (rc $1)"
      echo "$m"
    } > "$OUT_ROOT/fail-report.txt" 2>/dev/null || true
  fi
  exit "$1"
}

# ---------------------------------------------------------------- args -----
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout|--port|--serial|--out-root)
                 [ $# -ge 2 ] || fail 4 "$1 requires a value"
                 case "$1" in
                   --timeout)   TIMEOUT=$2 ;;
                   --port)      PORT=$2 ;;
                   --serial)    SERIAL_ARG=$2 ;;
                   --out-root)  OUT_ROOT=$2 ;;
                 esac
                 shift 2 ;;
    --verbose)   VERBOSE=1; shift ;;
    -h|--help)   grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)          fail 4 "unknown option: $1" ;;
    *)           if [ -z "$POC" ]; then POC=$1; shift
                 else POC_ARGS+=("$1"); shift; fi ;;
  esac
done
[ -n "$POC" ] || fail 4 "no poc file given (usage: poc-run.sh <poc.py|poc.c> [args...])"
[ -f "$POC" ] || fail 4 "poc file not found: $POC"
EXT="${POC##*.}"
case "$EXT" in
  py|c) ;;
  *)    fail 4 "unsupported poc type '.$EXT' — write your poc as .py or .c" ;;
esac

# evidence dir first: every later failure must still leave a report behind
TS=$(date +%Y%m%d-%H%M%S)
NAME="${POC##*/}"
SAFE="${NAME//[!a-zA-Z0-9._-]/_}"
OUT="$OUT_ROOT/poc-$SAFE-$TS-$$"
mkdir -p "$OUT" || fail 3 "cannot create $OUT"
ln -sfn "$OUT" "$OUT_ROOT/latest" 2>/dev/null \
  || trap '[ -n "$OUT" ] && ln -sfn "$OUT" "$OUT_ROOT/latest" 2>/dev/null || true' EXIT
cp "$POC" "$OUT/poc.copy" 2>/dev/null || true

# ------------------------------------------------------------- infra -------
# find the emulation's QEMU (no pgrep dependency: scan /proc)
QEMU_PID=""
for d in /proc/[0-9]*; do
  [ -r "$d/cmdline" ] || continue
  if grep -aqs 'qemu-system' "$d/cmdline" 2>/dev/null \
     && grep -aqs 'qemu.final.serial.log' "$d/cmdline" 2>/dev/null; then
    QEMU_PID="${d#/proc/}"
    break
  fi
done
[ -n "$QEMU_PID" ] || fail 3 "no running QEMU found — is the emulation up?"

CMDLINE=$(tr '\0' ' ' < "/proc/$QEMU_PID/cmdline" 2>/dev/null) \
  || fail 3 "cannot read /proc/$QEMU_PID/cmdline"

if [ -n "$SERIAL_ARG" ]; then
  SERIAL="$SERIAL_ARG"
else
  SERIAL=$(printf '%s\n' "$CMDLINE" | grep -o -- '-serial file:[^ ]*' | head -1 | sed 's/^-serial file://')
fi
[ -n "$SERIAL" ] && [ -f "$SERIAL" ] \
  || fail 3 "serial log not found (pass --serial PATH if non-standard)"

# CI channel needs the ANALYZE execve audit (firmadyne.syscall bit 32) — it
# is registered at BOOT time only (runtime /sys writes change the parameter
# but not the jprobes, verified on AC15). Without it the marker/canary
# execve lines never appear; crash + liveness channels stay fully active,
# so grade those and flag CI as not evaluable instead of blocking.
SC=$(printf '%s\n' "$CMDLINE" | grep -o 'firmadyne\.syscall=[0-9]\+' | head -1 | cut -d= -f2)
SC=${SC:-0}
CI_ARMED=1
if [ "$(( SC & 32 ))" -eq 0 ]; then
  CI_ARMED=0
fi

# guest IP: both spellings (inferNetwork writes `ip`, makeNetwork multi-if
# writes `ip.0`/`ip.1` — W30E class images have no plain `ip`)
D=$(dirname "$SERIAL")
IP=$(head -n1 "$D/ip" 2>/dev/null | tr -d '[:space:]')
if [ -z "$IP" ]; then
  for f in "$D"/ip.[0-9]*; do
    [ -f "$f" ] && IP=$(head -n1 "$f" | tr -d '[:space:]') && [ -n "$IP" ] && break
  done
fi
[ -n "$IP" ] || fail 3 "guest IP not found ($D/ip, $D/ip.N)"

# ------------------------------------------------------------ run poc ------
# FirmAE-d34d-style attribution token, unique per run
MARKER="d34d$(od -An -tx1 -N3 /dev/urandom | tr -d ' \n')"

probe() {  # probe <ip> <port> -> alive|dead
  if timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
    echo alive
  else
    echo dead
  fi
}

# --- CI side-effect channel (no analyze mode needed) ------------------------
# FirmAE bakes /bin/a (injectionChecker) into every image; a CI that executes
# it appends a date+env+stat record to the guest file
# /firmadyne/os_cmd_injection_log. If the debug-boot telnetd backdoor
# (31338 -> /firmadyne/sh) is reachable, we count those records before/after
# the poc — CI verdicts then work even when the ANALYZE execve audit is off.
GEXEC="$OUT/gexec.py"
cat > "$GEXEC" <<'GSEOF'
import re, socket, sys, time
ip, port, cmd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    s = socket.create_connection((ip, port), 3)
    s.settimeout(2.5)
except OSError:
    sys.exit(5)
time.sleep(0.3)
try:
    s.recv(65536)
except OSError:
    pass
s.sendall((cmd + '\r\n').encode())
time.sleep(1.2)
d = b''
while True:
    try:
        c = s.recv(4096)
    except OSError:
        break
    if not c:
        break
    d += c
s.close()
IAC = re.compile(rb'\xff[\xfd\xfb][\x20-\x7f]')
sys.stdout.write(IAC.sub(b'', d).decode('latin-1', 'replace'))
GSEOF

canary_read() {  # raw injection log, or empty on no backdoor
  timeout 12 python3 -I "$GEXEC" "$IP" 31338 \
    'cat /firmadyne/os_cmd_injection_log 2>/dev/null' 2>/dev/null
}
CANARY_ARMED=0
if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/31338" 2>/dev/null; then
  CANARY_ARMED=1
  if CANARY_RAW0=$(canary_read); then
    CANARY0=$(grep -acE '[0-9]{2}:[0-9]{2}:[0-9]{2}' <<<"$CANARY_RAW0")
  else
    CANARY0=NA   # baseline unreadable (backdoor flaked) — never let a 0-line
  fi             # ghost baseline inflate the delta into a CI verdict
else
  CANARY0=NA
fi

export TARGET_IP="$IP" TARGET_PORT="$PORT" POC_MARKER="$MARKER"
LIVE_BEFORE=$(probe "$IP" "$PORT")
# baseline gate: a dead target before the poc is an infra problem, never a
# DoS verdict — fail fast so the agent fixes the boot/port instead of
# reading rc 2 as "my attack worked"
if [ "$LIVE_BEFORE" = dead ]; then
  fail 3 "baseline gate: nothing answers tcp://$IP:$PORT BEFORE the poc ran — the emulation is not serving (check 'emu status', re-boot, or pass --port P). This was not graded as service_down."
fi
OFFSET=$(stat -c %s "$SERIAL" 2>/dev/null || echo 0)

STATUS=""
RC=0
T0=$(date +%s%N)
case "$EXT" in
  py)
    timeout -k 5 "$TIMEOUT" python3 -u "$POC" ${POC_ARGS[@]+"${POC_ARGS[@]}"} \
      >"$OUT/stdout.txt" 2>"$OUT/stderr.txt"
    RC=$?
    ;;
  c)
    if ! gcc -O0 -o "$OUT/poc.bin" "$POC" >"$OUT/compile.log" 2>&1; then
      STATUS=compile_error
      RC=-1
    else
      timeout -k 5 "$TIMEOUT" "$OUT/poc.bin" ${POC_ARGS[@]+"${POC_ARGS[@]}"} \
        >"$OUT/stdout.txt" 2>"$OUT/stderr.txt"
      RC=$?
    fi
    ;;
esac
T1=$(date +%s%N)
WALL_MS=$(( (T1 - T0) / 1000000 ))

if [ "$STATUS" = compile_error ]; then :
elif [ "$RC" -eq 124 ]; then STATUS=timeout
elif [ "$RC" -ge 128 ]; then STATUS="signal:$(( RC - 128 ))"
elif [ "$RC" -eq 0 ]; then STATUS=ok
else STATUS="exit:$RC"
fi

# ------------------------------------------------- collect signal layer ----
sleep 3   # delayed crashes / trailing execve may land shortly after the poc
tail -c +$(( OFFSET + 1 )) "$SERIAL" > "$OUT/serial_segment.txt" 2>/dev/null || true
grep -a '\[ANALYZE\] \[PID:' "$OUT/serial_segment.txt" > "$OUT/analyze_lines.txt" 2>/dev/null || true
grep -a -i -E 'sending SIG(SEGV|BUS|ILL|FPE|TRAP)|potentially unexpected fatal signal|kernel panic|oops:|bug:|general protection fault' \
  "$OUT/serial_segment.txt" > "$OUT/crash_lines.txt" 2>/dev/null || true
# reboot detector: lines that only appear when the guest REBOOTED during the
# run window. FirmAE's sys_reboot interception restarts init IN PLACE (kernel
# stays up, no second banner!), so the authoritative signatures are the
# kernel's own shutdown notice + the firmadyne hook lines — all printed by
# kernel code, arch- and vendor-agnostic; a real re-boot banner counts too.
REBOOTS=$(grep -acE 'firmadyne: sys_reboot|removed CAP_SYS_BOOT|Requesting system reboot|Linux version' "$OUT/serial_segment.txt" 2>/dev/null || true)
REBOOTS=${REBOOTS:-0}
# pre-run segment -> STAFF-style dry-run ignore list (pre-existing crashers)
head -c "$OFFSET" "$SERIAL" > "$OUT/pre_segment.txt" 2>/dev/null || true
LIVE_AFTER=$(probe "$IP" "$PORT")
LIVE_PROBES=1
LIVE_CONFIRM=""
if [ "$LIVE_AFTER" = dead ]; then     # confirm handshake: a single 3s-timeout
  for _t in 2 3; do                   # connect can blip under host load —
    sleep 2                           # dead must be seen 3-for-3 to count
    LIVE_PROBES=$_t
    if [ "$(probe "$IP" "$PORT")" = alive ]; then
      LIVE_AFTER=alive; LIVE_CONFIRM="respawned_on_retry"; break
    fi
  done
fi
# canary post-read (+3s more settle — a command injection may land late)
CANARY1=NA
if [ "$CANARY_ARMED" = 1 ]; then
  sleep 3
  CANARY_RAW1=$(canary_read)
  printf '%s\n' "$CANARY_RAW1" > "$OUT/canary_log.txt"
  CANARY1=$(grep -acE '[0-9]{2}:[0-9]{2}:[0-9]{2}' <<<"$CANARY_RAW1")
fi

# ------------------------------------------------------------- report ------
export POCRUN_OUT="$OUT" POCRUN_POC="$POC" POCRUN_TYPE="$EXT" \
       POCRUN_STATUS="$STATUS" POCRUN_EXIT="$RC" POCRUN_WALL_MS="$WALL_MS" \
       POCRUN_TIMEOUT="$TIMEOUT" POCRUN_QEMU_PID="$QEMU_PID" \
       POCRUN_SYSCALL="$SC" POCRUN_SERIAL="$SERIAL" POCRUN_MARKER="$MARKER" \
       POCRUN_LIVE_BEFORE="$LIVE_BEFORE" POCRUN_LIVE_AFTER="$LIVE_AFTER" \
       POCRUN_LIVE_PROBES="$LIVE_PROBES" POCRUN_LIVE_CONFIRM="$LIVE_CONFIRM" \
       POCRUN_CI_ARMED="$CI_ARMED" POCRUN_CANARY_ARMED="$CANARY_ARMED" \
       POCRUN_CANARY0="$CANARY0" POCRUN_CANARY1="$CANARY1" POCRUN_TS="$TS" \
       POCRUN_REBOOTS="$REBOOTS"

python3 - <<'PYEOF' > "$OUT/report.txt"
import json, os, re, sys

out = os.environ['POCRUN_OUT']
E = lambda k, d='': os.environ.get('POCRUN_' + k, d)
marker = E('MARKER')

CRASH_RE = re.compile(r'sending SIG(SEGV|BUS|ILL|FPE|TRAP)|'
                      r'potentially unexpected fatal signal|'
                      r'kernel panic|oops:|bug:|general protection fault',
                      re.IGNORECASE)

def read_tail(path, n):
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2); sz = f.tell()
            f.seek(max(0, sz - n))
            return f.read().decode('utf-8', 'replace')
    except OSError:
        return ''

def read_lines(path, cap):
    try:
        with open(path, 'rb') as f:
            ls = f.read().decode('utf-8', 'replace').splitlines()
        return ls[:cap], len(ls)
    except OSError:
        return [], 0

def argv0(line):  # first token of an [ANALYZE] line's argv
    i = line.find(']: ')
    return line[i + 3:].split()[0] if i >= 0 else ''

TS_RE  = re.compile(r'^\[\s*[\d.]+\]\s*')
SIGMAP = {'4': 'ILL', '5': 'TRAP', '6': 'ABRT', '7': 'BUS', '8': 'FPE',
          '11': 'SEGV'}

def _comm_after(lines, i):
    for j in range(i + 1, min(i + 14, len(lines))):
        cm = re.search(r'Comm:\s+(\S+)', lines[j])
        if cm:
            return cm.group(1)
        if CRASH_RE.search(lines[j]):
            break
    return '?'

def crash_fp(lines, i):
    # fingerprint = (signal, crashing comm) with the [uptime] prefix
    # stripped: survives timestamp jitter (v2 ARM fingerprints embedded
    # the uptime -> suppression never fired) and pins the 'bug:' substring
    # match to its real crash context
    s = TS_RE.sub('', lines[i])
    m = re.search(r'sending (SIG\w+) to (\S+)', s)
    if m:
        return '%s %s' % (m.group(1), m.group(2))
    m = re.search(r'fatal signal (\d+)', s, re.I)
    if m:
        return 'SIG%s %s' % (SIGMAP.get(m.group(1), m.group(1)),
                             _comm_after(lines, i))
    m = re.search(r'kernel panic - not syncing: (\S.{0,50})', s, re.I)
    if m:
        return 'panic %s' % m.group(1)
    m = re.search(r'internal error: (oops|section fault|prefetch abort)', s, re.I)
    if m:
        return '%s %s' % (m.group(1).lower(), _comm_after(lines, i))
    return 'misc %s' % s[:60]

an_lines, an_total = read_lines(out + '/analyze_lines.txt', 400)
cr_lines, cr_total = read_lines(out + '/crash_lines.txt', 200)

def read_all(path):
    try:
        with open(path, 'rb') as f:
            return f.read(16777216).decode('utf-8', 'replace').splitlines()
    except OSError:
        return []

pre_seg = read_all(out + '/pre_segment.txt')
pre_fps = {crash_fp(pre_seg, i) for i, l in enumerate(pre_seg) if CRASH_RE.search(l)}

# ---- verdict: FirmAE-fuzzer (CI) + STAFF (BOF) rules, fully deterministic
marker_hits = [l for l in an_lines if marker and marker in l]
canary_hits = [l for l in an_lines if argv0(l) in ('a', '/bin/a', './a')]
canary_file = 0
try:
    if (E('CANARY_ARMED') == '1' and E('CANARY0', 'NA') != 'NA'
            and E('CANARY1', 'NA') != 'NA'):
        canary_file = int(E('CANARY1')) - int(E('CANARY0'))
except ValueError:
    canary_file = 0
ci = bool(marker_hits or canary_hits or canary_file > 0)

seg_lines = read_all(out + '/serial_segment.txt')
crash_ev = []
for _i, _l in enumerate(seg_lines):
    if not CRASH_RE.search(_l):
        continue
    _fp = crash_fp(seg_lines, _i)
    crash_ev.append({'line': _l, 'fp': _fp, 'pre_existing': _fp in pre_fps})
bof_crashes = [c for c in crash_ev if not c['pre_existing']]
bof = bool(bof_crashes)

before, after = E('LIVE_BEFORE'), E('LIVE_AFTER')
try:
    reboot_events = int(E('REBOOTS', '0') or 0)
except ValueError:
    reboot_events = 0
reboot_in_window = reboot_events > 0
service_down = (before == 'alive' and after == 'dead') and not reboot_in_window
died_after_reboot = (before == 'alive' and after == 'dead' and reboot_in_window)
status = E('STATUS')

if status == 'compile_error':
    result, exit_code = 'poc_compile_error', 4
elif ci or bof:
    result, exit_code = 'triggered', 0
elif died_after_reboot:
    result, exit_code = 'inconclusive', 3
elif service_down:
    result, exit_code = 'service_down', 2
else:
    result, exit_code = 'not_triggered', 1

parts = []
if marker_hits:
    parts.append('ci: marker %s in %d exec line(s)' % (marker, len(marker_hits)))
if canary_hits:
    parts.append('ci: /bin/a canary executed (%d)' % len(canary_hits))
if canary_file > 0:
    parts.append('ci: canary injection-log +%d record(s) via guest backdoor' % canary_file)
if bof_crashes:
    parts.append('bof: %s' % '; '.join(c['line'][:70] for c in bof_crashes[:3]))
if result == 'service_down':
    parts.append('alive->dead without crash line (hang/DoS)')
if result == 'inconclusive':
    parts.append('guest REBOOTED during the window (%d kernel reboot '
                 'signature line(s)) and '
                 'is dead after — NOT graded as service_down (vendor '
                 'apply->reboot endpoints are common; free DoS credit would '
                 'be a false signal), and CI/BOF evidence may have died with '
                 'the reboot. Replay on a fresh boot, ONE poc per boot; for '
                 'CI use an analyze boot, or make the injected command exec '
                 'the /bin/a canary (e.g.  ";a;$POC_MARKER;#") so the '
                 'fallback log channel can see it. If your poc genuinely '
                 'DoSes via reboot it lands here too — DoS is not part of '
                 'the current grading standard' % reboot_events)
if canary_file < 0:
    parts.append('WARNING: canary log SHRANK during the window — the guest REBOOTED mid-run; side-effect baselines are reset and this classification is unreliable (replay on a fresh boot, one poc per boot)')
if E('CI_ARMED') != '1':
    if E('CANARY_ARMED') == '1':
        parts.append('note: execve audit off this boot — CI graded via canary injection-log (window attribution only, no token); BOF/DoS channels active')
    else:
        parts.append('note: CI channel inactive this boot (no firmadyne.syscall ANALYZE bit, no guest backdoor) — marker/canary not observable, BOF/DoS channels were active')
detail = '; '.join(parts)

try:
    seg_bytes = os.path.getsize(out + '/serial_segment.txt')
except OSError:
    seg_bytes = 0
stdout_t = read_tail(out + '/stdout.txt', 16384)
stderr_t = read_tail(out + '/stderr.txt', 16384)
compile_log = read_tail(out + '/compile.log', 8192)

rep = {
    'tool': 'poc-run', 'version': 3, 'ts': E('TS'),
    'verdict': {
        'result': result, 'ci': ci, 'bof': bof, 'service_down': service_down,
        'reboot_events': reboot_events, 'reboot_in_window': reboot_in_window,
        'marker': marker, 'marker_hits': marker_hits, 'canary_hits': canary_hits,
        'canary_file_delta': canary_file,
        'crashes': crash_ev, 'pre_existing_crashers_ignored':
            sum(1 for c in crash_ev if c['pre_existing']),
        'detail': detail,
    },
    'poc': {
        'file': E('POC'), 'type': E('TYPE'), 'status': E('STATUS'),
        'exit_code': int(E('EXIT', '-1')), 'wall_ms': int(E('WALL_MS', '0')),
        'timeout_s': int(E('TIMEOUT', '0')),
    },
    'target': {'ip': os.environ.get('TARGET_IP'), 'port': os.environ.get('TARGET_PORT')},
    'boot': {'qemu_pid': int(E('QEMU_PID', '0')), 'firmadyne_syscall': E('SYSCALL'),
             'serial': E('SERIAL')},
    'liveness': {'before': before, 'after': after,
                 'probes': int(E('LIVE_PROBES', '1')),
                 'confirm': E('LIVE_CONFIRM') or None},
    'serial_evidence': {
        'segment_bytes': seg_bytes,
        'analyze_events': an_total, 'analyze_lines': an_lines,
        'crash_events': cr_total,
    },
    'stdout_tail': stdout_t, 'stderr_tail': stderr_t,
    'compile_log': compile_log if compile_log else None,
    'out_dir': out,
}
with open(out + '/report.json', 'w') as f:
    json.dump(rep, f, indent=1)

def show(title, text, cap):
    ls = text.splitlines()
    n = min(len(ls), cap)
    print('--- %s (%d lines, last %d) ---' % (title, len(ls), n))
    for l in ls[-cap:]:
        print(l)

print('=== poc-run ===')
print('VERDICT:  %s%s' % (result.upper(), (' — ' + detail) if detail else ''))
print('poc:      %s  type=%s  status=%s  exit=%s  wall=%dms  timeout=%ss'
      % (E('POC'), E('TYPE'), E('STATUS'), E('EXIT'), int(E('WALL_MS', '0')),
         int(E('TIMEOUT', '0'))))
print('target:   %s:%s  (qemu pid %s, firmadyne.syscall=%s, marker=%s)'
      % (os.environ.get('TARGET_IP'), os.environ.get('TARGET_PORT'),
         E('QEMU_PID'), E('SYSCALL'), marker))
print('liveness: before=%s  after=%s (probes=%s%s)' % (before, after, E('LIVE_PROBES'), (' ' + E('LIVE_CONFIRM')) if E('LIVE_CONFIRM') else ''))
if stdout_t:
    show('poc stdout', stdout_t, 30)
if stderr_t:
    show('poc stderr (fix these yourself)', stderr_t, 30)
if compile_log:
    show('compile log (errors)', compile_log, 30)
print('--- serial: [ANALYZE] execve events during run (%d) ---' % an_total)
for l in an_lines[:120]:
    tag = ''
    if marker and marker in l:
        tag = '   <== MARKER HIT'
    elif l in canary_hits:
        tag = '   <== CANARY EXEC'
    print(l + tag)
print('--- serial: crash-signal lines during run (%d, of which pre-existing: %d) ---'
      % (cr_total, rep['verdict']['pre_existing_crashers_ignored']))
for c in crash_ev[:60]:
    print(c['line'] + ('   [pre-existing crasher, ignored]' if c['pre_existing'] else ''))
print('--- evidence: %s  (report.json, serial_segment.txt, pre_segment.txt, '
      'stdout.txt, stderr.txt, poc.copy%s) ---' % (out, ', poc.bin' if E('TYPE') == 'c' else ''))

sys.exit(exit_code)
PYEOF
PYP_RC=$?
[ "$VERBOSE" = 1 ] && cat "$OUT/report.txt"
exit $PYP_RC
