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
#       SERVICE DOWN  : service was alive, is dead after, and no crash line
#                       (hang/DoS).
#   * Everything (your stdout/stderr, the serial window, the raw segment)
#     is kept in the evidence dir for your own analysis.
#   * The emulation must be booted in ANALYZE mode (firmadyne.syscall=32,
#     e.g. `emu analyze`); the crash channel is on in every boot mode.
#
# Usage:
#   poc-run.sh <poc.py|poc.c> [poc args...] [--timeout S] [--port P]
#              [--serial PATH] [--out-root DIR] [--verbose]
# Output contract: stdout/stderr are SILENT unless --verbose. The exit code
#   is the only immediate signal; the full human-readable report lands at
#   <out>/report.txt (machine copy report.json beside it) and
#   <out-root>/latest always symlinks to the newest run, so:
#       poc-run.sh /work/poc/poc.py || cat /tmp/poc-runs/latest/report.txt
# Exit:   0 TRIGGERED | 1 not triggered | 2 service down | 3 infra error
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

# ANALYZE channel must be armed (firmadyne.syscall bit 32), else CI runs blind
SC=$(printf '%s\n' "$CMDLINE" | grep -o 'firmadyne\.syscall=[0-9]\+' | head -1 | cut -d= -f2)
SC=${SC:-0}
if [ "$(( SC & 32 ))" -eq 0 ]; then
  fail 3 "ANALYZE channel off (firmadyne.syscall=$SC): reboot the emulation in analyze mode first (e.g. emu stop && emu analyze)"
fi

IP=$(head -n1 "$(dirname "$SERIAL")/ip" 2>/dev/null | tr -d '[:space:]')
[ -n "$IP" ] || fail 3 "guest IP not found at $(dirname "$SERIAL")/ip"

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
grep -a -E 'sending SIG(SEGV|BUS|ILL|FPE|KILL|TRAP)|Potentially unexpected fatal signal|Kernel panic|Oops:|BUG:|general protection fault' \
  "$OUT/serial_segment.txt" > "$OUT/crash_lines.txt" 2>/dev/null || true
# pre-run segment -> STAFF-style dry-run ignore list (pre-existing crashers)
head -c "$OFFSET" "$SERIAL" 2>/dev/null | tail -c 262144 > "$OUT/pre_segment.txt" || true
LIVE_AFTER=$(probe "$IP" "$PORT")

# ------------------------------------------------------------- report ------
export POCRUN_OUT="$OUT" POCRUN_POC="$POC" POCRUN_TYPE="$EXT" \
       POCRUN_STATUS="$STATUS" POCRUN_EXIT="$RC" POCRUN_WALL_MS="$WALL_MS" \
       POCRUN_TIMEOUT="$TIMEOUT" POCRUN_QEMU_PID="$QEMU_PID" \
       POCRUN_SYSCALL="$SC" POCRUN_SERIAL="$SERIAL" POCRUN_MARKER="$MARKER" \
       POCRUN_LIVE_BEFORE="$LIVE_BEFORE" POCRUN_LIVE_AFTER="$LIVE_AFTER" \
       POCRUN_TS="$TS"

python3 - <<'PYEOF' > "$OUT/report.txt"
import json, os, re, sys

out = os.environ['POCRUN_OUT']
E = lambda k, d='': os.environ.get('POCRUN_' + k, d)
marker = E('MARKER')

CRASH_RE = re.compile(r'sending SIG(SEGV|BUS|ILL|FPE|KILL|TRAP)|'
                      r'Potentially unexpected fatal signal|Kernel panic|'
                      r'Oops:|BUG:|general protection fault')

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

def crash_fp(line):
    m = re.search(r'sending (SIG\w+) to (\S+)', line)
    if m:
        return '%s %s' % (m.group(1), m.group(2))
    m = re.search(r'Potentially unexpected fatal signal (\d+)', line)
    if m:
        return 'fatalsig %s' % m.group(1)
    return line[:60]

an_lines, an_total = read_lines(out + '/analyze_lines.txt', 400)
cr_lines, cr_total = read_lines(out + '/crash_lines.txt', 200)
pre_lines, _ = read_lines(out + '/pre_segment.txt', 3000)
pre_fps = {crash_fp(l) for l in pre_lines if CRASH_RE.search(l)}

# ---- verdict: FirmAE-fuzzer (CI) + STAFF (BOF) rules, fully deterministic
marker_hits = [l for l in an_lines if marker and marker in l]
canary_hits = [l for l in an_lines if argv0(l) in ('a', '/bin/a', './a')]
ci = bool(marker_hits or canary_hits)

crash_ev = [{'line': l, 'pre_existing': crash_fp(l) in pre_fps} for l in cr_lines]
bof_crashes = [c for c in crash_ev if not c['pre_existing']]
bof = bool(bof_crashes)

before, after = E('LIVE_BEFORE'), E('LIVE_AFTER')
service_down = (before == 'alive' and after == 'dead')
status = E('STATUS')

if status == 'compile_error':
    result, exit_code = 'poc_compile_error', 4
elif ci or bof:
    result, exit_code = 'triggered', 0
elif service_down:
    result, exit_code = 'service_down', 2
else:
    result, exit_code = 'not_triggered', 1

parts = []
if marker_hits:
    parts.append('ci: marker %s in %d exec line(s)' % (marker, len(marker_hits)))
if canary_hits:
    parts.append('ci: /bin/a canary executed (%d)' % len(canary_hits))
if bof_crashes:
    parts.append('bof: %s' % '; '.join(c['line'][:70] for c in bof_crashes[:3]))
if result == 'service_down':
    parts.append('alive->dead without crash line (hang/DoS)')
detail = '; '.join(parts)

try:
    seg_bytes = os.path.getsize(out + '/serial_segment.txt')
except OSError:
    seg_bytes = 0
stdout_t = read_tail(out + '/stdout.txt', 16384)
stderr_t = read_tail(out + '/stderr.txt', 16384)
compile_log = read_tail(out + '/compile.log', 8192)

rep = {
    'tool': 'poc-run', 'version': 2, 'ts': E('TS'),
    'verdict': {
        'result': result, 'ci': ci, 'bof': bof, 'service_down': service_down,
        'marker': marker, 'marker_hits': marker_hits, 'canary_hits': canary_hits,
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
    'liveness': {'before': before, 'after': after},
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
print('liveness: before=%s  after=%s' % (before, after))
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
