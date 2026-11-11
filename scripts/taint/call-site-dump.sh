#!/bin/bash
# agent-scan :: taint — call-site-dump (deterministic, host-side)
#
# Usage: call-site-dump.sh [--force] [--out FILE] <binary>
#
# Ghidra-headless static extraction of EVERY call site in EVERY function of
# <binary> — caller-side facts for probe/spec composition: call address,
# return site (fall-through), best-effort callee, per-position physical
# argument locations (calling-convention registers/stack slots) with
# resolved constants (const_string / const_int), the ABI return register,
# and a bounded forward consumer scan of the return value. See
# CallSiteDump.java for the output schema and the three evidence paths.
#
# The Ghidra project is CACHED under <model>/taint-work/ghidra-projects/
# (re-exports skip analysis); --force drops the cache and re-analyzes.
#
# <model> is the nearest ancestor of <binary> holding task.json. Without
# one, the cache lands next to the binary and --out becomes required.
#
# Default output: <model>/taint-work/call-site-dump/<sanitized>.json
#   (taint-work/ is the new architecture's intermediates root; the Phase-1
#    Mapper contract may rename it later — one sed away.)
#
# Exit 0 = dump written; the dumper's summary line goes to stdout.
#
# Env: GHIDRA_INSTALL_DIR (default <repo>/deps/ghidra_12.1.4_PUBLIC),
#      JAVA_HOME (default /opt/java/jdk-21) — host-side Ghidra only, see
#      scripts/rehost/build-deps.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GHIDRA_HOME="${GHIDRA_INSTALL_DIR:-$ROOT/deps/ghidra_12.1.4_PUBLIC}"
export JAVA_HOME="${JAVA_HOME:-/opt/java/jdk-21}"
SCRIPT_DIR="$ROOT/scripts/taint"

FORCE=0
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        --out)   OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
BINARY="${1:?usage: call-site-dump.sh [--force] [--out FILE] <binary>}"
[ -f "$BINARY" ] || { echo "[-] not a file: $BINARY" >&2; exit 1; }
[ -x "$GHIDRA_HOME/support/analyzeHeadless" ] || {
    echo "[-] Ghidra not found at $GHIDRA_HOME (run scripts/rehost/build-deps.sh)" >&2; exit 1; }
BINARY="$(readlink -f "$BINARY")"
BINBASE="$(basename "$BINARY")"

# ---- model folder: nearest ancestor with task.json -------------------------
MODEL=""
d="$(dirname "$BINARY")"
while [ "$d" != "/" ]; do
    if [ -f "$d/task.json" ]; then MODEL="$d"; break; fi
    d="$(dirname "$d")"
done

# ---- cache + output placement ----------------------------------------------
if [ -n "$MODEL" ]; then
    CACHE_BASE="$MODEL/taint-work"
else
    [ -n "$OUT" ] || { echo "[-] no task.json ancestor found — --out is required" >&2; exit 1; }
    CACHE_BASE="$(dirname "$BINARY")"
fi

# project name + display path from the path inside the rootfs (unique per binary)
REL="$(realpath --relative-to="${MODEL:-$(dirname "$BINARY")}/rootfs" "$BINARY" 2>/dev/null || echo "$BINBASE")"
PROJNAME="$(printf '%s' "$REL" | sed 's|/|__|g; s|\.|_|g')"
DISPLAY="rootfs/$REL"
PROJDIR="$CACHE_BASE/ghidra-projects"
OUT="${OUT:-$CACHE_BASE/call-site-dump/$PROJNAME.json}"
mkdir -p "$PROJDIR" "$(dirname "$OUT")"
LOG="$(dirname "$OUT")/.call-site-dump.log"

if [ "$FORCE" = 1 ]; then
    rm -rf "$PROJDIR/$PROJNAME.rep" "$PROJDIR/$PROJNAME.gpr"
    rm -f "$OUT"
fi
# a stale output must never satisfy a failed run (analyzeHeadless exits 0
# even when the postScript errors)
rm -f "$OUT"

echo "[call-site-dump] binary : $BINARY"
echo "[call-site-dump] project: $PROJDIR/$PROJNAME (cached for re-exports)"
echo "[call-site-dump] out    : $OUT"
START=$(date +%s)

if [ -d "$PROJDIR/$PROJNAME.rep" ]; then
    "$GHIDRA_HOME/support/analyzeHeadless" "$PROJDIR" "$PROJNAME" \
        -process "$BINBASE" -noanalysis \
        -scriptPath "$SCRIPT_DIR" \
        -postScript CallSiteDump.java "$OUT" "$DISPLAY" "$BINARY" > "$LOG" 2>&1
else
    "$GHIDRA_HOME/support/analyzeHeadless" "$PROJDIR" "$PROJNAME" \
        -import "$BINARY" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript CallSiteDump.java "$OUT" "$DISPLAY" "$BINARY" > "$LOG" 2>&1
fi
RC=$?

ELAPSED=$(( $(date +%s) - START ))
grep -E "CallSiteDump:|SCRIPT ERROR|ERROR" "$LOG" | tail -3 || true
# the summary line is the script's success handshake — a stale $OUT or a
# postScript error (analyzeHeadless still exits 0) must not pass as OK
if [ $RC -ne 0 ] || [ ! -f "$OUT" ] || ! grep -q "CallSiteDump: functions=" "$LOG"; then
    echo "[call-site-dump] FAILED (rc=$RC, ${ELAPSED}s) — see $LOG" >&2
    exit "${RC:-1}"
fi
echo "[call-site-dump] OK (${ELAPSED}s) -> $OUT"
