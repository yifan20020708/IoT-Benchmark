#!/bin/bash
# agent-scan :: taint — Ghidra xref-index builder (deterministic, host-side)
#
# Usage: ghidra-index.sh [--force] [--out FILE] <binary>
#
# Analyzes <binary> once with Ghidra headless and exports the per-function
# xref index (referenced strings, call edges with argument strings,
# decompiled-text calls with resolved PIC arithmetic — see
# IndexExporter.java). The Ghidra project is CACHED under
# <model>/taint-source/ghidra-projects/ so re-exports skip analysis
# (seconds instead of minutes); --force drops the cache and re-analyzes.
#
# <model> is the nearest ancestor directory of <binary> holding task.json
# (the dataset's model-folder marker). Without one, the cache lands next to
# the binary and --out becomes required.
#
# Default output: <model>/taint-source/ghidra-index/<sanitized-rel-path>.json
# Exit 0 = index written; the exporter's own summary line goes to stdout.
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
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
BINARY="${1:?usage: ghidra-index.sh [--force] [--out FILE] <binary>}"
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
    CACHE_BASE="$MODEL/taint-source"
else
    [ -n "$OUT" ] || { echo "[-] no task.json ancestor found — --out is required" >&2; exit 1; }
    CACHE_BASE="$(dirname "$BINARY")"
fi

# project name from the path inside the rootfs (unique per binary)
REL="$(realpath --relative-to="${MODEL:-$(dirname "$BINARY")}/rootfs" "$BINARY" 2>/dev/null || echo "$BINBASE")"
PROJNAME="$(printf '%s' "$REL" | sed 's|/|__|g; s|\.|_|g')"
PROJDIR="$CACHE_BASE/ghidra-projects"
OUT="${OUT:-$CACHE_BASE/ghidra-index/$PROJNAME.json}"
mkdir -p "$PROJDIR" "$(dirname "$OUT")"
LOG="$(dirname "$OUT")/.ghidra-index.log"

if [ "$FORCE" = 1 ]; then
    rm -rf "$PROJDIR/$PROJNAME.rep" "$PROJDIR/$PROJNAME.gpr"
    rm -f "$OUT"
fi

echo "[ghidra-index] binary : $BINARY"
echo "[ghidra-index] project: $PROJDIR/$PROJNAME (cached for re-exports)"
echo "[ghidra-index] out    : $OUT"
START=$(date +%s)

if [ -d "$PROJDIR/$PROJNAME.rep" ]; then
    "$GHIDRA_HOME/support/analyzeHeadless" "$PROJDIR" "$PROJNAME" \
        -process "$BINBASE" -noanalysis \
        -scriptPath "$SCRIPT_DIR" \
        -postScript IndexExporter.java "$OUT" > "$LOG" 2>&1
else
    "$GHIDRA_HOME/support/analyzeHeadless" "$PROJDIR" "$PROJNAME" \
        -import "$BINARY" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript IndexExporter.java "$OUT" > "$LOG" 2>&1
fi
RC=$?

ELAPSED=$(( $(date +%s) - START ))
grep -E "IndexExporter:|SCRIPT ERROR|ERROR" "$LOG" | tail -3 || true
if [ $RC -ne 0 ] || [ ! -f "$OUT" ]; then
    echo "[ghidra-index] FAILED (rc=$RC, ${ELAPSED}s) — see $LOG" >&2
    exit "${RC:-1}"
fi
echo "[ghidra-index] OK (${ELAPSED}s) -> $OUT"
