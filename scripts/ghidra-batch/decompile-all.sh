#!/usr/bin/env bash
# decompile-all.sh - decompile every function of one binary with Ghidra headless.
#
# Usage:   decompile-all.sh <binary> <output-dir>
# Input:   any Ghidra-supported binary (ELF/PE/Mach-O, all architectures);
#          symlinks are resolved to the real file
# Output:  <output-dir>/<function>_<address>.c   one pseudocode file per function
#          <output-dir>/.decompile-all.log       full analyzeHeadless run log
#
# Env:     GHIDRA_INSTALL_DIR (default /root/projects/agent-scan/deps/ghidra_12.1.4_PUBLIC)
#          JAVA_HOME          (default /opt/java/jdk-21)
#
# Notes:   uses an ephemeral Ghidra project (mktemp + -deleteProject), so no
#          analysis database persists between runs; the input file is never
#          modified. Exit code is analyzeHeadless's; summary goes to stdout.
set -u

GHIDRA_HOME="${GHIDRA_INSTALL_DIR:-/root/projects/agent-scan/deps/ghidra_12.1.4_PUBLIC}"
export JAVA_HOME="${JAVA_HOME:-/opt/java/jdk-21}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { echo "Usage: $(basename "$0") <binary> <output-dir>" >&2; exit 2; }
[ $# -eq 2 ] || usage
BIN="$1"; OUT="$2"
[ -f "$BIN" ] || { echo "error: not a file: $BIN" >&2; exit 2; }
[ -x "$GHIDRA_HOME/support/analyzeHeadless" ] || { echo "error: Ghidra not found at $GHIDRA_HOME" >&2; exit 2; }

mkdir -p "$OUT" || exit 2
BIN="$(readlink -f "$BIN")"
OUT="$(readlink -f "$OUT")"
LOG="$OUT/.decompile-all.log"

PROJ="$(mktemp -d /tmp/ghidra-decompile-all.sh-XXXXXX)"
trap 'rm -rf "$PROJ"' EXIT

echo "[decompile-all.sh] target : $BIN"
echo "[decompile-all.sh] outdir : $OUT"
START=$(date +%s)

"$GHIDRA_HOME/support/analyzeHeadless" "$PROJ" tmp \
  -import "$BIN" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript DecompileAll.java "$OUT" \
  -deleteProject > "$LOG" 2>&1
RC=$?

ELAPSED=$(( $(date +%s) - START ))
grep -E "DecompileAll:|SCRIPT ERROR|EXCEPTION" "$LOG" | tail -3
if [ $RC -ne 0 ]; then
  echo "[decompile-all.sh] FAILED (rc=$RC, ${ELAPSED}s) - see $LOG" >&2
  exit $RC
fi
N=$(find "$OUT" -maxdepth 1 -name '*.c' | wc -l)
echo "[decompile-all.sh] OK: $N .c files in ${ELAPSED}s -> $OUT"
