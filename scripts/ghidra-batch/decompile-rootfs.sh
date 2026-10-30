#!/usr/bin/env bash
# decompile-rootfs - mirror-decompile every ELF binary of an unpacked filesystem.
#
# Usage:  decompile-rootfs [--jobs N] [--force] <rootfs-dir> <output-dir>
#
# Input:  an unpacked firmware filesystem (e.g. binwalk -e .../squashfs-root)
# Output: <output-dir> mirrors <rootfs-dir>'s layout:
#           - every directory      -> same directory (created even if empty)
#           - every symlink        -> symlink; absolute targets are rewritten
#                                     to the equivalent relative path inside
#                                     the output tree (busybox farms stay
#                                     navigable), others mirrored as-is
#           - every ELF binary     -> a DIRECTORY named after the file, filled
#                                     by scripts/ghidra-batch/decompile-all.sh
#                                     with one <function>_<address>.c per
#                                     function + .decompile-all.log
#           - other regular files  -> not represented
# Hardlinked binaries are decompiled once (inode dedup), later links mirror
# the first one's output directory.
#
# Parallelism: --jobs N concurrent Ghidra instances (default 8; each takes
# ~1-2 GB JVM heap, so mind RAM when raising).
# Resume:      a binary is skipped when its output dir already holds a
#              completed run (.decompile-all.log containing "DecompileAll:
#              ok="); --force decompiles everything again.
#
# Exit 0 = no failures (failures listed in <output-dir>/.failed.txt).
set -u

JOBS=8
FORCE=0
while [ $# -gt 2 ]; do
    case "$1" in
        --jobs)  JOBS="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) echo "usage: decompile-rootfs [--jobs N] [--force] <rootfs-dir> <output-dir>" >&2; exit 2 ;;
    esac
done
ROOTFS="${1:?usage: decompile-rootfs [--jobs N] [--force] <rootfs-dir> <output-dir>}"
OUT="${2:?missing output-dir}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$SCRIPT_DIR/decompile-all.sh" ] || { echo "error: $SCRIPT_DIR/decompile-all.sh not found" >&2; exit 2; }
[ -d "$ROOTFS" ] || { echo "error: not a directory: $ROOTFS" >&2; exit 2; }
ROOTFS="$(cd "$ROOTFS" && pwd)"
mkdir -p "$OUT" || exit 2
OUT="$(cd "$OUT" && pwd)"

START=$(date +%s)
echo "[decompile-rootfs] rootfs : $ROOTFS"
echo "[decompile-rootfs] out    : $OUT (jobs=$JOBS force=$FORCE)"

# ---------------------------------------------------------------------------
# 1. mirror the directory skeleton (even dirs that hold no binaries)
# ---------------------------------------------------------------------------
find "$ROOTFS" -type d -print0 | while IFS= read -r -d '' d; do
    mkdir -p "$OUT${d#"$ROOTFS"}"
done

# ---------------------------------------------------------------------------
# 2. mirror symlinks (absolute targets rewritten to output-relative)
# ---------------------------------------------------------------------------
nsym=0
while IFS= read -r -d '' l; do
    rel=${l#"$ROOTFS"}
    tgt=$(readlink "$l")
    case "$tgt" in
        /*) if [ -e "$ROOTFS$tgt" ]; then
                # point it at the mirrored location inside $OUT
                tgt=$(realpath -m --relative-to="$OUT$(dirname "$rel")" "$OUT$tgt")
            fi ;;
    esac
    ln -sfn "$tgt" "$OUT$rel" 2>/dev/null && nsym=$((nsym + 1))
done < <(find "$ROOTFS" -type l -print0)

# ---------------------------------------------------------------------------
# 3. enumerate ELF binaries (regular files), dedup hardlinks by inode
# ---------------------------------------------------------------------------
echo "[decompile-rootfs] scanning for ELF files ..."
ELFLIST=$(mktemp); trap 'rm -f "$ELFLIST"' EXIT
find "$ROOTFS" -type f -print0 | xargs -0 -r file -F $'\t' \
    | awk -F'\t' '$2 ~ /ELF/ { print $1 }' > "$ELFLIST"

declare -A INODE_SEEN
njobs=0
JOBFILE=$(mktemp); trap 'rm -f "$ELFLIST" "$JOBFILE"' EXIT
while IFS= read -r bin; do
    rel=${bin#"$ROOTFS/"}
    key=$(stat -c '%d_%i' "$bin")
    if [ -n "${INODE_SEEN[$key]:-}" ]; then
        # hardlink twin: mirror the first one's output dir instead
        ln -sfn "$(realpath -m --relative-to="$OUT$(dirname "/$rel")" "${INODE_SEEN[$key]}")" \
            "$OUT/$rel" 2>/dev/null
        continue
    fi
    INODE_SEEN[$key]="$OUT/$rel"
    printf '%s\0' "$rel" >> "$JOBFILE"
    njobs=$((njobs + 1))
done < "$ELFLIST"
echo "[decompile-rootfs] $njobs ELF binaries ($nsym symlinks mirrored)"

# ---------------------------------------------------------------------------
# 4. run decompile-all.sh in parallel (skip already-completed on resume)
# ---------------------------------------------------------------------------
preskip=0
while IFS= read -r -d '' rel; do
    if [ "$FORCE" -ne 1 ] && [ -f "$OUT/$rel/.decompile-all.log" ] \
       && grep -q 'DecompileAll: ok=' "$OUT/$rel/.decompile-all.log"; then
        preskip=$((preskip + 1))
    fi
done < "$JOBFILE"

run_one() {
    # NB: separate `local` lines — a chained `local a=x b=$a` expands $a
    # with its OLD (outer-scope) value, because all words of the `local`
    # command are expanded before the builtin assigns anything.
    local rel="$1"
    local in="$ROOTFS/$rel"
    local out="$OUT/$rel"
    mkdir -p "$out"
    if [ "$FORCE" -ne 1 ] && [ -f "$out/.decompile-all.log" ] \
       && grep -q 'DecompileAll: ok=' "$out/.decompile-all.log"; then
        echo "[skip] $rel"
        return 0
    fi
    "$SCRIPT_DIR/decompile-all.sh" "$in" "$out" >/dev/null 2>&1
    if [ -f "$out/.decompile-all.log" ] && grep -q 'DecompileAll: ok=' "$out/.decompile-all.log"; then
        echo "[ ok ] $rel"
    else
        echo "[fail] $rel"
        return 1
    fi
}
export -f run_one
export ROOTFS OUT SCRIPT_DIR FORCE

xargs -0 -r -P "$JOBS" -n 1 bash -c 'run_one "$1"' _ < "$JOBFILE" || true

# ---------------------------------------------------------------------------
# 5. summary — per THIS run's job list, verdicts from the logs on disk
# ---------------------------------------------------------------------------
ok=0; fail=0; : > "$OUT/.failed.txt"
while IFS= read -r -d '' rel; do
    log="$OUT/$rel/.decompile-all.log"
    if [ -f "$log" ] && grep -q 'DecompileAll: ok=' "$log"; then
        ok=$((ok + 1))
    else
        fail=$((fail + 1))
        echo "$rel" >> "$OUT/.failed.txt"
    fi
done < "$JOBFILE"

ELAPSED=$(( $(date +%s) - START ))
echo
echo "===== decompile-rootfs ====="
echo "rootfs        : $ROOTFS"
echo "binaries ok   : $ok   ($preskip skipped as already-done, still counted)"
echo "failed        : $fail (listed in .failed.txt)"
echo "symlinks      : $nsym mirrored"
echo "elapsed       : ${ELAPSED}s  ($((ELAPSED / 60))m$((ELAPSED % 60))s)"
[ "$fail" -eq 0 ] || exit 1
