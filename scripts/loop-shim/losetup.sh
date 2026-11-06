#!/bin/bash
# agent-scan :: losetup shim — parallel-safe loop-device access
# (full rationale: the header comment itself; companion kpartx.sh)
#
# Installed at /usr/local/sbin/losetup (PATH shadows /usr/sbin/losetup;
# task-image PATH order verified: /usr/local/sbin comes first). Everything
# in the engine (firmae.config add_partition, makeImage.sh, the generated
# run.sh) and the agents calls unqualified `losetup` — all covered.
#
# Loop devices are kernel-global and NOT namespaced; task containers share
# the host /dev, so concurrent agents sabotage each other three ways:
#   A. find-free race in `losetup -Pf` -> add_partition's poll spins forever
#   B. agent-improvised `losetup -D` detaches every VISIBLE loop (other
#      containers' active images, snapd's, solved containers')
#   C. add_partition claims loops by backing-path STRING; identical paths
#      in different containers (each has its own /opt/FirmAE-pro) let one
#      container mount another's image — silent cross-corruption
#
# The shim: one global cross-container flock (file in the shared /dev)
# kills A; attaches go through a per-container HARDLINK alias
# (/tmp/loop-alias/<hostname>-<n> — same inode, globally unique path
# string; /tmp and /opt verified on the same overlay) and listings rewrite
# our aliases back to the original path while hiding foreign ones, killing
# C; `-D` is translated to detach only loops this container attached (via
# the alias map), killing B; `-d` of a foreign-aliased loop is refused
# (visible message, rc 0 so cleanup scripts don't derail).
#
# Residual blind spots (see above): absolute-path losetup
# calls, `mount -o loop`, and loops attached inside kpartx (own shim:
# lock only). The automated pipeline uses unqualified losetup only.
#
# State: /tmp/loop-alias/<hostname>-<n>       hardlink alias (until detach)
#        /tmp/loop-alias/<hostname>-<n>.map  "<device>|<original-path>"
set -u

REAL=/usr/sbin/losetup
[ -x "$REAL" ] || REAL=/sbin/losetup
[ -x "$REAL" ] || { echo "losetup(shim): real losetup not found" >&2; exit 1; }

ALIAS_DIR=/tmp/loop-alias
HOST=$(cat /proc/sys/kernel/hostname 2>/dev/null) || HOST=ctr
LOCK=/dev/.agent-scan-losetup.lock       # /dev is shared -> cross-container
mkdir -p "$ALIAS_DIR" 2>/dev/null || true

ERRF=/tmp/.losetup-shim.$$.err
trap 'rm -f "$ERRF" 2>/dev/null' EXIT

lock() {
    exec 9>"$LOCK"
    flock -w 300 9 || echo "losetup(shim): lock timeout — proceeding unlocked" >&2
}
# NB: bare `exec 9>&-` only — a `2>/dev/null` here would redirect the
# SHELL's stderr to /dev/null permanently and silently swallow every later
# diagnostic (learned the hard way in preflight: the -D message vanished)
unlock() { exec 9>&-; return 0; }

# ---------------------------------------------------------------------------
# output filter — rewrite OUR aliases back to the original path, DROP lines
# belonging to foreign aliases. Format-agnostic (token rewrite): works both
# for the table format of bare `losetup` (BACK-FILE in column 6 — what
# add_partition parses) and the "NAME: [maj:min] ino (path)" of -a/-j.
# ---------------------------------------------------------------------------
filter_output() {
    local line out tok foreign orig toks
    while IFS= read -r line; do
        case "$line" in
        *"$ALIAS_DIR/"*)
            out=$line; foreign=0
            toks=$(printf '%s\n' "$line" | grep -o "$ALIAS_DIR/[^ )]*" || true)
            while IFS= read -r tok; do
                [ -n "$tok" ] || continue
                case "$tok" in
                "$ALIAS_DIR/$HOST"-*)
                    orig=""
                    [ -f "$tok.map" ] && orig=$(cut -d'|' -f2 "$tok.map" 2>/dev/null)
                    [ -n "$orig" ] && out=${out//"$tok"/"$orig"} ;;
                *) foreign=1 ;;
                esac
            done <<< "$toks"
            [ "$foreign" = 0 ] && printf '%s\n' "$out" ;;
        *)  printf '%s\n' "$line" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# argv classification (pragmatic — covers every losetup form the engine,
# emu, hverify or a cleanup-minded agent produces; exotic forms fall
# through to locked passthrough, which is always safe)
# ---------------------------------------------------------------------------
detach_all=0; find_free=0; has_j=0; has_d=0; has_c=0
fileop=""; devop=""
argv=("$@")
skip=0
i=0
while [ $i -lt ${#argv[@]} ]; do
    a=${argv[$i]}
    if [ "$skip" = 1 ]; then skip=0; i=$((i+1)); continue; fi
    case "$a" in
    --detach-all)  detach_all=1 ;;
    --detach)      has_d=1; skip=1 ;;
    --find)        find_free=1 ;;
    --associated)  has_j=1; skip=1 ;;
    --offset|--output|--sizelimit|--set-capacity) skip=1 ;;
    --partscan|--read-only|--show|--list|--all|--no-loopback|--help|-V|--version) ;;
    -[A-Za-z]*)
        s=${a#-}
        while [ -n "$s" ]; do
            c=${s:0:1}
            case "$c" in
            D) detach_all=1; s=${s:1} ;;
            f) find_free=1;   s=${s:1} ;;
            j) has_j=1;       s=${s:1} ;;
            c) has_c=1;       s=${s:1} ;;
            # value-taking: rest of cluster (if any) is the value
            d) has_d=1; s=${s:1}; break ;;
            o|O)       s=${s:1}; break ;;
            *)         s=${s:1} ;;
            esac
        done
        # cluster ENDED on a value-taking letter (-o, -d, -O, -j): the next
        # arg is that value, not an operand
        case "$a" in -[A-Za-z]*[odOj]) skip=1 ;; esac
        ;;
    *)  # operand: regular file (backing-file candidate) or loop device
        if [ -f "$a" ]; then
            fileop="$a"
        else
            case "$a" in /dev/loop*|loop*) devop="$a" ;; esac
        fi ;;
    esac
    i=$((i+1))
done

# ---------------------------------------------------------------------------
# -D / --detach-all: translate to "detach only what THIS container attached"
# (the original nukes every visible loop — cross-container sabotage)
# ---------------------------------------------------------------------------
if [ "$detach_all" = 1 ]; then
    lock
    n=0
    for m in "$ALIAS_DIR/$HOST"-*.map; do
        [ -f "$m" ] || continue
        dev=$(cut -d'|' -f1 "$m" 2>/dev/null)
        if [ -n "$dev" ] && "$REAL" -d "$dev" 2>/dev/null; then
            rm -f "$m" "${m%.map}"
            n=$((n+1))
        fi
    done
    unlock
    echo "losetup(shim): --detach-all translated: detached $n loop(s) owned by this container" >&2
    exit 0
fi

# ---------------------------------------------------------------------------
# -d <dev>: allow ours, refuse foreign-aliased, passthrough the rest
# ---------------------------------------------------------------------------
if [ "$has_d" = 1 ]; then
    targ=""
    for a in "$@"; do
        case "$a" in /dev/loop*|loop*) targ=$a; break ;; esac
    done
    base=$(printf '%s' "${targ##*/}" | sed 's/p[0-9]*$//')   # loop18p1 -> loop18
    mine=""
    if [ -n "$base" ]; then
        for m in "$ALIAS_DIR/$HOST"-*.map; do
            [ -f "$m" ] || continue
            [ "$(cut -d'|' -f1 "$m" 2>/dev/null)" = "/dev/$base" ] && mine=$m
        done
    fi
    if [ -n "$mine" ]; then
        lock
        "$REAL" "$@" 2>"$ERRF"; rc=$?
        unlock
        cat "$ERRF" >&2 2>/dev/null
        # drop alias+map only on real success — a failed detach (e.g. the
        # engine's partition-node form) leaves the loop tracked
        [ $rc -eq 0 ] && rm -f "$mine" "${mine%.map}"
        exit $rc
    fi
    # no local map: is the loop aliased to a FOREIGN container?
    bp=$( { "$REAL" -O NAME,BACK-FILE 2>/dev/null || true; } \
          | awk -v d="/dev/$base" '$1==d {print $2}' | head -1)
    case "$bp" in
    "$ALIAS_DIR/$HOST"-*) ;;  # ours with a lost map — allow below
    "$ALIAS_DIR"/*)
        echo "losetup(shim): refusing --detach of foreign loop ${targ:-?} (owned by another container)" >&2
        exit 0 ;;
    esac
    lock
    "$REAL" "$@" 2>"$ERRF"; rc=$?
    unlock
    cat "$ERRF" >&2 2>/dev/null
    exit $rc
fi

# ---------------------------------------------------------------------------
# attach: file operand present, no query/capacity mode -> run through a
# per-container hardlink alias so the GLOBAL loop table records a path
# unique to this container (path-string collision = cross-container theft)
# ---------------------------------------------------------------------------
if [ -n "$fileop" ] && [ "$has_j$has_c" = "00" ]; then
    alias=""
    n=1
    while [ -e "$ALIAS_DIR/$HOST-$n" ] || [ -e "$ALIAS_DIR/$HOST-$n.map" ]; do
        n=$((n+1))
    done
    a="$ALIAS_DIR/$HOST-$n"
    ln "$fileop" "$a" 2>/dev/null && alias="$a"   # EXDEV -> unaliased (still locked)
    if [ -n "$alias" ]; then
        newargv=()
        for x in "$@"; do [ "$x" = "$fileop" ] && x="$alias"; newargv+=("$x"); done
    else
        newargv=("$@")
    fi
    lock
    out=$("$REAL" "${newargv[@]}" 2>"$ERRF"); rc=$?
    if [ -n "$alias" ]; then
        dev=$("$REAL" -j "$alias" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -n "$dev" ]; then
            printf '%s|%s\n' "$dev" "$fileop" > "$alias.map"
        else
            rm -f "$alias"    # attach failed: nothing to remember
        fi
    fi
    unlock
    cat "$ERRF" >&2 2>/dev/null
    [ -n "$out" ] && printf '%s\n' "$out" | filter_output
    exit $rc
fi

# ---------------------------------------------------------------------------
# everything else (bare listing, -a, -O, -j, -f alone, -c, --help, ...):
# locked passthrough with the output projection applied
# ---------------------------------------------------------------------------
lock
out=$("$REAL" "$@" 2>"$ERRF"); rc=$?
unlock
cat "$ERRF" >&2 2>/dev/null
[ -n "$out" ] && printf '%s\n' "$out" | filter_output
exit $rc
