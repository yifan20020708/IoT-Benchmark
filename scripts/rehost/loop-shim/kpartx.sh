#!/bin/bash
# agent-scan :: kpartx shim — serialize kpartx against the global loop lock
# (companion to losetup.sh — same rationale in its header)
#
# kpartx attaches loop devices internally via ioctls, BYPASSING the losetup
# shim — its find-free race therefore needs the same cross-container lock.
# Its loops are NOT alias-protected (unaliased in the global table): the
# translated `losetup -D` will not detach them, and another container's
# listing sees them. Known, accepted residual: kpartx is used by the
# engine's mount.sh/umount.sh (manual debugging), not the automated
# pipeline (add_partition -> losetup only).
set -u
REAL=/usr/sbin/kpartx
[ -x "$REAL" ] || REAL=/sbin/kpartx
[ -x "$REAL" ] || { echo "kpartx(shim): real kpartx not found" >&2; exit 1; }

LOCK=/dev/.agent-scan-losetup.lock
exec 9>"$LOCK"
flock -w 300 9 || echo "kpartx(shim): lock timeout — proceeding unlocked" >&2
exec "$REAL" "$@"
