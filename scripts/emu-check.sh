#!/bin/bash
# agent-scan :: one-shot emulation check
#
# Runs the full FirmAE-pro pipeline for the task's firmware:
#   extract (binwalk) -> getArch -> makeImage -> inferNetwork (arbitration
#   test boots) -> final boot -> network/web reachability check.
# Success is recorded in /opt/FirmAE-pro/scratch/<iid>/result ("true"/"false").
#
# Usage: emu-check [firmware_path] [brand]
# Defaults come from the task image env: $FIRMWARE and $BRAND.
set -e

FW="${1:-${FIRMWARE:-}}"
BRAND="${2:-${BRAND:-auto}}"

if [ -z "$FW" ] || [ ! -e "$FW" ]; then
    echo "emu-check: firmware not found: '$FW' (set FIRMWARE or pass a path)" >&2
    exit 1
fi

cd /opt/FirmAE-pro
exec ./run.sh -c "$BRAND" "$FW"
