#!/bin/bash
# agent-scan :: solved-image entrypoint — one-click firmware boot
#
# Baked into task:<name>:solved via `docker commit --change` after the
# harness has verified the emulation. Boots the SAME state the harness
# verified: PostgreSQL up -> pre-rendered scratch/<iid>/run.sh (which
# blocks in the foreground while QEMU runs).
#
# Run the solved image with the same flags the pipeline needed:
#   docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
#       --restart unless-stopped task-<name>:solved
# (scripts/run-solved.sh wraps this.) Web service lands on the IP recorded
# in scratch/<iid>/ip (~1-2 min under TCG); the image HEALTHCHECK polls it.
#
# If QEMU dies, run.sh tears down its tap and exits, this entrypoint exits
# with it, and docker's restart policy boots a fresh emulation.
set -e

FIRMAE=/opt/FirmAE-pro

# 1. PostgreSQL — run.sh's get_fs/get_kernel shell functions query it
service postgresql start
for _ in $(seq 1 30); do
    pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
pg_isready -q -h 127.0.0.1 || { echo "[solved] PostgreSQL failed to start"; exit 1; }

# 2. the verified emulation = latest scratch dir
IID=$(ls "$FIRMAE/scratch" | grep -E '^[0-9]+$' | sort -n | tail -1)
IP=$(cat "$FIRMAE/scratch/$IID/ip" 2>/dev/null || echo "?")
echo "[solved] booting iid=$IID — web service expected at http://$IP/ within ~2min"

# 3. defensive cleanup: a previous boot killed mid-flight may have left a
#    tap behind (taps live in this netns, so they can only be ours)
for t in $(ip -o link 2>/dev/null | awk -F': ' '$2 ~ /^tap[0-9]/ {print $2}'); do
    ip link del "$t" 2>/dev/null || true
done

# 4. run.sh resolves paths relative to FIRMAE_DIR and blocks on QEMU
cd "$FIRMAE"
exec ./scratch/"$IID"/run.sh
