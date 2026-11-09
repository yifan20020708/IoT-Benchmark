#!/bin/bash
# agent-scan :: one-click launch of a solved task image
# Usage: run-solved.sh <task-name> [container-name]
#
# Boots the harness-verified emulation: firmware's web service comes up at
# the IP recorded in task.yaml / scratch/<iid>/ip (~1-2 min under TCG).
# --restart unless-stopped: if QEMU dies, the entrypoint exits and docker
# boots a fresh emulation automatically.
set -euo pipefail
NAME="${1:?usage: run-solved.sh <task-name> [container-name]}"
CONTAINER="${2:-solved-$NAME}"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d \
    --init \
    --privileged \
    --device /dev/kvm \
    -v /dev:/dev \
    --restart unless-stopped \
    --name "$CONTAINER" \
    "task-$NAME:solved"

echo "container : $CONTAINER (watch health: docker ps)"
echo "web       : docker exec $CONTAINER curl http://<ip>/   (IP: tasks/$NAME/output/ip or harness_ip)"
