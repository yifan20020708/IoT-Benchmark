#!/bin/bash
# agent-scan :: commit-solved.sh — promote a harness-verified task container
# to a solved image (the step AFTER agent-run.sh reports success)
#
# Usage: commit-solved.sh <fw-folder>
#   e.g.: ./scripts/rehost/commit-solved.sh data/firmware/tenda/TEG5328FV1.0
#
# Preconditions (checked, fail fast):
#   - <fw-folder>/result.json holds status=success (harness ground truth —
#     a merely-agent-claimed success must never be promoted)
#   - the task container exists (kept running by agent-run.sh) and holds
#     no live QEMU (hverify leaves it clean; emu stop otherwise)
# What it does:
#   - hygiene: strip everything the BUILD agent left behind so it cannot
#     ship in the deliverable — session data (/root/.claude*), caches,
#     scratch in /tmp (extraction copies, disasm tools, boot logs) — and
#     stop PostgreSQL for a clean data dir (solved-entrypoint restarts it)
#   - docker commit with the solved runtime config:
#       ENTRYPOINT solved-entrypoint  (one-click boot, default mode)
#       HEALTHCHECK     web poll on the recorded guest IP
#     /usr/local/bin/{emu,emu-shell,hverify} were shipped into the task
#     container by agent-run.sh, so the lab entrypoint rides along.
# Result: image task-<vendor__model>:solved. Exit 0 = created.
# The promotion consumes its inputs: the task container is removed and the
# superseded task-<id>:raw image is untagged — the solved image is the only
# artifact that remains (its layer chain still shares firmae-base layers).
#
# The solved image is the complete agent world for the next phase:
#   dynamic side — emu {run,debug,boot,analyze,debug-analyze,stop,status,...}
#   static side  — /home/{rootfs,decompiled-rootfs,scripts,workspace}
#   poc side     — /work/{poc,poc-runs} (poc sources | grading evidence)
# NOT baked by design: scripts/taint/poc-run.sh and the decompiled-rootfs
# mirror are host-side standing assets — `docker cp` them at derive time so
# grading always replays the CURRENT script, never a stale baked copy.
set -euo pipefail

FWDIR="${1:?usage: commit-solved.sh <fw-folder>}"
FWDIR="$(cd "$FWDIR" 2>/dev/null && pwd)" || { echo "[-] no such folder: $1" >&2; exit 1; }

[ -f "$FWDIR/result.json" ] || { echo "[-] no result.json in $FWDIR (run agent-run.sh first)" >&2; exit 1; }
STATUS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$FWDIR/result.json")
[ "$STATUS" = "success" ] || { echo "[-] result.json status=$STATUS — only harness-verified successes may be promoted" >&2; exit 1; }

[ -f "$FWDIR/task.json" ] || { echo "[-] missing task.json" >&2; exit 1; }

VENDOR=$(basename "$(dirname "$FWDIR")")
MODEL=$(basename "$FWDIR")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODEL" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')
CONTAINER="task-$TASK_ID"
IMAGE="task-$TASK_ID:solved"

docker container inspect "$CONTAINER" >/dev/null 2>&1 || { echo "[-] no such container: $CONTAINER" >&2; exit 1; }
NQ=$(docker exec "$CONTAINER" bash -c 'pgrep -f "^qemu-system" | wc -l' 2>/dev/null || echo 1)
[ "$NQ" = "0" ] || { echo "[-] QEMU still running in $CONTAINER — stop it first (docker exec $CONTAINER emu stop)" >&2; exit 1; }

# the commit will point ENTRYPOINT at solved-entrypoint — it must exist
# (agent-run.sh ships it; a container built by an older flow may lack it,
# which would produce an image that dies with exit 127 on first boot)
docker exec "$CONTAINER" test -x /usr/local/bin/solved-entrypoint \
    || { echo "[-] /usr/local/bin/solved-entrypoint missing in $CONTAINER — docker cp scripts/rehost/solved-entrypoint.sh $CONTAINER:/usr/local/bin/solved-entrypoint first" >&2; exit 1; }

echo "[*] promoting $CONTAINER -> $IMAGE"
echo "[*] hygiene: stripping build-agent leftovers"
docker exec "$CONTAINER" bash -c '
rm -rf /root/.claude /root/.claude.json /root/.cache /root/.npm
rm -rf /home/workspace/.claude
rm -rf /tmp/* 2>/dev/null || true
# Phase-2 workspace skeleton (baked empty; content arrives at derive/run time)
mkdir -p /work/poc /work/poc-runs /home/workspace
service postgresql stop >/dev/null 2>&1 || true
'

docker commit \
    --change 'ENTRYPOINT ["/usr/local/bin/solved-entrypoint"]' \
    --change 'CMD []' \
    --change 'HEALTHCHECK --interval=30s --timeout=5s --start-period=200s --retries=3 CMD for ip in $(cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null); do curl -sL --max-redirs 5 -o /dev/null --max-time 4 "http://$ip/" && exit 0; done; exit 1' \
    "$CONTAINER" "$IMAGE" >/dev/null

IID=$(docker exec "$CONTAINER" bash -c 'ls /opt/FirmAE-pro/scratch/ | grep -E "^[0-9]+$" | sort -n | tail -1')
IP=$(docker exec "$CONTAINER" bash -c "cat /opt/FirmAE-pro/scratch/$IID/ip /opt/FirmAE-pro/scratch/$IID/ip.[0-9]* 2>/dev/null | head -1" || echo "?")
SIZE=$(docker images "$IMAGE" --format '{{.Size}}')

# the promotion consumed its inputs — remove them (IP was read first)
docker rm -f "$CONTAINER" >/dev/null
docker rmi "task-${TASK_ID}:raw" >/dev/null 2>&1 || true

# reflect the promotion in the host-side result.json: the raw image and the
# task container no longer exist — the solved image is the artifact of record
python3 - "$FWDIR/result.json" "$IMAGE" <<'EOF'
import json, sys
path, image = sys.argv[1], sys.argv[2]
d = json.load(open(path))
d["image"] = image
d["container"] = None
json.dump(d, open(path, "w"), indent=2, ensure_ascii=False)
EOF

echo
echo "===== commit-solved: $TASK_ID ====="
echo "image     : $IMAGE ($SIZE)"
echo "removed   : $CONTAINER (container), task-${TASK_ID}:raw (image tag)"
echo "result    : $FWDIR/result.json image/container fields updated"
echo "guest ip  : $IP"
echo "one-click : docker run -d --init --privileged --device /dev/kvm -v /dev:/dev --restart unless-stopped $IMAGE"
echo "lab mode  : docker run -d --init --privileged --device /dev/kvm -v /dev:/dev --entrypoint /usr/local/bin/emu-shell $IMAGE"
echo "             then: docker exec -it <ctr> emu run   (or debug / boot / analyze / debug-analyze)"
echo "derive    : same as lab mode, plus the not-baked assets copied in:"
echo "             docker cp scripts/taint/poc-run.sh <ctr>:/usr/local/bin/poc-run"
echo "             docker cp <host-decompiled-rootfs>/. <ctr>:/home/decompiled-rootfs/"
echo "             pocs -> /work/poc | grading evidence -> /work/poc-runs (--out-root)"
exit 0
