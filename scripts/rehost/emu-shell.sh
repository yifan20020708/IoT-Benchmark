#!/bin/bash
# agent-scan :: lab-mode entrypoint for solved images
#
# The default solved-image entrypoint (solved-entrypoint) boots the verified
# emulation unattended. This one is the opt-in counterpart: it readies the
# environment but leaves the firmware STOPPED, so an agent (or a human) can
# drive it explicitly:
#
#   docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
#       --entrypoint /usr/local/bin/emu-shell task-<name>:solved
#   docker exec -it <ctr> emu run          # or: debug | boot | analyze
#   docker exec -it <ctr> emu status | emu serial -f
#
# PostgreSQL must be up before any emu boot (run.sh queries it for the
# filesystem/kernel paths), so it is started here; `emu` retries on its own
# in case it died since. Interactive runs (docker run -it) land in a shell.
set -u

service postgresql start >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
    pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
if pg_isready -q -h 127.0.0.1; then
    echo "[lab] PostgreSQL ready"
else
    echo "[lab] WARN: PostgreSQL not ready — emu will retry on start"
fi
echo "[lab] emulation idle — drive it with: emu run | debug | boot | analyze | status | serial | stop"

if [ -t 0 ]; then
    exec bash
fi
exec sleep infinity
