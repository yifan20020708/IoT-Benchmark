#!/bin/bash
# agent-scan :: base/task image entrypoint
#
# Starts the baked-in PostgreSQL (user firmadyne, db firmware, schema already
# imported at image build time), waits for it, then hands control to the
# container command. With no command, keeps the container alive as an agent
# workspace (drive it with `docker exec`).
set -e

service postgresql start

# wait for the DB to accept connections
for _ in $(seq 1 60); do
    if pg_isready -q -h 127.0.0.1; then
        break
    fi
    sleep 1
done

if [ "$#" -eq 0 ]; then
    exec sleep infinity
fi

exec "$@"
