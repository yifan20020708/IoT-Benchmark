#!/bin/bash
# agent-scan :: stage 1 — agent-driven firmware collection (runs on the host)
#
# Usage: collect-firmware.sh [--timeout <s>] <vendor> <count> <outdir>
#   e.g.: ./scripts/collect-firmware.sh tenda 50 data/firmware/tenda
#
# The collection agent (claude, effort=max, credentials from .env) runs
# DIRECTLY on this host — no container: it discovers the vendor's official
# download sources, fetches the newest firmware per device model, unpacks
# each one to its root filesystem (binwalk via the firmae-base image — the
# same extractor the emulation pipeline uses; models that won't unpack are
# rejected on the spot), and writes <model>/{task.json,rootfs/}.
# Afterwards the driver independently validates every folder (JSON schema +
# firmware + a real rootfs tree) and reports a summary. Idempotent: existing
# model folders are kept and count toward the target.
#
# Finally, as a DETERMINISTIC (non-agent) phase, every valid rootfs is
# mirror-decompiled: scripts/ghidra-batch/decompile-rootfs.sh
#   <model>/rootfs/  ->  <model>/decompiled-rootfs/   (one <function>_<addr>.c
# per function, layout mirrored). Resumable — reruns only touch new binaries.
# Per-ELF Ghidra failures are normal and reported per model, never fatal.
# --no-decompile skips this phase; --jobs N sets its parallelism (default 8).
#
# The agent gets a throwaway CLAUDE_CONFIG_DIR so it cannot inherit this
# project's memory/config (prompt hygiene), and its process group is
# watchdog-killed on timeout (same semantics as agent-run.sh).
#
# Exit 0 = outdir holds at least <count> valid model folders.
set -euo pipefail

TIMEOUT=7200
DJOBS=8
DECOMPILE=1
while [ $# -gt 3 ]; do
    case "$1" in
        --timeout)      TIMEOUT="$2"; shift 2 ;;
        --jobs)         DJOBS="$2"; shift 2 ;;
        --no-decompile) DECOMPILE=0; shift ;;
        *) echo "usage: collect-firmware.sh [--timeout <s>] [--jobs N] [--no-decompile] <vendor> <count> <outdir>" >&2; exit 1 ;;
    esac
done
VENDOR="${1:?usage: collect-firmware.sh [--timeout <s>] <vendor> <count> <outdir>}"
COUNT="${2:?missing count}"
OUTDIR="${3:?missing outdir}"

case "$VENDOR" in ''|*[!a-z0-9-]*) echo "[-] vendor must be [a-z0-9-]: $VENDOR" >&2; exit 1 ;; esac
case "$COUNT" in ''|*[!0-9]*) echo "[-] count must be a positive integer: $COUNT" >&2; exit 1 ;; esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE" >&2; exit 1; }

OUTDIR="$(mkdir -p "$OUTDIR" && cd "$OUTDIR" && pwd)"

# LLM credentials for the claude CLI (unquoted KEY=VALUE lines, bash-sourceable)
set -a; . "$ENV_FILE"; set +a

LOGDIR="$ROOT/logs"; mkdir -p "$LOGDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$LOGDIR/collect-$VENDOR-$STAMP.log"
CONF=$(mktemp -d /tmp/agent-scan-collect.XXXXXX)   # throwaway claude config
PROMPT=$(mktemp)
trap 'rm -rf "$CONF" "$PROMPT"' EXIT

sed -e "s|__OUTDIR__|$OUTDIR|g" -e "s|__VENDOR__|$VENDOR|g" -e "s|__COUNT__|$COUNT|g" \
    "$ROOT/scripts/collect-prompt.md" > "$PROMPT"

BEFORE=$(find "$OUTDIR" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | wc -l)
echo "[*] collect: vendor=$VENDOR target=$COUNT (already have $BEFORE) outdir=$OUTDIR timeout=${TIMEOUT}s"
echo "[*] agent log: $LOG"

# ---------------------------------------------------------------------------
# run the agent on the host under the process-group watchdog
#   - proxy vars stripped: the local proxy is dead, direct works
#   - CLAUDE_CONFIG_DIR=$CONF: fresh CLI state, no inherited project memory
#   - marker file decides timeout vs natural exit (see agent-run.sh)
# ---------------------------------------------------------------------------
set +e
( cd "$OUTDIR" && exec env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u no_proxy -u NO_PROXY \
    CLAUDE_CONFIG_DIR="$CONF" IS_SANDBOX=1 TO="$TIMEOUT" PROMPT_FILE="$PROMPT" \
    bash -c '
set -u
rm -f /tmp/.collect-timed-out
START=$(date +%s)
setsid claude -p "$(cat "$PROMPT_FILE")" \
    --effort max \
    --dangerously-skip-permissions &
PID=$!
(   # watchdog: enforce the budget on the whole process group
    while kill -0 "$PID" 2>/dev/null; do
        sleep 10
        if [ $(( $(date +%s) - START )) -ge "$TO" ]; then
            touch /tmp/.collect-timed-out
            kill -TERM -- "-$PID" 2>/dev/null
            sleep 30
            kill -KILL -- "-$PID" 2>/dev/null
            exit 0
        fi
    done
) &
WD=$!
wait "$PID"; RC=$?
kill "$WD" 2>/dev/null
[ -f /tmp/.collect-timed-out ] && exit 124 || exit "$RC"
' ) 2>&1 | tee "$LOG"
AGENT_RC=${PIPESTATUS[0]}
set -e
rm -f /tmp/.collect-timed-out

# ---------------------------------------------------------------------------
# independent post-validation — never trust the agent's self-report:
# every model folder must hold a schema-valid task.json + the firmware +
# a rootfs tree that actually looks like a root filesystem
# ---------------------------------------------------------------------------
echo "[*] validating $OUTDIR ..."
valid=0
VALID_DIRS=()
for d in "$OUTDIR"/*/; do
    [ -d "$d" ] || continue
    model=$(basename "$d")
    ok=$(python3 - "$d" <<'EOF'
import json, os, sys
d = sys.argv[1]
try:
    t = json.load(open(os.path.join(d, "task.json")))
except Exception:
    print("no-valid-task.json"); sys.exit()
fw = t.get("firmware")
if not fw or not os.path.isfile(os.path.join(d, fw)):
    print("firmware-missing"); sys.exit()
for k in ("brand", "model", "sha256"):
    if not t.get(k):
        print("missing-" + k); sys.exit()
rootfs = t.get("rootfs") or "rootfs"
r = os.path.join(d, rootfs)
if not os.path.isdir(r):
    print("rootfs-missing"); sys.exit()
markers = [m for m in ("bin", "etc", "sbin", "usr", "lib", "www", "htdocs")
           if os.path.isdir(os.path.join(r, m))]
files = sum(len(f) for _, _, f in os.walk(r))
if not markers or files < 20:
    print(f"rootfs-not-a-fs (markers={markers} files={files})"); sys.exit()
print("ok")
EOF
)
    if [ "$ok" = "ok" ]; then
        valid=$((valid + 1))
        VALID_DIRS+=("$d")
    else
        echo "    [!] $model: $ok"
    fi
done
strays=$(find "$OUTDIR" -mindepth 1 -maxdepth 1 ! -type d ! -name '.*' | wc -l)

# ---------------------------------------------------------------------------
# phase 3 — deterministic mirror-decompile of every valid rootfs (no agent):
#   <model>/rootfs/  ->  <model>/decompiled-rootfs/
# Models run sequentially, each with $DJOBS concurrent Ghidra instances;
# decompile-rootfs.sh is resumable, so re-runs only touch new binaries.
# ---------------------------------------------------------------------------
if [ "$DECOMPILE" -eq 1 ] && [ "${#VALID_DIRS[@]}" -gt 0 ]; then
    echo
    echo "[*] decompiling ${#VALID_DIRS[@]} rootfs trees (jobs=$DJOBS, deterministic) ..."
    dc_ok=0
    dc_fail=0
    for d in "${VALID_DIRS[@]}"; do
        model=$(basename "$d")
        if "$ROOT/scripts/ghidra-batch/decompile-rootfs.sh" --jobs "$DJOBS" \
                "$d/rootfs" "$d/decompiled-rootfs" > "$d/.decompile-rootfs.log" 2>&1; then
            dc_ok=$((dc_ok + 1))
            echo "    [dc ok]   $model"
        else
            dc_fail=$((dc_fail + 1))
            echo "    [dc fail] $model (see $model/.decompile-rootfs.log)"
        fi
    done
else
    dc_ok=0
    dc_fail=0
fi

echo
echo "===== collect-firmware: $VENDOR ====="
echo "valid model folders : $valid / $COUNT target"
echo "agent               : rc=$AGENT_RC$([ "$AGENT_RC" = 124 ] && echo ' (timed out)')"
if [ "$DECOMPILE" -eq 1 ]; then
    echo "decompiled rootfs   : $dc_ok ok, $dc_fail failed (per-model failures non-fatal)"
else
    echo "decompiled rootfs   : skipped (--no-decompile)"
fi
echo "log                 : $LOG"
[ "$strays" -gt 0 ] && echo "stray root files    : $strays (not counted, review manually)"
[ "$valid" -ge "$COUNT" ] || exit 1
