#!/bin/bash
# agent-scan :: taint — verify container: re-grade ONE unit's archive
#
# Usage: verify-run.sh [--mode M] [--boot-timeout S] [--keep] <model-dir> <unit-name>
#
#   <model-dir>     data/firmware/<vendor>/<model> (solved image present)
#   <unit-name>     taint-work-output/functions/<unit> whose archive under
#                   hunt-output/functions/<unit>/pocs/ is to be re-graded
#   --mode          emulation mode for every poc boot (default: debug —
#                   backdoor canary-file CI + crash-line BOF + liveness
#                   all grade there; the analyze audit hook crashed on the
#                   ARM engines, so debug-analyze is NOT a safe default)
#   --boot-timeout  seconds to wait for a freshly booted emulation to
#                   answer HTTP before the poc run is recorded
#                   boot_failed / rc3-inconclusive-equivalent (default 300)
#   --keep          leave the last verify container running afterwards
#
# The scoring path of Phase-2: NO LLM anywhere. One container per unit,
# but ONE FRESH CONTAINER PER POC (docker rm + re-run from the solved
# image): the grading protocol demands a factory-state boot per poc, and
# a destructive poc poisons the container's raw in place (AC15 lesson) —
# recreating is the only reliable reset, and it is cheap because the 519M
# of image layers are shared; only the writable layer is new.
#
# Per poc: recreate container -> stage CURRENT poc-run.sh + emu.sh + poc
# -> emu <mode> -> wait for serving -> poc-run --out-root /work/poc-runs/N
# -> harvest rc + full report to
#   hunt-output/functions/<unit>/verify/{result.json,evidence/}
# Verdicts mirror the rc contract: 0 TRIGGERED / 1 not_triggered /
# 2 service_down / 3 inconclusive / 4 poc_error / -1 boot_failed.
# Archive files outside [A-Za-z0-9._@+-]*.py|c violate the contract and
# are listed in result.json but never executed.
#
# Exit: 0 always on a completed pass (inconclusive verdicts are verdicts;
# the pass verdict for the unit is result.json — not this exit code).
set -euo pipefail

MODE="debug"; BOOT_TIMEOUT=300; KEEP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: verify-run.sh [--mode M] [--boot-timeout S] <model-dir> <unit-name>}"
UNIT="${2:?usage: verify-run.sh [--mode M] [--boot-timeout S] <model-dir> <unit-name>}"
MODEL="$(cd "$MODEL" 2>/dev/null && pwd)" || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"

UNITOUT="$MODEL/hunt-output/functions/$UNIT"
POCSDIR="$UNITOUT/pocs"
[ -d "$POCSDIR" ] || { echo "[-] no archive dir: $POCSDIR (run hunt-run.sh first)" >&2; exit 1; }
VOUT="$UNITOUT/verify"

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' \
          | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "[-] no solved image: $IMAGE" >&2; exit 1; }

CSLUG=$(printf '%s-%s' "$TASK_ID" "$UNIT" | tr '_' '-')
[ "${#CSLUG}" -gt 80 ] && CSLUG="${CSLUG:0:70}-$(printf '%s' "$UNIT" | md5sum | cut -c1-8)"
CONTAINER="verify-$CSLUG"

SAFE_RE='^[A-Za-z0-9._@+-]+\.(py|c)$'
mapfile -t POC_LIST < <(cd "$POCSDIR" && find . -maxdepth 1 -type f \( -name '*.py' -o -name '*.c' \) -printf '%f\n' | grep -E "$SAFE_RE" | sort)
mapfile -t JUNK_LIST < <(cd "$POCSDIR" && find . -maxdepth 1 -type f -printf '%f\n' | grep -vE "$SAFE_RE" | sort)

rm -rf "$VOUT"; mkdir -p "$VOUT/evidence"
RESULTS="$VOUT/poc-results.jsonl"; : > "$RESULTS"
printf '%s\n' "${JUNK_LIST[@]}" 2>/dev/null | grep -v '^$' > "$VOUT/violations.txt" || : > "$VOUT/violations.txt"
V_START=$(date +%s)

write_final_result() {   # python assembles result.json from the harvest files
    python3 - "$VOUT/result.json" "$RESULTS" "$VOUT/violations.txt" \
              "$TASK_ID" "$UNIT" "$IMAGE" "$MODE" "$V_START" <<'EOF'
import json, sys, collections, datetime, os
p, results, junk, task, unit, image, mode, start = sys.argv[1:9]
pocs = [json.loads(l) for l in open(results) if l.strip()]
counts = collections.Counter(x["verdict"] for x in pocs)
viol = [x for x in open(junk).read().splitlines() if x.strip()]
infra = sum(1 for x in pocs if x["rc"] == -1)
json.dump({
    "task": task, "unit": unit, "image": image, "mode": mode,
    "status": "success" if infra == 0 else "partial_infra",
    "started_at": datetime.datetime.fromtimestamp(int(start)).astimezone().isoformat(timespec="seconds"),
    "finished_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "grade": "one fresh container+boot per poc; deterministic replay by the CURRENT poc-run.sh only",
    "pocs": pocs, "counts": dict(counts), "contract_violations": viol,
}, open(p, "w"), indent=2, ensure_ascii=False)
print(f"[verify-run] summary: {dict(counts)} violations={len(viol)}")
EOF
}

if [ "${#POC_LIST[@]}" = 0 ]; then
    # empty archive: still record the verify verdict — this file is the
    # batch layer's resume marker and the unit's "graded clean" claim
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    write_final_result
    echo "[verify-run] $UNIT: archive empty — nothing to grade"
    exit 0
fi

SHIM_OK=0
boot_container() {   # fresh writable layer = factory raw state
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
        --entrypoint /usr/local/bin/emu-shell \
        --name "$CONTAINER" "$IMAGE" >/dev/null || return 1
    for _ in $(seq 1 30); do docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 && break; sleep 1; done
    docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 || return 1
    if [ "$SHIM_OK" = 0 ]; then
        docker cp "$ROOT/scripts/rehost/loop-shim/losetup.sh" "$CONTAINER:/usr/local/sbin/losetup" 2>/dev/null \
         && docker cp "$ROOT/scripts/rehost/loop-shim/kpartx.sh" "$CONTAINER:/usr/local/sbin/kpartx" 2>/dev/null \
         && docker exec "$CONTAINER" chmod +x /usr/local/sbin/losetup /usr/local/sbin/kpartx 2>/dev/null \
         && SHIM_OK=1 || true   # no shim: still correct, boots serialize on host loop only when contended
    fi
    return 0
}

echo "[verify-run] $UNIT: ${#POC_LIST[@]} poc(s), one fresh boot each, mode=$MODE"
IDX=0
for poc in "${POC_LIST[@]}"; do
    IDX=$((IDX + 1))
    RC=-1; NOTE=""
    EVDIR="$VOUT/evidence/$IDX-$poc"
    if boot_container; then
        docker exec "$CONTAINER" mkdir -p /work/poc /work/poc-runs
        docker cp "$SCRIPTS/poc-run.sh" "$CONTAINER:/usr/local/bin/poc-run"
        docker cp "$ROOT/scripts/rehost/emu.sh" "$CONTAINER:/usr/local/bin/emu"
        docker exec "$CONTAINER" chmod +x /usr/local/bin/poc-run /usr/local/bin/emu
        docker cp "$POCSDIR/$poc" "$CONTAINER:/work/poc/$poc"
        docker exec "$CONTAINER" emu "$MODE" >/dev/null 2>&1 || NOTE="emu-boot-cmd-failed"
        # wait until something answers HTTP; poc-run's own baseline gate
        # keeps the final say — this loop only removes boot latency
        DEADLINE=$(( $(date +%s) + BOOT_TIMEOUT ))
        CODE=000
        while :; do
            CODE=$(docker exec "$CONTAINER" bash -c '
                IP=$( { cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null; } | head -1)
                if [ -n "$IP" ]; then curl -s -m 3 -o /dev/null -w "%{http_code}" "http://$IP/" 2>/dev/null; else echo 000; fi' 2>/dev/null) || CODE=000
            [ -z "$CODE" ] && CODE=000
            [ "$CODE" != "000" ] && break
            [ "$(date +%s)" -ge "$DEADLINE" ] && break
            sleep 5
        done
        if [ "$CODE" != "000" ]; then
            set +e
            docker exec "$CONTAINER" bash -c "poc-run \"/work/poc/$poc\" --out-root /work/poc-runs/$IDX"
            RC=$?
            set -e
            mkdir -p "$EVDIR"
            docker cp "$CONTAINER:/work/poc-runs/$IDX/." "$EVDIR/" 2>/dev/null || NOTE="evidence-copy-failed"
        else
            NOTE="no HTTP answer within ${BOOT_TIMEOUT}s after emu $MODE"
        fi
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    else
        NOTE="container boot failed (infra)"
    fi
    case $RC in
        0) VERDICT=TRIGGERED ;;
        1) VERDICT=not_triggered ;;
        2) VERDICT=service_down ;;
        3) VERDICT=inconclusive ;;
        4) VERDICT=poc_error ;;
        *) VERDICT=boot_failed ;;
    esac
    python3 - "$poc" "$RC" "$VERDICT" "$IDX" "$NOTE" "$RESULTS" <<'EOF'
import json, sys
poc, rc, verdict, idx, note, res = sys.argv[1:7]
with open(res, "a") as f:
    f.write(json.dumps({"poc": poc, "rc": int(rc), "verdict": verdict,
                        "evidence": f"evidence/{idx}-{poc}/", "note": note or None}) + "\n")
EOF
    echo "[verify-run]   $poc -> rc=$RC $VERDICT ${NOTE:+($NOTE)}"
done
[ -n "$KEEP" ] || docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

write_final_result
echo "[verify-run] result: $VOUT/result.json"
[ -z "$KEEP" ] || echo "[verify-run] container kept: $CONTAINER"
exit 0
