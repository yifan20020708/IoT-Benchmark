#!/bin/bash
# agent-scan :: taint — verify container: re-grade ONE unit's archive
#
# Usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] [--keep]
#                      [--no-report] [--report-timeout S] <model-dir> <unit-name>
#
#   <model-dir>     data/firmware/<vendor>/<model> (solved image present)
#   <unit-name>     taint-work-output/functions/<unit> whose archive under
#                   hunt-output/functions/<unit>/pocs/ is to be re-graded
#   --parallel      concurrent poc jobs (default 4, capped at #pocs).
#                   One poc = one dedicated container = one fresh boot,
#                   exactly as the serial protocol; parallelism only
#                   overlaps the boots. Each TCG QEMU ~1 core; on a
#                   busy host (e.g. this unit runs inside hunt-batch,
#                   which already parallelizes units) pass --parallel 1.
#   --mode          emulation mode for every poc boot (default debug:
#                   THE grading boot — canary-file CI + crash-line BOF
#                   + liveness all live there; treat it as fixed)
#   --boot-timeout  seconds to wait for a freshly booted emulation to
#                   answer HTTP before the poc run is recorded
#                   boot_failed / rc3-inconclusive-equivalent (default 300)
#   --keep          leave ALL per-poc verify containers running afterwards
#                   (the protocol's reset button is each container's
#                   writable layer; with --keep nothing is graded twice in
#                   one container anyway — every job starts its own)
#   --no-report     skip the round-vault step (default ON: every hit —
#                   rc0 TRIGGERED or rc2 service_down — is archived to
#                   data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/ as
#                   poc + full grading evidence + meta.json, and a
#                   STATIC-only report agent (report-agent.sh, effort
#                   high, boots nothing — the rc is already final) writes
#                   the English REPORT.md + the AUDIT.json judgment
#                   ledger (evidence-audit dimensions + binary 0-DAY/N-DAY
#                   novelty verdict; the archiver derives the overall
#                   3-tier confidence from them, never agent-asserted);
#                   the snapshot is inline (fast,
#                   deterministic) but the AGENT RUNS DETACHED — grading
#                   never waits on an LLM; an entry with the same poc
#                   hash is append-only, so re-runs cannot lose hits)
#   --report-timeout report-agent wall budget per hit, seconds (default 2400)
#
# The scoring path of Phase-2: NO LLM anywhere IN THE VERDICT. N container
# jobs at a time, but ONE FRESH CONTAINER PER POC (unique name
# verify-<unit-slug>-<idx>, destroyed after harvest — the writable layer
# is the reset button): the grading protocol demands a factory-state boot
# per poc, and a destructive poc poisons the container's raw in place
# (AC15 lesson). Recreation is cheap because the 519M of image layers are
# shared; only the writable layer is new. The loop shim is installed into
# EVERY container (parallel jobs contend on the kernel-global loop pool;
# scripts/rehost/loop-shim header).
#
# Per poc: new container -> stage CURRENT poc-run.sh + emu.sh + poc
# -> emu <mode> -> wait for serving -> poc-run --out-root /work/poc-runs/N
# -> harvest rc + full report to
#   hunt-output/functions/<unit>/verify/{result.json,evidence/}
#   and, for hits, snapshot + DETACHED report into data/round/ (the
#   "round" field of each poc line is that vault path; note records
#   "report-detached").
# Verdicts mirror the rc contract: 0 TRIGGERED / 1 not_triggered /
# 2 service_down / 3 inconclusive / 4 poc_error / -1 boot_failed.
# Archive files outside [A-Za-z0-9._@+-]*.py|c violate the contract and
# are listed in result.json but never executed.
#
# Exit: 0 always on a completed pass (inconclusive verdicts are verdicts;
# the pass verdict for the unit is result.json — not this exit code).
set -euo pipefail

MODE="debug"; BOOT_TIMEOUT=300; KEEP=""
REPORT_ON=1; REPORT_TIMEOUT=2400; PAR=4
while [ $# -gt 0 ]; do
    case "$1" in
        --parallel) PAR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --report-timeout) REPORT_TIMEOUT="$2"; shift 2 ;;
        --no-report) REPORT_ON=""; shift ;;
        --keep) KEEP=1; shift ;;
        -h|--help) awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,"");print}' "$0"; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] <model-dir> <unit-name>}"
UNIT="${2:?usage: verify-run.sh [--parallel N] [--mode M] [--boot-timeout S] <model-dir> <unit-name>}"
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
    for t in $(docker ps -aq -f "name=^${CONTAINER}-" 2>/dev/null); do
        docker rm -f "$t" >/dev/null 2>&1 || true
    done
    write_final_result
    echo "[verify-run] $UNIT: archive empty — nothing to grade"
    exit 0
fi

boot_container() {   # $1 = container name; fresh writable layer = factory state
    local CTR="$1"
    docker rm -f "$CTR" >/dev/null 2>&1 || true
    docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
        --entrypoint /usr/local/bin/emu-shell \
        --name "$CTR" "$IMAGE" >/dev/null || return 1
    for _ in $(seq 1 30); do docker exec "$CTR" pg_isready -q -h 127.0.0.1 && break; sleep 1; done
    docker exec "$CTR" pg_isready -q -h 127.0.0.1 || return 1
    # loop shim in EVERY container: parallel jobs contend on the
    # kernel-global loop pool, and each container's PATH is its own
    docker cp "$ROOT/scripts/rehost/loop-shim/losetup.sh" "$CTR:/usr/local/sbin/losetup" 2>/dev/null \
     && docker cp "$ROOT/scripts/rehost/loop-shim/kpartx.sh" "$CTR:/usr/local/sbin/kpartx" 2>/dev/null \
     && docker exec "$CTR" chmod +x /usr/local/sbin/losetup /usr/local/sbin/kpartx 2>/dev/null \
     || echo "[verify-run] WARN: loop shim not installed in $CTR (loop mounts may contend)" >&2
    return 0
}

run_poc_job() {   # $1 = idx, $2 = poc — self-contained job, writes its own part file
    local IDX="$1" poc="$2"
    local CTR="$CONTAINER-$IDX"
    local RC=-1 NOTE="" ROUND=""
    local EVDIR="$VOUT/evidence/$IDX-$poc"
    if boot_container "$CTR"; then
        docker exec "$CTR" mkdir -p /work/poc /work/poc-runs
        docker cp "$SCRIPTS/poc-run.sh" "$CTR:/usr/local/bin/poc-run"
        docker cp "$ROOT/scripts/rehost/emu.sh" "$CTR:/usr/local/bin/emu"
        docker exec "$CTR" chmod +x /usr/local/bin/poc-run /usr/local/bin/emu
        docker cp "$POCSDIR/$poc" "$CTR:/work/poc/$poc"
        docker exec "$CTR" emu "$MODE" >/dev/null 2>&1 || NOTE="emu-boot-cmd-failed"
        # wait until something answers HTTP; poc-run's own baseline gate
        # keeps the final say — this loop only removes boot latency
        local DEADLINE CODE=000
        DEADLINE=$(( $(date +%s) + BOOT_TIMEOUT ))
        while :; do
            CODE=$(docker exec "$CTR" bash -c '
                IP=$( { cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null; } | head -1)
                if [ -n "$IP" ]; then curl -s -m 3 -o /dev/null -w "%{http_code}" "http://$IP/" 2>/dev/null; else echo 000; fi' 2>/dev/null) || CODE=000
            [ -z "$CODE" ] && CODE=000
            [ "$CODE" != "000" ] && break
            [ "$(date +%s)" -ge "$DEADLINE" ] && break
            sleep 5
        done
        if [ "$CODE" != "000" ]; then
            set +e
            docker exec "$CTR" bash -c "poc-run \"/work/poc/$poc\" --out-root /work/poc-runs/$IDX"
            RC=$?
            set -e
            mkdir -p "$EVDIR"
            docker cp "$CTR:/work/poc-runs/$IDX/." "$EVDIR/" 2>/dev/null || NOTE="evidence-copy-failed"
        else
            NOTE="no HTTP answer within ${BOOT_TIMEOUT}s after emu $MODE"
        fi
        [ -n "$KEEP" ] || docker rm -f "$CTR" >/dev/null 2>&1 || true
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
    # round vault: the SNAPSHOT is inline (pure file ops + deterministic
    # meta build — milliseconds, and it yields the vault path for the
    # jsonl line). The REPORT AGENT is then detached: grading of the next
    # poc never waits on an LLM. Failures of either never change the rc —
    # the note records them.
    if [ -n "$REPORT_ON" ] && { [ "$RC" = 0 ] || [ "$RC" = 2 ]; }; then
        set +e
        ROUND=$(bash "$SCRIPTS/report-agent.sh" --snapshot-only --mode "$MODE" \
                    "$MODEL" "$UNIT" "$POCSDIR/$poc" "$RC" "$EVDIR" 2>>"$VOUT/report-agent.log" \
                | tail -1)
        RR=${PIPESTATUS[0]}
        set -e
        case "$ROUND" in data/round/*) ;; *) ROUND="" ;; esac
        if [ -n "$ROUND" ]; then
            ( setsid bash "$SCRIPTS/report-agent.sh" --timeout "$REPORT_TIMEOUT" --mode "$MODE" \
                  "$MODEL" "$UNIT" "$POCSDIR/$poc" "$RC" "$EVDIR" \
                  >/dev/null 2>>"$VOUT/report-agent.log" & )
            NOTE="${NOTE:+$NOTE,}report-detached"
        else
            NOTE="${NOTE:+$NOTE,}report-snapshot-rc$RR"
        fi
    fi
    python3 - "$poc" "$RC" "$VERDICT" "$IDX" "$NOTE" "$ROUND" "$VOUT/poc-results.$IDX.part" <<'EOF'
import json, sys
poc, rc, verdict, idx, note, round_, res = sys.argv[1:8]
with open(res, "a") as f:
    f.write(json.dumps({"poc": poc, "rc": int(rc), "verdict": verdict,
                        "evidence": f"evidence/{idx}-{poc}/",
                        "round": round_ or None, "note": note or None}) + "\n")
EOF
    echo "[verify-run]   #$IDX $poc -> rc=$RC $VERDICT${ROUND:+ round=$ROUND} ${NOTE:+($NOTE)}"
}

NJOBS="${#POC_LIST[@]}"
[ "$PAR" -gt "$NJOBS" ] && PAR="$NJOBS"
echo "[verify-run] $UNIT: $NJOBS poc(s), one fresh boot each, parallel=$PAR, mode=$MODE"
IDX=0
for poc in "${POC_LIST[@]}"; do
    IDX=$((IDX + 1))
    while [ "$(jobs -rp | wc -l)" -ge "$PAR" ]; do wait -n; done
    run_poc_job "$IDX" "$poc" &
done
wait

# merge per-job parts in index order — the jsonl stays deterministic
: > "$RESULTS"
for i in $(seq 1 "$NJOBS"); do
    if [ ! -f "$VOUT/poc-results.$i.part" ]; then
        # a job that died before writing its line (crash mid-container-op):
        # never silently drop a poc from the ledger
        python3 - "${POC_LIST[$((i - 1))]}" "$i" "$VOUT/poc-results.$i.part" <<'EOF'
import json, sys
poc, idx, res = sys.argv[1:4]
with open(res, "a") as f:
    f.write(json.dumps({"poc": poc, "rc": -1, "verdict": "boot_failed",
                        "evidence": f"evidence/{idx}-{poc}/",
                        "round": None, "note": "job died before reporting"}))
EOF
    fi
    cat "$VOUT/poc-results.$i.part" >> "$RESULTS"
    rm -f "$VOUT/poc-results.$i.part"
done
if [ -z "$KEEP" ]; then   # belt & braces: a job that died early leaves its container
    for t in $(docker ps -aq -f "name=^${CONTAINER}-" 2>/dev/null); do
        docker rm -f "$t" >/dev/null 2>&1 || true
    done
fi

write_final_result
echo "[verify-run] result: $VOUT/result.json"
[ -z "$KEEP" ] || echo "[verify-run] containers kept: $CONTAINER-1..$NJOBS"
exit 0
