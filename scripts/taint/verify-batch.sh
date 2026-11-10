#!/bin/bash
# agent-scan :: taint — two-phase parallel chunk verification of a full spec
#
# Usage: verify-batch.sh [--budget S] [--chunks N] [--max-parallel K]
#                        [--out F] [--workdir D] <model-dir> <spec.json>
#
# Runs a full-coverage verify-request.sh spec that cannot fit one boot
# (hundreds of armed breakpoints grind the guest's own init path) as
# PARALLEL BOOT CHUNKS. Every rule is mechanical — no firmware knowledge
# here; the agent's spec order is authoritative:
#
#   ROUND 1  chunk-probes.py splits the spec order-preserving with chunk
#            boundaries SNAPPED TO HANDLER GROUPS (probes sharing an
#            entry_break never split — the re-verification is
#            function-granular), replicating the session bootstrap (curl
#            -c jar writer) into every chunk; all chunks run in parallel
#            (semaphore --max-parallel), each in its own container + boot
#            + FRESH canaries
#   ANALYZE  merge-verdicts.py: pass-anywhere merge (value-based canary
#            attribution makes chunks independent proofs) + slow-zone
#            detection from send timings (trailing ~20s+ send gaps = the
#            daemon-wedge signature)
#   ROUND 2  only if pass-EXPECTED probes failed: they re-run in small
#            chunks — victims on clean boots with a fresh bootstrap, each
#            slow-zone suspect ALONE (a wedge probe can only kill its
#            own boot)
#
# Chunk count: --chunks N overrides the spec's optional top-level "chunks"
# hint (agent-specified), else ceil(n/32). Merged verdicts keep the
# single-run schema (spec/all_pass/web_ready/probes) so the driver's
# consumer code is unchanged; merged events.jsonl lands at
# <workdir>/events.jsonl (where taint-run.sh's write-back reads it when
# --workdir .../driver-probes is passed).
# exit 0 = all probes pass, 1 = any fail, 2 = infrastructure error.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # no __pycache__ anywhere in the pipeline

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUDGET=1200      # per-chunk wall budget (boot + web + sends + evidence)
CHUNKS=""        # "" = spec "chunks" hint or ceil(n/32)
MAXP=16          # max concurrent verify-request.sh runs
OUT=""
WORKDIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --budget)       BUDGET="$2"; shift 2 ;;
        --chunks)       CHUNKS="$2"; shift 2 ;;
        --max-parallel) MAXP="$2"; shift 2 ;;
        --out)          OUT="$2"; shift 2 ;;
        --workdir)      WORKDIR="$2"; shift 2 ;;
        -h|--help)      sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: verify-batch.sh [--budget S] [--chunks N] <model-dir> <spec.json>}"
SPEC="${2:?usage: verify-batch.sh [--budget S] [--chunks N] <model-dir> <spec.json>}"
MODEL="$(cd "$MODEL" 2>/dev/null && pwd)" || { echo "[-] no such dir: $1" >&2; exit 2; }
[ -f "$MODEL/task.json" ] || { echo "[-] not a model dir (no task.json): $MODEL" >&2; exit 2; }
[ -f "$SPEC" ] || { echo "[-] no such spec: $SPEC" >&2; exit 2; }
SPEC="$(readlink -f "$SPEC")"
STEM="$(basename "$SPEC" .json)"

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')
docker image inspect "task-$TASK_ID:solved" >/dev/null 2>&1 \
    || { echo "[-] no solved image for this task (run the rehost stage first)" >&2; exit 2; }

WORKDIR="${WORKDIR:-$MODEL/taint-source/verify/$STEM-batch}"
OUT="${OUT:-$WORKDIR/verdicts.json}"
rm -rf "$WORKDIR"    # a batch is atomic: never mix rounds of two runs
mkdir -p "$WORKDIR"

# one batch per (task, spec stem) at a time: the workdir wipe above must
# never race a live batch; DIFFERENT specs/specs of different tasks are free
LOCK=/tmp/agent-scan-verify-batch-$(printf '%s__%s' "$TASK_ID" "$STEM" | tr -c 'a-z0-9._-' '-').lock
exec 9>"$LOCK"
flock -n 9 || { echo "[-] another verify-batch is already running $TASK_ID $STEM" >&2; exit 2; }

# children (verify-request.sh) trap their own EXIT and tear their containers
# down; make sure they RECEIVE that signal if we are interrupted (the
# timeout wrapper forwards TERM to its child)
trap 'trap - EXIT; kill $(jobs -p) 2>/dev/null || true' EXIT

# ---- launch every chunk spec of a round in parallel (semaphore) ---------------
launch_chunks() {   # $1 = round dir; chunks = $1/<STEM>-<round>-chunk-*.json
    local rdir="$1" round cf cd_ log_ launched=0 t0 t1 rc TPID
    round="$(basename "$rdir")"
    for cf in "$rdir"/"$STEM-$round"-chunk-*.json; do
        [ -e "$cf" ] || continue
        while [ "$(jobs -rp | wc -l)" -ge "$MAXP" ]; do
            wait -n || true
        done
        cd_="$rdir/$(basename "$cf" .json)"
        log_="$rdir/$(basename "$cf").log"
        (
            trap 'kill "$TPID" 2>/dev/null' TERM INT
            t0=$(date +%s)
            rc=0
            timeout $((BUDGET + 300)) \
                bash "$SCRIPTS/verify-request.sh" --budget "$BUDGET" \
                    --workdir "$cd_" "$MODEL" "$cf" >"$log_" 2>&1 &
            TPID=$!
            wait "$TPID" || rc=$?
            t1=$(date +%s)
            printf '{"chunk":"%s","start":%s,"end":%s,"rc":%s,"wall":%s}\n' \
                "$(basename "$cd_")" "$t0" "$t1" "$rc" "$((t1 - t0))" \
                >>"$rdir/timeline.jsonl"
        ) &
        launched=$((launched + 1))
    done
    wait || true
    echo "[batch] $round: $launched chunk run(s) finished"
}

shopt -s nullglob

# ---- ROUND 1: mechanical split + parallel boots -------------------------------
mkdir -p "$WORKDIR/r1"
CHUNK_ARGS=()
[ -n "$CHUNKS" ] && CHUNK_ARGS=(--chunks "$CHUNKS")
python3 "$SCRIPTS/chunk-probes.py" --prefix "$STEM-r1" --group-by \
    "${CHUNK_ARGS[@]}" "$SPEC" "$WORKDIR/r1"
launch_chunks "$WORKDIR/r1"

r1_dirs=("$WORKDIR"/r1/"$STEM"-r1-chunk-*/)
[ ${#r1_dirs[@]} -gt 0 ] || { echo "[-] round 1 produced no chunks" >&2; exit 2; }

# ---- ANALYZE: merge + slow-zone detection --------------------------------------
python3 "$SCRIPTS/merge-verdicts.py" "$SPEC" "${r1_dirs[@]}" \
    --out "$OUT" --events "$WORKDIR/events.jsonl" --analysis "$WORKDIR/analysis.json"

web_any=$(python3 -c 'import json,sys; print("true" if json.load(open(sys.argv[1])).get("web_ready") else "false")' "$OUT")
if [ "$web_any" != "true" ]; then
    echo "[-] web service never answered in any chunk (infrastructure failure)" >&2
    exit 2
fi

# ---- ROUND 2 (repair): retry pass-expected failures on clean boots -------------
# verdicts stay expect-blind; the repair POLICY filters by expect here
ROUND2=$(python3 - "$SPEC" "$WORKDIR/analysis.json" "$WORKDIR/r2-spec.json" <<'EOF'
import json, sys
spec_path, analysis_path, r2_path = sys.argv[1:4]
spec = json.load(open(spec_path))
a = json.load(open(analysis_path))
failed = set(a.get("failed") or [])
suspects = set(a.get("suspects") or [])
retry = [p for p in spec["probes"]
         if (p.get("expect") or "pass") == "pass" and p.get("id") in failed]
if not retry:
    print(json.dumps({"round2": False}))
else:
    r2 = dict(spec)
    r2["probes"] = retry
    json.dump(r2, open(r2_path, "w"), indent=2, ensure_ascii=False)
    isol = [p["id"] for p in retry if p["id"] in suspects]
    print(json.dumps({"round2": True, "failed": len(retry),
                      "victims": len(retry) - len(isol), "suspects": isol}))
EOF
)
echo "[batch] repair decision: $ROUND2"
DO_R2=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("round2"))' <<<"$ROUND2")

if [ "$DO_R2" = "True" ]; then
    mkdir -p "$WORKDIR/r2"
    ISOLATE_ARGS=()
    SUS=$(python3 -c 'import json,sys; print(",".join(json.load(sys.stdin).get("suspects") or []))' <<<"$ROUND2")
    [ -n "$SUS" ] && ISOLATE_ARGS=(--isolate "$SUS")
    python3 "$SCRIPTS/chunk-probes.py" --prefix "$STEM-r2" --size 8 --group-by \
        "${ISOLATE_ARGS[@]}" "$WORKDIR/r2-spec.json" "$WORKDIR/r2"
    launch_chunks "$WORKDIR/r2"
fi

# ---- final merge (r1 + r2, pass-if-any) + report -------------------------------
all_dirs=("$WORKDIR"/r1/"$STEM"-r1-chunk-*/ "$WORKDIR"/r2/"$STEM"-r2-chunk-*/)
[ ${#all_dirs[@]} -gt 0 ] || { echo "[-] no chunks to merge" >&2; exit 2; }
python3 "$SCRIPTS/merge-verdicts.py" "$SPEC" "${all_dirs[@]}" \
    --out "$OUT" --events "$WORKDIR/events.jsonl" --analysis "$WORKDIR/analysis.json"

nverdicts=$(find "$WORKDIR" -mindepth 2 -name verdicts.json | wc -l)
if [ "$nverdicts" -eq 0 ]; then
    echo "[-] no chunk produced verdicts (infrastructure failure)" >&2
    exit 2
fi

python3 - "$OUT" "$WORKDIR" <<'EOF'
import json, os, sys
out, wd = sys.argv[1:3]
v = json.load(open(out))
for r in ("r1", "r2"):
    p = os.path.join(wd, r, "timeline.jsonl")
    if not os.path.exists(p):
        continue
    for line in open(p):
        if line.strip():
            t = json.loads(line)
            print(f"[batch] {t['chunk']}: rc={t['rc']} wall={t['wall']}s")
npass = sum(1 for p in v.get("probes", []) if p.get("verdict") == "pass")
print(f"[batch] merged: {npass}/{len(v.get('probes', []))} pass  "
      f"all_pass={v.get('all_pass')} web_ready={v.get('web_ready')}")
EOF
echo "[batch] verdicts -> $OUT   events -> $WORKDIR/events.jsonl"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("all_pass") else 1)' "$OUT"
