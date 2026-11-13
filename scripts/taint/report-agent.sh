#!/bin/bash
# agent-scan :: taint — round vault: archive ONE graded hit, then a static
#                 report agent writes its English vulnerability report
#
# Usage: report-agent.sh [--timeout S] [--mode M] [--effort E]
#                        [--snapshot-only|--render-only]
#                        <model-dir> <unit> <poc-file> <rc> <evidence-dir>
#
#   <model-dir>      data/firmware/<vendor>/<model>
#   <unit>           hunt-output/functions/<unit> the poc came from (ledger
#                    metadata only — the vault layout is FLAT per model)
#   <poc-file>       the poc source (host path, usually in hunt-output)
#   <rc>             the graded rc — only 0 TRIGGERED / 2 service_down are
#                    accepted: the vault holds hits, nothing else
#   <evidence-dir>   harvested poc-run evidence dir (contains one
#                    poc-<name>-<ts>-<id>/ run dir incl. report.json)
#   --timeout        report-agent wall budget in seconds (default 2400)
#   --mode           grading boot mode recorded in meta.json (default debug)
#   --effort         claude --effort for the report agent (default high —
#                    documentation + novelty search, not hunting; the
#                    gateway accepts low|high|max)
#   --snapshot-only  archive poc+evidence+meta and SKIP the LLM agent
#   --render-only    also render the prompt, then stop (plumbing checks)
#
# The vault (data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/) is an
# APPEND-ONLY record of every deterministic-graded hit, immune to hunt or
# verify re-runs overwriting hunt-output. Entry naming: the poc stem +
# the grading timestamp from report.json ("ts") — every graded run gets a
# unique name by construction; unit and handler live in meta.json, not in
# the path.
#   poc.<ext>       copy of the verified proof-of-concept
#   evidence/       full grader output of the archived run
#   meta.json       verdict, class, marker, hashes, provenance, novelty
#   REPORT.md       English vulnerability report — prose only (the agent
#                   writes REPORT.md + AUDIT.json, nothing else). It is
#                   STATIC-only: the rc is final
#                   (dynamic verification already happened by the
#                   deterministic grader), so the agent boots nothing and
#                   sends no traffic to the target; it may use WebSearch/
#                   WebFetch against public advisory sources for the
#                   binary novelty verdict (0-DAY / N-DAY; failing to
#                   demonstrate an N-Day match IS 0-day — benchmark
#                   policy; audited via checked_at + the queries list)
#   AUDIT.json      the JUDGMENT ledger — the AGENT writes it directly
#                   (schema in report-prompt.md: attribution /
#                   threat_model / artifact_check / novelty; the
#                   REPORT.md HTML-comment footers are GONE), and the
#                   script EXTENDS the same file with two things the
#                   agent may NOT assert: `finality` (read straight
#                   from the grader's report.json — new crash line /
#                   canary = CLOSED) and `confidence` — the overall
#                   3-tier verdict high|medium|low DERIVED from
#                   finality x attribution x threat_model x
#                   artifact_check (high = CLOSED+TOKEN+pure remote+
#                   no artifact doubt; low = guest-side, non-remote,
#                   artifact doubt or finality CHECK; else medium).
#                   BENCHMARK POLICY: confidence grades the ATTRIBUTION
#                   CHAIN, never the reality of the finding — every
#                   tier in the vault is a deterministic hit (rc0/rc2);
#                   high and medium are equally real vulnerabilities.
#                   A cited CVE ID is flagged citation_verified:false +
#                   cve_needs_verification for the driver to confirm —
#                   an agent-cited ID nobody verified is a known
#                   hallucination vector (see CVE-2024-35793, 2026-11-13)
#   AUDIT.driver.json (optional) driver-side verified audit; never
#                   touched by this script
#   .agent-run/     rendered prompt + agent log (diagnostics, append-only)
#
# Identity: an entry whose meta.poc_sha256 matches the given poc is
# REUSED wherever it lives in the model vault — evidence refreshed,
# REPORT.md never overwritten (present: the agent is skipped; absent: it
# retries). A changed poc hash can never touch an existing entry; it
# creates a new timestamped sibling. index.json (the model ledger, incl.
# novelty/cve) is rebuilt from every entry's meta.json at each pass.
#
# Exit: 0 = entry exists (reported / reused / snapshot-only), the LAST
# stdout line is then the repo-relative vault path; 3 = no evidence (no
# report.json found) — nothing created; 1 = usage/refusal/report-agent
# failure (the snapshot is kept; the next verify pass retries the agent).
set -euo pipefail

TIMEOUT=2400; MODE="debug"; SNAPSHOT_ONLY=""; RENDER_ONLY=""; EFFORT="high"
while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --effort) EFFORT="$2"; shift 2 ;;
        --snapshot-only) SNAPSHOT_ONLY=1; shift ;;
        --render-only) SNAPSHOT_ONLY=1; RENDER_ONLY=1; shift ;;
        -h|--help) awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,"");print}' "$0"; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: report-agent.sh <model-dir> <unit> <poc-file> <rc> <evidence-dir>}"
UNIT="${2:?}"; POCFILE="${3:?}"; RC="${4:?}"; EVDIR="${5:?}"
[ -d "$MODEL" ] || { echo "[-] no such dir: $MODEL" >&2; exit 1; }
MODEL="$(cd "$MODEL" && pwd)"
POCFILE="$(cd "$(dirname "$POCFILE")" && pwd)/$(basename "$POCFILE")"
[ -f "$POCFILE" ] || { echo "[-] poc missing: $POCFILE" >&2; exit 1; }
EVDIR="$(cd "$EVDIR" 2>/dev/null && pwd)" || { echo "[-] no evidence dir: $EVDIR" >&2; exit 3; }
[ "$RC" = 0 ] || [ "$RC" = 2 ] || { echo "[-] rc=$RC is not a hit — vault holds TRIGGERED/service_down only" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"
ENV_FILE="$ROOT/.env"
[ -f "$ENV_FILE" ] || { echo "[-] missing $ENV_FILE (agent credentials)" >&2; exit 1; }

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
VAULT="$ROOT/data/round/$VENDOR/$MODELNAME"

POCNAME=$(basename "$POCFILE")
STEM="${POCNAME%.*}"
EXT="${POCNAME##*.}"

# decisive grader artifact — without it there is nothing to archive
# (newest wins if the harvest dir somehow holds several run dirs)
RJSON=$(find "$EVDIR" -name report.json -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
if [ -z "$RJSON" ]; then
    echo "[-] no report.json under $EVDIR — nothing archived" >&2
    exit 3
fi
GRADE_TS=$(python3 -c "import json,re;print(re.sub(r'[^0-9A-Za-z._-]','',str(json.load(open('$RJSON')).get('ts',''))) or 'graded-unknown')" 2>/dev/null || echo "graded-unknown")

POC_SHA=$(sha256sum "$POCFILE" | cut -d' ' -f1)

# ---- entry selection: sha reuse anywhere, else append-only ts name ------
ENTRY=""; REUSE=""
MATCH=$(python3 - "$VAULT" "$POC_SHA" <<'EOF'
import json, glob, os, sys
vault, sha = sys.argv[1:3]
for mp in sorted(glob.glob(os.path.join(vault, "*", "meta.json"))):
    try: m = json.load(open(mp))
    except Exception: continue
    if m.get("poc_sha256") == sha:
        print(os.path.dirname(mp)); break
EOF
)
if [ -n "$MATCH" ]; then
    ENTRY="$MATCH"; REUSE=1
else
    name="$STEM-$GRADE_TS"
    i=2
    while [ -f "$VAULT/$name/meta.json" ]; do   # same name, DIFFERENT poc (edge): bump
        name="$STEM-$GRADE_TS-$i"; i=$((i + 1))
    done
    ENTRY="$VAULT/$name"
fi

extend_audit() {   # inject the two machine facts the agent may NOT
    # assert — deterministic finality + derived 3-tier confidence —
    # into the agent's AUDIT.json and mirror judgments into meta.json.
    # IDEMPOTENT: safe to re-run; repairs entries whose agent died
    # between writing AUDIT.json and this finalization step.
    python3 - "$ENTRY" <<'PYEOF' || true
import json, sys, os, glob, datetime
entry = sys.argv[1]
mp = os.path.join(entry, "meta.json")
m = json.load(open(mp))
ap = os.path.join(entry, "AUDIT.json")
aud = None
if os.path.exists(ap):
    try:
        aud = json.load(open(ap))
    except Exception:
        aud = None
if not isinstance(aud, dict):
    m["novelty"] = "missing"; m["confidence"] = None; m["attribution"] = None
    json.dump(m, open(mp, "w"), indent=2, ensure_ascii=False)
    print("[report-agent] WARN: REPORT.md written but AUDIT.json "
          "missing/invalid — no judgments merged (next pass retries)", file=sys.stderr)
    sys.exit(0)

def sub(name):
    d = aud.get(name)
    return d if isinstance(d, dict) else {}
attr, tm, art, nov = sub("attribution"), sub("threat_model"), sub("artifact_check"), sub("novelty")

def finality_of():
    fin = m.get("finality")
    if isinstance(fin, dict) and "grade" in fin:
        return fin
    # meta predates finality injection — recompute from the evidence
    fin = {"grade": "UNKNOWN", "basis": "no meta.finality; evidence report.json unreadable"}
    rps = sorted(glob.glob(os.path.join(entry, "evidence", "*", "report.json")),
                 key=os.path.getmtime)
    if rps:
        try:
            v = json.load(open(rps[-1])).get("verdict", {})
            fresh = [c for c in v.get("crashes", []) if not c.get("pre_existing")]
            res = v.get("result", "")
            fin = {
                "grade": "CLOSED" if ((res == "triggered" and (fresh or v.get("ci")))
                                      or (res == "service_down" and v.get("service_down"))) else "CHECK",
                "basis": {"result": res, "crash_lines_new": len(fresh), "ci": v.get("ci"),
                          "bof": v.get("bof"), "service_down": v.get("service_down"),
                          "marker": v.get("marker")},
            }
        except Exception:
            pass
    return fin

fin = finality_of()
# overall confidence: DERIVED, never agent-asserted — the rubric in
# report-prompt.md / the script header
ok = (art.get("emulation_artifact") == "no"
      and tm.get("remote_http_only") is True
      and fin.get("grade") == "CLOSED")
if not ok:
    conf = "low"
elif attr.get("grade") == "TOKEN" and attr.get("marker_in_registers") is True:
    conf = "high"
else:
    conf = "medium"

if nov.get("cve"):
    nov["citation_verified"] = False   # until a driver search confirms the ID
aud["finality"] = fin
aud["confidence"] = {"level": conf,
                     "derived_from": "finality(script) x attribution x threat_model x artifact_check"}
aud["extended_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
json.dump(aud, open(ap, "w"), indent=2, ensure_ascii=False)

m["novelty"] = nov.get("status") or "missing"
m["cve"] = nov.get("cve")
m["confidence"] = conf
m["attribution"] = attr.get("grade")
m["finality"] = fin
m["cve_needs_verification"] = bool(nov.get("cve"))   # agent-cited ID: driver must confirm it
json.dump(m, open(mp, "w"), indent=2, ensure_ascii=False)
print(f"[report-agent] audit merged: confidence={conf} novelty={m['novelty']} "
      f"cve={m['cve']} finality={fin.get('grade')} attribution={attr.get('grade')} "
      f"remote={tm.get('remote_http_only')} artifact={art.get('emulation_artifact')}",
      file=sys.stderr)
PYEOF
}

# a reused entry that already has BOTH agent outputs needs no agent —
# BUT an AUDIT.json without the script extensions means a previous run
# died between the agent's write and finalization: repair by re-running
# extend_audit ONLY (no agent spend, REPORT.md untouched)
if [ -n "$REUSE" ] && [ -s "$ENTRY/REPORT.md" ] && [ -s "$ENTRY/AUDIT.json" ]; then
    if ! python3 -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if isinstance(d.get('confidence'),dict) else 1)" "$ENTRY/AUDIT.json" 2>/dev/null; then
        echo "[report-agent] REUSE: AUDIT.json lacks finality/confidence — repairing (finalize only, no agent)" >&2
        extend_audit
    fi
    rebuild_index() {
        python3 - "$VAULT" >/dev/null <<'EOF'
import json, sys, os, glob, datetime
vault = sys.argv[1]
hits = []
for mp in sorted(glob.glob(os.path.join(vault, "*", "meta.json"))):
    try: m = json.load(open(mp))
    except Exception: continue
    hits.append({
        "unit": m.get("unit"), "poc": m.get("poc"), "class": m.get("vuln_class"),
        "rc": m.get("rc"), "marker": m.get("marker"), "verdict": m.get("verdict"),
        "novelty": m.get("novelty"), "cve": m.get("cve"),
        "cve_unverified": bool(m.get("cve_needs_verification")),
        "confidence": m.get("confidence"), "attribution": m.get("attribution"),
        "report": m.get("report"), "graded_at": m.get("graded_at"),
        "audit": os.path.exists(os.path.join(os.path.dirname(mp), "AUDIT.json")),
        "audit_driver": os.path.exists(os.path.join(os.path.dirname(mp), "AUDIT.driver.json")),
        "path": os.path.basename(os.path.dirname(mp)),
    })
tmp = os.path.join(vault, ".index.tmp")
json.dump({"generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
           "hits": hits, "count": len(hits)},
          open(tmp, "w"), indent=2, ensure_ascii=False)
os.replace(tmp, os.path.join(vault, "index.json"))
EOF
    }
    rebuild_index
    echo "[report-agent] hit already reported (same poc hash): $ENTRY/REPORT.md" >&2
    echo "${ENTRY#"$ROOT"/}"
    exit 0
fi

# ---- snapshot: poc + full evidence, then meta.json -----------------------
mkdir -p "$ENTRY/evidence" "$ENTRY/.agent-run"
cp -f "$POCFILE" "$ENTRY/poc.$EXT"
rm -rf "$ENTRY/evidence.new"; mkdir -p "$ENTRY/evidence.new"
cp -a "$EVDIR/." "$ENTRY/evidence.new/"
rm -rf "$ENTRY/evidence"
mv "$ENTRY/evidence.new" "$ENTRY/evidence"
# relative-to-the-snapshot, not to the original harvest dir
RJSON_REL=$(cd "$ENTRY/evidence" && find . -name report.json -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
RJSON_REL="evidence${RJSON_REL#.}"
EV_REL=$(dirname "$RJSON_REL")

python3 - "$ENTRY/meta.json" "$MODEL" "$VENDOR" "$MODELNAME" "$UNIT" "$POCNAME" \
          "$POC_SHA" "$RC" "$MODE" "$RJSON" "$EVDIR" <<'EOF'
import json, sys, os, datetime
meta_p, model, vendor, modelname, unit, pocname, sha, rc, mode, rjson, evdir = sys.argv[1:12]
r = json.load(open(rjson))
v = r.get("verdict", {})
fresh = [c for c in v.get("crashes", []) if not c.get("pre_existing")]
res = v.get("result", "")
# deterministic finality: what MAKES this verdict closed, from the
# grader artifact itself — machine fact, never agent opinion
fin = {
    "grade": "CLOSED" if ((res == "triggered" and (fresh or v.get("ci")))
                          or (res == "service_down" and v.get("service_down"))) else "CHECK",
    "basis": {"result": res, "crash_lines_new": len(fresh), "ci": v.get("ci"),
              "bof": v.get("bof"), "service_down": v.get("service_down"),
              "marker": v.get("marker")},
}
cls = []
if v.get("ci"): cls.append("command_injection")
if v.get("bof"): cls.append("stack_overflow")
if v.get("service_down") or int(rc) == 2: cls.append("denial_of_service")
task = {}
try: task = json.load(open(os.path.join(model, "task.json")))
except Exception: pass
json.dump({
    "schema": "round/1",
    "vendor": vendor, "model": modelname, "unit": unit, "poc": pocname,
    "poc_sha256": sha,
    "rc": int(rc), "verdict": v.get("result", ""), "vuln_class": "+".join(cls) or "unknown",
    "marker": v.get("marker", ""), "mode": mode,
    "grader_detail": v.get("detail", ""),
    "crash_events": (r.get("serial_evidence") or {}).get("crash_events"),
    "finality": fin,
    "boot": r.get("boot", {}), "poc_run": r.get("poc", {}),
    "firmware_file": task.get("firmware", ""), "brand": task.get("brand", ""),
    "graded_at": r.get("ts", ""),
    "archived_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "source": {"model_dir": model, "hunt_poc": os.path.join(model, "hunt-output/functions", unit, "pocs", pocname),
               "evidence_origin": evdir, "report_json": rjson},
    "report": "pending", "novelty": None, "cve": None,
    "confidence": None, "attribution": None,
}, open(meta_p, "w"), indent=2, ensure_ascii=False)
print(f"[report-agent] meta: {'+'.join(cls) or 'unknown'} marker={v.get('marker','')}", file=sys.stderr)
EOF

set_status() {   # $1 = meta.report value
    python3 - "$ENTRY/meta.json" "$1" <<'EOF'
import json, sys, datetime
m = json.load(open(sys.argv[1])); m["report"] = sys.argv[2]
m["report_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
json.dump(m, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
EOF
}

rebuild_index() {
    python3 - "$VAULT" >/dev/null <<'EOF'
import json, sys, os, glob, datetime
vault = sys.argv[1]
hits = []
for mp in sorted(glob.glob(os.path.join(vault, "*", "meta.json"))):
    try: m = json.load(open(mp))
    except Exception: continue
    hits.append({
        "unit": m.get("unit"), "poc": m.get("poc"), "class": m.get("vuln_class"),
        "rc": m.get("rc"), "marker": m.get("marker"), "verdict": m.get("verdict"),
        "novelty": m.get("novelty"), "cve": m.get("cve"),
        "cve_unverified": bool(m.get("cve_needs_verification")),
        "confidence": m.get("confidence"), "attribution": m.get("attribution"),
        "report": m.get("report"), "graded_at": m.get("graded_at"),
        "audit": os.path.exists(os.path.join(os.path.dirname(mp), "AUDIT.json")),
        "audit_driver": os.path.exists(os.path.join(os.path.dirname(mp), "AUDIT.driver.json")),
        "path": os.path.basename(os.path.dirname(mp)),
    })
tmp = os.path.join(vault, ".index.tmp")
json.dump({"generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
           "hits": hits, "count": len(hits)},
          open(tmp, "w"), indent=2, ensure_ascii=False)
os.replace(tmp, os.path.join(vault, "index.json"))
EOF
}

# ---- the static report agent (host-side claude, no emulation anywhere) --
if [ -n "$SNAPSHOT_ONLY" ] && [ -z "$RENDER_ONLY" ]; then
    set_status "snapshot-only"
    rebuild_index
    echo "[report-agent] snapshot-only — agent skipped" >&2
    echo "${ENTRY#"$ROOT"/}"
    exit 0
fi

sed -e "s|{{VENDOR}}|$VENDOR|g" -e "s|{{MODELNAME}}|$MODELNAME|g" \
    -e "s|{{UNIT}}|$UNIT|g" -e "s|{{POCNAME}}|$POCNAME|g" \
    -e "s|{{RC}}|$RC|g" -e "s|{{MODE}}|$MODE|g" -e "s|{{MARKER}}|$(python3 -c "import json;print(json.load(open('$ENTRY/meta.json')).get('marker',''))")|g" \
    -e "s|{{CLASS}}|$(python3 -c "import json;print(json.load(open('$ENTRY/meta.json')).get('vuln_class',''))")|g" \
    -e "s|{{VERDICT}}|$(python3 -c "import json;print(json.load(open('$ENTRY/meta.json')).get('verdict','') or 'triggered')")|g" \
    "$SCRIPTS/report-prompt.md" > "$ENTRY/.agent-run/prompt.rendered.md"
python3 - "$ENTRY" "$MODEL" "$EV_REL" "$RJSON_REL" "$POCNAME" "$EXT" <<'EOF'
import json, sys, re
entry, model, ev_rel, rjson_rel, pocname, ext = sys.argv[1:7]
m = json.load(open(entry + "/meta.json"))
det = re.sub(r"\s+", " ", m.get("grader_detail", ""))[:200]
tok = {
    "DETAIL": det,
    "MODEL": model,
    "ENTRY": entry,
    "POC_REL": f"poc.{ext}",
    "EVIDENCE_REL": ev_rel + "/",
    "REPORT_REL": rjson_rel,
    "FIRMWARE": m.get("firmware_file", ""),
    "BRAND": m.get("brand", ""),
}
p = entry + "/.agent-run/prompt.rendered.md"
s = open(p).read()
for k, v in tok.items():
    s = s.replace("{{" + k + "}}", v)
open(p, "w").write(s)
EOF
if [ -n "$RENDER_ONLY" ]; then
    set_status "snapshot-only"
    rebuild_index
    echo "[report-agent] render-only — prompt: $ENTRY/.agent-run/prompt.rendered.md" >&2
    echo "${ENTRY#"$ROOT"/}"
    exit 0
fi

echo "[report-agent] launching static report agent (timeout ${TIMEOUT}s, effort ${EFFORT}, cwd $ENTRY)" >&2
RUN_START=$(date +%s)
set +e
(
    set -a; . "$ENV_FILE"; set +a
    cd "$ENTRY"
    env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH \
        -u CLAUDE_CODE_MESSAGING_SOCKET -u CLAUDE_CODE_MESSAGING_TOKEN \
        -u CLAUDE_CODE_SESSION_ID -u CLAUDE_CODE_SESSION_ATTENDED \
        -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_PID -u CLAUDE_EFFORT -u AI_AGENT \
        IS_SANDBOX=1 \
        bash -c '
set -u
TO="$2"
MARKER="$3"
EFF="$4"
rm -f "$MARKER"
START=$(date +%s)
setsid claude -p "$(cat "$1")" --effort "$EFF" --dangerously-skip-permissions &
PID=$!
(   # watchdog: TERM then KILL the whole group; marker file records the verdict
    while kill -0 "$PID" 2>/dev/null; do
        sleep 5
        if [ $(( $(date +%s) - START )) -ge "$TO" ]; then
            touch "$MARKER"
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
[ -f "$MARKER" ] && exit 124 || exit "$RC"
' _ "$ENTRY/.agent-run/prompt.rendered.md" "$TIMEOUT" "$ENTRY/.agent-run/.timed-out" "$EFFORT"
) 2>&1 | tee -a "$ENTRY/.agent-run/agent.log"
AGENT_RC=${PIPESTATUS[0]}
set -e
DUR=$(( $(date +%s) - RUN_START ))

if [ -s "$ENTRY/REPORT.md" ]; then
    # AUDIT.json is the AGENT'S judgment file (no REPORT.md footers
    # anymore); finalize injects the machine facts + mirrors meta.json.
    extend_audit
    set_status "written"
    echo "[report-agent] REPORT.md + AUDIT.json written (${DUR}s, agent rc=$AGENT_RC)" >&2
else
    set_status "agent-failed:rc$AGENT_RC"
    echo "[report-agent] WARN: no REPORT.md after agent (rc=$AGENT_RC, ${DUR}s) — snapshot kept, retry is automatic on the next verify pass" >&2
fi
rebuild_index
echo "${ENTRY#"$ROOT"/}"
[ -s "$ENTRY/REPORT.md" ]
