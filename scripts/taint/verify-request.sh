#!/bin/bash
# agent-scan :: taint — deterministic dynamic verification framework
# (driver side; the GDB side is gdb-recorder.py in this directory)
#
# Usage: verify-request.sh [--keep] [--budget S] [--image IMG] [--out F]
#                          [--workdir D] <model-dir> <spec.json>
#
# A BLIND STOP-READ-COMPARE MACHINE. This script holds ZERO firmware
# knowledge: no symbols, no ABI register tables, no call-site/return-site
# arithmetic, no notion of what a "source" or "getter" is. Every address
# to stop at and every location to read comes from the AGENT's spec; the
# harness only executes it faithfully and reports facts:
#
#   source check   stop at an agent-given vaddr, read the agent-given
#                  locations, compare against THIS probe's randomly
#                  generated canary — every location is tried in EVERY
#                  interpretation; an EXACT hit (pointwise: the value at
#                  the location IS the canary) passes, an ADJACENT hit
#                  (canary deeper inside the scanned block) is reported
#                  as a lead and never passes
#   getter check   stop at an agent-given vaddr; the mere hit after this
#                  probe's request is the whole proof (getters receive no
#                  user input — dispatch is the claim, there is nothing to
#                  compare). A getter's proof is inherently exact — the
#                  breakpoint sits at an exact address; there is no
#                  adjacent tier.
#
# The CANARY is generated HERE, per probe per run, injected into the
# request template as {{CANARY}} (a string) / {{CANARY_INT}} (a decimal
# number) and never printed. A check compares only against ITS OWN
# probe's canary, so a match proves that probe's request carried the
# value to that point; other probes' canaries visible at a stop are
# logged as contamination diagnostics and never count. The anti-
# fabrication backstop is unchanged from the old stage: whoever grades
# re-runs the spec with fresh random canaries.
#
# Per run: fresh lab container from the solved image -> emu boot (CPU
# frozen, gdbstub 0.0.0.0:1234) -> host gdb-multiarch attaches and
# releases the CPU (native-speed boot, zero breakpoints) -> web wait ->
# marker + SIGINT handshake arms every breakpoint just before the first
# request -> probes sent sequentially in spec order -> events -> verdicts
# -> teardown. ONE SPEC = ONE BOOT = all its probes.
#
# Spec format (agent-authored JSON; every address is a plain guest vaddr
# the agent computed itself — "0x1234", "1234", "*0x1234" and a JSON
# number are all accepted and normalized):
# {
#   "probes": [{
#     "id": "formAddBlack__ID__0x52434",       // unique, required
#     "request": ["curl","-s","--max-time","20","-X","POST",
#                 "-H","Content-Type: application/json",
#                 "-d","{\"addBlack\":{\"ID\":{{CANARY_INT}}}}",
#                 "http://{{GUEST_IP}}/goform/module"],
#     "checks": [
#       {"break": "0x52438",                    // stop address (required)
#        "read": ["$r0"]},                      // source check: the
#                                               // locations to read;
#                                               // omit "read" entirely
#                                               // for a getter check
#       {"break": "0x97654"}                    // getter check: hit only
#     ]
#     }]
# }
#
# read location syntax (a list; a bare string is accepted too):
#   "$r0"        a bare register name — the value is tried AS the int
#               canary (equality) AND as a pointer (the buffer it points
#               at is scanned for the string canary and the int canary's
#               32/64-bit LE/BE byte patterns)
#   "$sp+0x10"  any other gdb expression — evaluated to an integer used
#   "0x9fc00"   as a MEMORY ADDRESS; the block there is scanned the same
#               way
# Every location, every interpretation, every stop — the TIER of the best
# match decides: pointwise (reg-int, or the canary at offset 0 of the
# block the location addresses) = match-exact; canary deeper inside the
# block = match-adjacent. Only exact passes. The agent hedges against a
# wrong channel by listing MORE locations (each an exact observation
# point), never by hoping the region scan catches it.
#
# Verdicts (per check, in verdicts.json):
#   canary:  match-exact — a POINTWISE observation: a read location's
#            value IS the canary (register equality with the int canary,
#            or the bytes AT the location start with the string canary /
#            hold the int canary pattern at offset 0). The only canary
#            verdict that passes.
#            match-adjacent — the canary was found DEEPER in a scanned
#            block (heap adjacency): proves the probe's request data
#            lives in the neighborhood, NOT that this observation point
#            consumed it. A lead for the agent, never a pass.
#            no-match (stopped, canary absent) | no-stop (breakpoint
#            never hit) | bp-error | not-sent
#   getter:  hit (stop inside [send-2s, send+60s] — the window is ONE-
#            DIRECTIONAL so the guest's own pre-send traffic is never
#            credited) | no-hit | hit-outside-window | bp-error | not-sent
#   probe:   pass iff every check is match-exact or hit
# exit 0 = all probes pass, 1 = any fail, 2 = infrastructure error
# (docker/boot/attach/web). The script is expect-blind: it reports facts,
# interpretation belongs to the caller.
#
# Output: --out verdict JSON (default <workdir>/verdicts.json) plus
# events.jsonl / canaries.json / send-times.json / gdb.log / spec.norm.json
# in the workdir. Default workdir: <model>/taint-verify/<spec-stem>/ .
#
# The canary values land in canaries.json inside the workdir — after a
# run they are public to whoever reads it. That is the same threat model
# as the old stage: a fresh run means fresh values, so post-hoc knowledge
# of past canaries proves nothing; the grading re-run is the backstop.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # no __pycache__ anywhere in the pipeline

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KEEP=0
BUDGET=900          # total wall-clock budget for the whole run
WEBWAIT=300         # max seconds waiting for the web service
EVIDWAIT=120        # max seconds waiting for probe evidence after requests
IMAGE=""
OUT=""
WORKDIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --keep)    KEEP=1; shift ;;
        --budget)  BUDGET="$2"; shift 2 ;;
        --image)   IMAGE="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,95p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) break ;;
    esac
done
MODEL="${1:?usage: verify-request.sh [--keep] [--budget S] [--out F] <model-dir> <spec.json>}"
SPEC="${2:?usage: verify-request.sh [--keep] [--budget S] [--out F] <model-dir> <spec.json>}"
MODEL="$(cd "$MODEL" 2>/dev/null && pwd)" || { echo "[-] no such dir: $1" >&2; exit 2; }
[ -f "$MODEL/task.json" ] || { echo "[-] not a model dir (no task.json): $MODEL" >&2; exit 2; }
[ -f "$SPEC" ] || { echo "[-] no such spec: $SPEC" >&2; exit 2; }
SPEC="$(readlink -f "$SPEC")"
STEM="$(basename "$SPEC" .json)"

VENDOR=$(basename "$(dirname "$MODEL")")
MODELNAME=$(basename "$MODEL")
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')
IMAGE="${IMAGE:-task-$TASK_ID:solved}"
# container name carries the spec stem: concurrent runs of different specs
# each get their own container instead of docker rm -f'ing each other
CONTAINER="taint-verify-$TASK_ID-$(printf '%s' "$STEM" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')"
WORK="${WORKDIR:-$MODEL/taint-verify/$STEM}"
mkdir -p "$WORK"
if [ -n "$OUT" ]; then
    mkdir -p "$(dirname "$OUT")"
else
    OUT="$WORK/verdicts.json"
fi

command -v gdb-multiarch >/dev/null || { echo "[-] gdb-multiarch missing on host (apt install gdb-multiarch)" >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "[-] no such image: $IMAGE" >&2; exit 2; }

RUN_START=$(date +%s)
teardown() {
    # gdb: TERM then KILL; emulation: emu stop; container: rm unless --keep
    if [ -n "${GDBPID:-}" ] && kill -0 "$GDBPID" 2>/dev/null; then
        kill -TERM "$GDBPID" 2>/dev/null || true
        sleep 3
        kill -KILL "$GDBPID" 2>/dev/null || true
    fi
    docker exec "$CONTAINER" emu stop >/dev/null 2>&1 || true
    if [ "$KEEP" = 1 ]; then
        echo "[*] container kept for inspection: $CONTAINER"
    else
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap 'teardown; trap - EXIT' EXIT

# ---- validate the spec, normalize addresses, generate canaries ---------------
python3 - "$SPEC" "$WORK" <<'EOF' || exit 1
import json, os, re, secrets, sys
spec_path, work = sys.argv[1:3]
try:
    s = json.load(open(spec_path))
except Exception as e:
    sys.exit(f"[-] spec is not valid JSON: {e}")
probes = s.get("probes")
if not isinstance(probes, list) or not probes:
    sys.exit("[-] spec must hold a non-empty 'probes' list")


def norm_addr(v):
    """'0x1234' | '1234' | '*0x1234' | 1234 -> '0x1234' (normalized hex)"""
    if isinstance(v, bool):
        raise ValueError(f"bad address: {v!r}")
    if isinstance(v, int):
        return "0x%x" % v
    t = str(v).strip().lstrip("*")
    t = re.sub(r"^0[xX]", "", t)
    if not re.fullmatch(r"[0-9a-fA-F]+", t):
        raise ValueError(f"bad address: {v!r}")
    return "0x%x" % int(t, 16)


def norm_reads(v):
    """a location string or a list of them -> a non-empty list of strings"""
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x.strip() for x in v):
        raise ValueError(f"bad read location list: {v!r}")
    return v


ids = set()
for i, p in enumerate(probes):
    for k in ("id", "request"):
        if not p.get(k):
            sys.exit(f"[-] probe[{i}] missing field: {k}")
    if not isinstance(p["request"], list) or not all(isinstance(a, str) for a in p["request"]):
        sys.exit(f"[-] probe[{i}].request must be a list of strings")
    if p["id"] in ids:
        sys.exit(f"[-] duplicate probe id: {p['id']}")
    ids.add(p["id"])
    checks = p.get("checks")
    if not isinstance(checks, list) or not checks:
        sys.exit(f"[-] probe[{i}] must hold a non-empty 'checks' list")
    for j, c in enumerate(checks):
        if not isinstance(c, dict) or not c.get("break"):
            sys.exit(f"[-] probe[{i}].checks[{j}] missing 'break' (a guest vaddr)")
        try:
            c["break"] = norm_addr(c["break"])
        except ValueError as e:
            sys.exit(f"[-] probe[{i}].checks[{j}]: {e}")
        if "read" in c:
            try:
                c["read"] = norm_reads(c["read"])
            except ValueError as e:
                sys.exit(f"[-] probe[{i}].checks[{j}]: {e}")

# canaries are generated HERE, never shown to the caller: the agent cannot
# pre-plant evidence for a value it has not seen. Two channels per probe:
# the string canary (buffer containment) and the int canary (equality /
# byte patterns)
canaries = {p["id"]: {"string": "VRF-" + secrets.token_hex(6),
                      "int": secrets.randbits(31)} for p in probes}
json.dump(canaries, open(os.path.join(work, "canaries.json"), "w"), indent=2)
# the normalized spec is the single source of truth for the recorder and
# the verdict step (the raw spec file is never rewritten)
json.dump({"probes": probes}, open(os.path.join(work, "spec.norm.json"), "w"),
          indent=2, ensure_ascii=False)
print(f"[verify] spec ok: {len(probes)} probe(s), "
      f"{sum(len(p['checks']) for p in probes)} check(s)")
EOF

# ---- fresh lab container + frozen gdb boot ---------------------------------
echo "[verify] task=$TASK_ID image=$IMAGE container=$CONTAINER work=$WORK"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
    --entrypoint /usr/local/bin/emu-shell \
    --name "$CONTAINER" "$IMAGE" >/dev/null || { echo "[-] docker run failed" >&2; exit 2; }

for _ in $(seq 1 30); do
    docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 && break
    sleep 1
done
docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 || { echo "[-] PostgreSQL failed" >&2; exit 2; }

echo "[verify] emu boot (CPU frozen, gdbstub :1234)..."
docker exec "$CONTAINER" emu boot || { echo "[-] emu boot failed" >&2; exit 2; }

BRIDGE=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER")
GUEST_IP=$(docker exec "$CONTAINER" emu ip 2>/dev/null | head -1)
[ -n "$GUEST_IP" ] || { echo "[-] no guest IP (emu ip)" >&2; exit 2; }
echo "[verify] bridge=$BRIDGE guest=$GUEST_IP"
timeout 5 bash -c "</dev/tcp/$BRIDGE/1234" 2>/dev/null \
    || { echo "[-] gdbstub unreachable at $BRIDGE:1234" >&2; exit 2; }

# ---- arm the recorder (native-speed boot; bps at send-start) -----------------
: > "$WORK/events.jsonl"   # fresh log per run (recorder appends)
ARM="$WORK/arm-now"        # marker file: the recorder arms when it exists
rm -f "$ARM"
GDBPID=""
VPROBE_SPEC="$WORK/spec.norm.json" \
VPROBE_LOG="$WORK/events.jsonl" \
VPROBE_BRIDGE="$BRIDGE" \
VPROBE_CANARIES="$(cat "$WORK/canaries.json")" \
VPROBE_ARM_MARKER="$ARM" \
gdb-multiarch -batch -nx -q -x "$SCRIPTS/gdb-recorder.py" \
    >"$WORK/gdb.log" 2>&1 &
GDBPID=$!
echo "[verify] gdb recorder pid=$GDBPID (native-speed boot; breakpoints arm at send-start)"

# ---- wait for the web service -----------------------------------------------
# BUDGET caps the WHOLE run (boot + web wait + probes + evidence): each wait
# phase takes at most the remaining budget, never its nominal maximum
deadline=$(( RUN_START + BUDGET ))
remain=$(( deadline - $(date +%s) ))
[ "$remain" -gt 0 ] || remain=5
[ "$remain" -gt "$WEBWAIT" ] && remain=$WEBWAIT
echo "[verify] waiting for web at http://$GUEST_IP/ (max ${remain}s)..."
web_code=000
for _ in $(seq 1 $(( remain / 5 ))); do
    # NOTE: curl -w prints the code itself on failure too ("000", rc != 0);
    # only default when it printed nothing at all
    web_code=$(docker exec "$CONTAINER" curl -s -o /dev/null -w '%{http_code}' \
        --max-time 5 "http://$GUEST_IP/" 2>/dev/null || true)
    [ -n "$web_code" ] || web_code=000
    [ "$web_code" != "000" ] && break
    kill -0 "$GDBPID" 2>/dev/null || break
    sleep 5
done
if [ "$web_code" = "000" ] || [ -z "$web_code" ]; then
    echo "[-] web service never answered (last code: $web_code)" >&2
    echo "false" > "$WORK/web_ready"
else
    echo "true" > "$WORK/web_ready"
    echo "[verify] web answering (HTTP $web_code) — arming breakpoints"
    # ---- the arm handshake -----------------------------------------------
    # touch the marker, then SIGINT gdb: its blocked `continue` returns, the
    # recorder sees the marker, arms every breakpoint, and re-continues.
    # Retries every 5s cover signal races (a SIGINT that lands before gdb
    # is inside `continue` is swallowed harmlessly by the stray-stop path).
    touch "$ARM"
    kill -INT "$GDBPID" 2>/dev/null || true
    armed=0
    for i in $(seq 1 30); do
        grep -q '"event": "armed"' "$WORK/events.jsonl" 2>/dev/null && { armed=1; break; }
        kill -0 "$GDBPID" 2>/dev/null || break
        [ $((i % 5)) = 0 ] && kill -INT "$GDBPID" 2>/dev/null || true
        sleep 1
    done
    if [ "$armed" = 1 ]; then
        echo "[verify] breakpoints armed at send-start — sending probes"
    else
        echo "[!] arm handshake failed — this run may record no events" >&2
    fi
fi

# ---- send the probes ---------------------------------------------------------
# the send loop is budget-capped: a wedged tail cannot burn unbounded time.
# One bad probe must never kill its whole spec: bytes capture (a probe's
# response may be BINARY), a 60s timeout, any exception — recorded, loop
# moves on
python3 - "$WORK/spec.norm.json" "$WORK" "$CONTAINER" "$GUEST_IP" "$deadline" <<'EOF'
import json, os, subprocess, sys, time
spec, work, ctr, guest_ip = sys.argv[1:5]
deadline = float(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else 0.0
spec = json.load(open(spec))
canaries = json.load(open(os.path.join(work, "canaries.json")))
sends = {}
for p in spec["probes"]:
    can = canaries[p["id"]]
    if deadline and time.time() > deadline:
        sends[p["id"]] = {"skipped": "budget"}
        print(f"[verify] probe {p['id']}: SKIPPED (budget exhausted)")
        continue
    argv = [a.replace("{{GUEST_IP}}", guest_ip)
             .replace("{{CANARY}}", can["string"])
             .replace("{{CANARY_INT}}", str(can["int"]))
            for a in p["request"]]
    print(f"[verify] probe {p['id']}: {' '.join(argv[:6])}{' ...' if len(argv) > 6 else ''}")
    t0 = time.time()
    try:
        rc = subprocess.run(["docker", "exec", ctr] + argv,
                            capture_output=True, timeout=60).returncode
        sends[p["id"]] = {"t": t0, "curl_rc": rc}
    except Exception as e:
        sends[p["id"]] = {"t": t0, "curl_rc": -1, "error": str(e)[:200]}
        print(f"[verify] probe {p['id']}: send error ({e}); continuing")
        time.sleep(2)
        continue
    time.sleep(2)  # let the handler run before the next request
json.dump(sends, open(os.path.join(work, "send-times.json"), "w"), indent=2)
EOF

# ---- wait for evidence --------------------------------------------------------
remain=$(( deadline - $(date +%s) ))
[ "$remain" -gt 0 ] || remain=10
[ "$remain" -gt "$EVIDWAIT" ] && remain=$EVIDWAIT
echo "[verify] collecting evidence (max ${remain}s)..."
for _ in $(seq 1 $(( remain / 5 ))); do
    python3 - "$WORK/spec.norm.json" "$WORK" <<'EOF' && break || true
import json, os, sys
spec = json.load(open(sys.argv[1]))
work = sys.argv[2]
try:
    sends = json.load(open(os.path.join(work, "send-times.json")))
except Exception:
    sys.exit(1)
try:
    events = [json.loads(l) for l in open(os.path.join(work, "events.jsonl"))
              if l.strip()]
except Exception:
    sys.exit(1)


def stop_exact(e):
    """a pointwise canary match at this stop: register equality, or the
    canary at offset 0 of the block a location addresses"""
    for l in e.get("locations", []):
        for m in l.get("matches", []):
            if m.get("mode") == "reg-int" or m.get("at") == 0:
                return True
    return False


for p in spec["probes"]:
    pid = p["id"]
    s = sends.get(pid, {})
    if s.get("skipped"):
        continue
    t0 = s.get("t", 0)
    stops = [e for e in events if e.get("event") == "check_stop"
             and e.get("probe") == pid]
    for chk in p.get("checks", []):
        site = [e for e in stops if e.get("break") == chk["break"]]
        if chk.get("read"):
            # only an EXACT match satisfies a canary check — an adjacent
            # match does not end the wait (a later stop of the same site
            # may still carry the pointwise proof)
            if not any(stop_exact(e) for e in site):
                sys.exit(1)
        else:
            if not any(t0 - 2.0 <= e.get("t", 0) <= t0 + 60 for e in site):
                sys.exit(1)   # getter check not yet hit in window
sys.exit(0)
EOF
    kill -0 "$GDBPID" 2>/dev/null || break
    sleep 5
done

# ---- verdict -------------------------------------------------------------------
VERDICT_RC=0
python3 - "$WORK/spec.norm.json" "$WORK" "$OUT" <<'EOF' || VERDICT_RC=$?
import json, os, sys
spec_path = sys.argv[1]
spec = json.load(open(spec_path))
work, outp = sys.argv[2:4]
try:
    sends = json.load(open(os.path.join(work, "send-times.json")))
except Exception:
    sends = {}
events = []
evp = os.path.join(work, "events.jsonl")
if os.path.exists(evp):
    events = [json.loads(l) for l in open(evp, errors="replace") if l.strip()]


def stops_for(pid, addr):
    return [e for e in events if e.get("event") == "check_stop"
            and e.get("probe") == pid and e.get("break") == addr]


def first_exact(e):
    """(location, match) of the first pointwise canary match in this stop,
    or None: register equality, or the canary at offset 0"""
    for l in e.get("locations", []):
        for m in l.get("matches", []):
            if m.get("mode") == "reg-int" or m.get("at") == 0:
                return l, m
    return None


def first_adjacent(e):
    for l in e.get("locations", []):
        for m in l.get("matches", []):
            if not (m.get("mode") == "reg-int" or m.get("at") == 0):
                return l, m
    return None


def ev_of(l, m):
    return {"loc": l.get("loc"), "value": l.get("value"),
            "string": l.get("string"), "mode": m.get("mode"),
            "at": m.get("at")}


results = []
all_pass = True
for p in spec["probes"]:
    pid = p["id"]
    s = sends.get(pid, {}) or {}
    t0 = s.get("t")
    skipped = s.get("skipped")
    probe_pass = True
    check_results = []
    for chk in p.get("checks", []):
        addr = chk["break"]
        kind = "canary" if chk.get("read") else "hit"
        site = stops_for(pid, addr)
        disabled = [d for d in events if d.get("event") == "site_disabled"
                    and d.get("probe") == pid and d.get("break") == addr]
        bp_err = [b for b in events if b.get("event") == "bp_error"
                  and b.get("symbol") == addr]
        rec = {"break": addr, "kind": kind, "stops": len(site)}
        if skipped or t0 is None:
            # never sent (budget skip, or the send loop never reached it)
            rec["verdict"] = "not-sent"
        elif kind == "canary":
            matching = [e for e in site if e.get("matched")]
            exacts = [x for x in (first_exact(e) for e in site) if x]
            if exacts:
                rec["verdict"] = "match-exact"
                rec["evidence"] = ev_of(*exacts[0])
            elif matching:
                rec["verdict"] = "match-adjacent"
                l, m = first_adjacent(matching[0]) or (matching[0]
                                                       .get("locations", [{}])[0], {})
                rec["evidence"] = ev_of(l, m)
                rec["note"] = ("adjacency: the canary is deeper in the "
                               "scanned block — a lead, not a pass")
            elif site:
                rec["verdict"] = "no-match"
            elif bp_err:
                rec["verdict"] = "bp-error"
            else:
                rec["verdict"] = "no-stop"
        else:
            inwin = [e for e in site if t0 and t0 - 2.0 <= e.get("t", 0) <= t0 + 60]
            if inwin:
                rec["verdict"] = "hit"
                rec["hits"] = len(inwin)
                rec["first_hit_at"] = inwin[0].get("t")
            elif site:
                rec["verdict"] = "hit-outside-window"
                rec["hits_outside"] = len(site)
            elif bp_err:
                rec["verdict"] = "bp-error"
            else:
                rec["verdict"] = "no-hit"
        if disabled:
            rec["site_disabled"] = [d.get("rule") for d in disabled]
        if rec["verdict"] not in ("match-exact", "hit"):
            probe_pass = False
        check_results.append(rec)
    if not check_results:
        probe_pass = False
    if not probe_pass:
        all_pass = False
    results.append({
        "probe": pid, "verdict": "pass" if probe_pass else "fail",
        "checks": check_results,
        "request_sent_at": t0,
        "skipped": skipped,
    })

res = {
    "spec": os.path.basename(spec_path),
    "all_pass": all_pass,
    "web_ready": os.path.exists(os.path.join(work, "web_ready"))
    and open(os.path.join(work, "web_ready")).read().strip() == "true",
    "probes": results,
}
json.dump(res, open(outp, "w"), indent=2, ensure_ascii=False)
print(f"[verify] verdicts -> {outp}")
for r in results:
    mark = "PASS" if r["verdict"] == "pass" else "FAIL"
    det = " ".join(f"{c['break']}:{c['verdict']}" for c in r["checks"])
    print(f"  {mark:5s} {r['probe']:40s} {det}")
sys.exit(0 if all_pass else 1)
EOF

echo "[verify] done in $(( $(date +%s) - RUN_START ))s (events: $WORK/events.jsonl)"
[ "$VERDICT_RC" = 0 ] && exit 0 || exit "$VERDICT_RC"
