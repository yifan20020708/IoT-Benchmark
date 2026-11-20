#!/bin/bash
# agent-scan :: taint — repro-run.sh: re-run ONE vault entry's poc on a fresh
# boot, RECORD the live replay as a timestamped event stream, and render the
# CNVD authenticity video (mp4 + srt) from exactly those bytes.
#
# Usage: repro-run.sh [--retries N] [--boot-timeout S] [--gate-confirm S]
#                     [--port P] [--no-agent] [--agent-timeout S]
#                     [--prose-only] [--keep] <vault-entry-dir>
#
#   <vault-entry-dir>  data/round/<vendor>/<model>/<poc-stem>-<graded-ts>
#   --prose-only       reuse the sealed replay of an already-successful
#                      repro/ (rc must match the vault): re-run ONLY the
#                      organizer agent + the render — no boot, no traffic
#
# What it does (per attempt; a fresh container EACH attempt):
#   boot emu debug -> serving gate (stability-confirm, boundary service_port)
#   -> baseline alive probe -> run the vault's sha-pinned poc via the CURRENT
#   poc-run -> live-tail the guest serial into the event stream -> harvest
#   serial-full/window/decisive + report.json -> render repro.mp4 + repro.srt.
# The video is the REPLAY: cause and effect share one screen in real time
# (split panes); the boot segment is time-lapsed and the caption says so.
#
# Integrity rules (retry semantics ALIGNED with verify-run):
#   * the replay's rc must equal the vault's rc (same hit class); otherwise a
#     fresh container+boot retry — --retries N extra attempts (default 5,
#     verify-run's default); rc=4 (poc_error) is deterministic and NEVER
#     retried; every attempt lands in repro.json's attempts_ledger and failed
#     attempts are preserved as repro.fail-<n>/ — best-of-N stays auditable.
#     After the retries the entry is marked repro.state=missed-replay with NO
#     video — a video is never rendered from stale evidence;
#   * repro/ is additive: an existing repro/ is moved to repro.pre-<ts>, the
#     vault's graded evidence/, REPORT.md, AUDIT.json are never touched;
#   * the renderer re-times the event stream but never adds content; the
#     stream itself (repro/session.jsonl) is archived for audit;
#   * the STATIC organizer agent (repro-prompt.md) writes prose only —
#     REPRO.md + the explanatory subtitle layer (repro/subtitles.json);
#     it never boots, sends traffic, or touches the verdict. Agent failure
#     is non-fatal: the renderer falls back to deterministic templates.
#
# Output inside the entry: repro/{session.jsonl,repro.mp4,repro.srt,
#   serial-full.log,serial-window.log,decisive.txt,canary-new.txt,
#   report.json,repro.json,REPRO.md,subtitles.json,pocrun/}.
#   meta.json gains a "repro" object.
# Exit: 0 = video rendered; 3 = missed-replay (no video); 1 = usage/infra.
set -euo pipefail

RETRIES=5; BOOT_TIMEOUT=420; GATE_CONFIRM=8; PORT=""; KEEP=""
NO_AGENT=""; AGENT_TIMEOUT=1200; PROSE_ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --retries) RETRIES="$2"; shift 2 ;;
        --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
        --gate-confirm) GATE_CONFIRM="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --no-agent) NO_AGENT=1; shift ;;
        --agent-timeout) AGENT_TIMEOUT="$2"; shift 2 ;;
        --prose-only) PROSE_ONLY=1; shift ;;
        --keep) KEEP=1; shift ;;
        -h|--help) awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,"");print}' "$0"; exit 0 ;;
        *) break ;;
    esac
done
ENTRY="${1:?usage: repro-run.sh [opts] <vault-entry-dir>}"
ENTRY="$(cd "$ENTRY" 2>/dev/null && pwd)" || { echo "[-] no such entry: $1" >&2; exit 1; }
[ -f "$ENTRY/meta.json" ] || { echo "[-] not a vault entry: $ENTRY" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$ROOT/scripts/taint"

read -r MODEL VENDOR MODELNAME VAULT_RC POCNAME UNIT < <(python3 -c '
import json, sys
m = json.load(open(sys.argv[1] + "/meta.json"))
print(m["source"]["model_dir"], m["vendor"], m["model"], m["rc"], m["poc"],
      m.get("unit", ""))' "$ENTRY")
[ -d "$MODEL" ] || { echo "[-] model dir gone: $MODEL" >&2; exit 1; }
TASK_ID=$(printf '%s__%s' "$VENDOR" "$MODELNAME" | tr '[:upper:]' '[:lower:]' \
          | sed 's/[^a-z0-9._-]/-/g')
IMAGE="task-$TASK_ID:solved"
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "[-] no solved image $IMAGE" >&2; exit 1; }
POCFILE=$(ls "$ENTRY"/poc.* 2>/dev/null | head -1)
[ -n "$POCFILE" ] || { echo "[-] no poc.* in entry" >&2; exit 1; }
if [ -z "$PORT" ]; then
    PORT=$(python3 -I -c "
import json,sys
try: print(json.load(open(sys.argv[1])).get('service_port') or 80)
except Exception: print(80)" "$MODEL/taint-work-output/boundary.json" 2>/dev/null) || PORT=80
fi
ESLUG=$(printf '%s' "$(basename "$ENTRY")" | tr '._' '--')
[ "${#ESLUG}" -gt 60 ] && ESLUG="${ESLUG:0:52}-$(printf '%s' "$ENTRY" | md5sum | cut -c1-6)"
REP="$ENTRY/repro"
if [ -z "$PROSE_ONLY" ] && [ -d "$REP" ]; then
    mv "$REP" "$ENTRY/repro.pre-$(date +%Y%m%d-%H%M%S)"
fi

SESSION="" ; ev() {  # ev <stream> <text> — append one timestamped event
    python3 -c 'import json,sys,time
open(sys.argv[1],"a",encoding="utf-8").write(
    json.dumps({"ts":time.time(),"s":sys.argv[2],"t":sys.argv[3]},
               ensure_ascii=False)+"\n")' "$SESSION" "$1" "$2"
}
# attempts ledger (verify-run alignment): every attempt is recorded, the
# score of record is the LAST one, failed attempts stay inspectable
LEDGER=$(mktemp); trap 'rm -f "$LEDGER"' EXIT
ledger() {  # ledger <attempt> <rc> <boot_s> <fail_dir>
    python3 -c 'import json,sys,time
open(sys.argv[1],"a").write(json.dumps({"attempt":int(sys.argv[2]),
    "rc":int(sys.argv[3]),"boot_s":int(sys.argv[4]),"fail_dir":sys.argv[5],
    "ts":time.time()})+"\n")' "$LEDGER" "$1" "$2" "$3" "$4"
}
gate_probe() {  # raw TCP probe of the declared attack-surface port
    docker exec -e GATEPORT="$PORT" "$1" bash -c '
        IP=$( { cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null; } | head -1)
        [ -n "$IP" ] && timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$GATEPORT" 2>/dev/null \
            && echo up || echo 000' 2>/dev/null || echo 000
}

if [ -n "$PROSE_ONLY" ]; then
    # reuse the SEALED replay: organizer agent + re-render only — no boot, no
    # traffic, session.jsonl/report.json untouched (prompt-tweak re-runs)
    [ -f "$REP/repro.json" ] || { echo "[-] --prose-only: no repro/repro.json in $ENTRY" >&2; exit 1; }
    read -r RC ATTEMPT BOOT_S CTR IMAGE PORT < <(python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
print(r["rc"], r["attempts"], r["boot_s"], r["container"], r["image"], r["port"])' "$REP/repro.json")
    [ "$RC" = "$VAULT_RC" ] || { echo "[-] --prose-only: sealed rc=$RC != vault rc=$VAULT_RC" >&2; exit 1; }
    # carry the sealed run's attempts ledger forward (repro.json is rewritten)
    python3 -c 'import json,sys
r = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w") as f:
    for a in r.get("attempts_ledger", []):
        f.write(json.dumps(a) + "\n")' "$REP/repro.json" "$LEDGER" 2>/dev/null || true
    echo "[repro] prose-only: reusing sealed replay rc=$RC from $REP"
else
ATTEMPT=0; RC=-9
while [ "$ATTEMPT" -le "$RETRIES" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    rm -rf "$REP"; mkdir -p "$REP"
    SESSION="$REP/session.jsonl"; : > "$SESSION"
    CTR="repro-$ESLUG-$ATTEMPT"
    docker rm -f "$CTR" >/dev/null 2>&1 || true
    echo "[repro] attempt $ATTEMPT/$((RETRIES + 1)) container=$CTR port=$PORT"
    docker run -d --init --privileged --device /dev/kvm -v /dev:/dev \
        --entrypoint /usr/local/bin/emu-shell --name "$CTR" "$IMAGE" >/dev/null \
        || { echo "[-] docker run failed" >&2; exit 1; }
    for _ in $(seq 1 30); do docker exec "$CTR" pg_isready -q -h 127.0.0.1 && break; sleep 1; done
    docker cp "$SCRIPTS/poc-run.sh" "$CTR:/usr/local/bin/poc-run"
    docker cp "$ROOT/scripts/rehost/emu.sh" "$CTR:/usr/local/bin/emu"
    docker exec "$CTR" chmod +x /usr/local/bin/poc-run /usr/local/bin/emu
    docker cp "$ROOT/scripts/rehost/loop-shim/losetup.sh" "$CTR:/usr/local/sbin/losetup" 2>/dev/null || true
    docker cp "$ROOT/scripts/rehost/loop-shim/kpartx.sh" "$CTR:/usr/local/sbin/kpartx" 2>/dev/null || true
    docker exec "$CTR" chmod +x /usr/local/sbin/losetup /usr/local/sbin/kpartx 2>/dev/null || true
    docker exec "$CTR" mkdir -p /work/poc /work/poc-runs
    docker cp "$POCFILE" "$CTR:/work/poc/$(basename "$POCFILE")"
    SER=$(docker exec "$CTR" sh -c 'ls -d /opt/FirmAE-pro/scratch/[0-9]* 2>/dev/null | sort -n | tail -1')/qemu.final.serial.log
    ev cap boot-start
    T_BOOT=$(date +%s)
    docker exec -d "$CTR" emu debug
    # serving gate with stability confirmation (same rule as verify-run)
    CODE=000; SAWUP=""
    DEADLINE=$(( $(date +%s) + BOOT_TIMEOUT ))
    while :; do
        CODE=$(gate_probe "$CTR")
        if [ "$CODE" = up ]; then
            SAWUP=1
            if [ "$GATE_CONFIRM" -gt 0 ]; then
                sleep "$GATE_CONFIRM"
                [ "$(gate_probe "$CTR")" = up ] && break
            else break; fi
        fi
        [ "$(date +%s)" -ge "$DEADLINE" ] && break
        sleep 5
    done
    [ "$CODE" = up ] || { echo "[repro] gate never stable (attempt $ATTEMPT)"; \
        ledger "$ATTEMPT" -9 0 "gate-fail"; \
        docker rm -f "$CTR" >/dev/null 2>&1 || true; continue; }
    BOOT_S=$(( $(date +%s) - T_BOOT ))
    ev cap gate-stable
    ev gate "gate: port $PORT stable after ${BOOT_S}s (confirm ${GATE_CONFIRM}s)"
    # boot serial sample for the (declared) time-lapse segment
    docker exec "$CTR" head -12 "$SER" 2>/dev/null | while IFS= read -r ln; do
        [ -n "$ln" ] && ev serial "$ln" || true
    done
    IP=$(docker exec "$CTR" sh -c 'cat /opt/FirmAE-pro/scratch/*/ip /opt/FirmAE-pro/scratch/*/ip.[0-9]* 2>/dev/null | head -1')
    HCODE=$(docker exec "$CTR" curl -sL --max-redirs 5 -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP/" 2>/dev/null || echo 000)
    ev cmd "$ curl -sL http://$IP/   (baseline, pre-attack)"
    ev out "HTTP $HCODE"
    ev probe "baseline probe: alive (tcp/$PORT + HTTP $HCODE)"
    # ---- attack window: live serial tailer + the graded poc, real time ----
    ev cap attack-start
    AT0=$(date +%s.%N)
    RAWTAIL="$REP/.rawtail"; : > "$RAWTAIL"
    # start the live tail at the NEXT line: the boot backlog already lives in
    # serial-full.log + the boot sample, re-tailing it would flood the window.
    # NOTE the redirect must run INSIDE the container — `docker exec wc -l <
    # $SER` opens the container path on the HOST (always empty).
    LOFF=$(docker exec "$CTR" sh -c "wc -l < '$SER' 2>/dev/null" || echo 0)
    LOFF=$(( ${LOFF:-0} + 1 ))
    ( while :; do
          NL=$(docker exec "$CTR" sh -c "wc -l < '$SER' 2>/dev/null" || echo 0)
          NL=${NL:-0}
          if [ "$NL" -ge "$LOFF" ]; then
              docker exec "$CTR" sed -n "${LOFF},${NL}p" "$SER" 2>/dev/null \
                | while IFS= read -r ln; do printf '%s SERIAL %s\n' "$(date +%s.%N)" "$ln"; done >> "$RAWTAIL"
              LOFF=$((NL + 1))
          fi
          sleep 0.4
      done ) &
    TPID=$!
    ev cmd "$ poc-run /work/poc/$(basename "$POCFILE") --port $PORT"
    set +e
    docker exec "$CTR" poc-run "/work/poc/$(basename "$POCFILE")" --port "$PORT" \
        --out-root /work/poc-runs/repro >/dev/null 2>&1
    RC=$?
    set -e
    kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true
    # the serial lines that landed DURING the window, with their real ts
    while read -r ts _rest; do
        ln="${_rest#SERIAL }"
        python3 -c 'import json,sys
open(sys.argv[1],"a",encoding="utf-8").write(
    json.dumps({"ts":float(sys.argv[2]),"s":"serial","t":sys.argv[3]},
               ensure_ascii=False)+"\n")' "$SESSION" "$ts" "$ln"
    done < "$RAWTAIL"
    rm -f "$RAWTAIL"
    mkdir -p "$REP/pocrun"
    docker cp "$CTR:/work/poc-runs/repro/." "$REP/pocrun/" 2>/dev/null || true
    RUND=$(ls -dt "$REP"/pocrun/poc-* 2>/dev/null | head -1)
    # the poc's own step log, verbatim, re-timed across the attack window
    if [ -n "$RUND" ] && [ -f "$RUND/stdout.txt" ]; then
        i=0
        while IFS= read -r ln; do
            [ -n "$ln" ] && python3 -c 'import json,sys
open(sys.argv[1],"a",encoding="utf-8").write(json.dumps(
    {"ts":float(sys.argv[3])+int(sys.argv[4])*0.15,"s":"out","t":sys.argv[2]},
    ensure_ascii=False)+"\n")' "$SESSION" "$ln" "$AT0" "$i" || true
            i=$((i + 1))
        done < "$RUND/stdout.txt"
    fi
    # canary new records (CI class) — verbatim from this run's log
    if [ -n "$RUND" ] && [ -f "$RUND/canary_log.txt" ]; then
        MK=$(python3 -c 'import json;print(json.load(open(sys.argv[1])).get("verdict",{}).get("marker",""))' "$RUND/report.json" 2>/dev/null || echo "")
        grep -F "$MK" "$RUND/canary_log.txt" 2>/dev/null > "$REP/canary-new.txt" || : > "$REP/canary-new.txt"
        while IFS= read -r ln; do [ -n "$ln" ] && ev canary "$ln" || true; done < "$REP/canary-new.txt"
    fi
    for p in 1 2 3; do
        PC=$(docker exec "$CTR" bash -c "timeout 3 bash -c 'exec 3<>/dev/tcp/$IP/$PORT' 2>/dev/null && echo alive || echo dead" 2>/dev/null || echo dead)
        ev probe "post probe #$p: $PC"
        sleep 2
    done
    ev cap attack-end
    # ---- harvest serial artifacts of THIS replay ----
    docker cp "$CTR:/work/poc-runs/repro/." "$REP/pocrun/" 2>/dev/null || true
    [ -z "$KEEP" ] || true
    docker exec "$CTR" tail -c 5242880 "$SER" > "$REP/serial-full.log" 2>/dev/null || : > "$REP/serial-full.log"
    if [ -n "$RUND" ]; then
        cp "$RUND/serial_segment.txt" "$REP/serial-window.log" 2>/dev/null || : > "$REP/serial-window.log"
        cp "$RUND/report.json" "$REP/report.json" 2>/dev/null || echo '{}' > "$REP/report.json"
    else
        : > "$REP/serial-window.log"; echo '{}' > "$REP/report.json"
    fi
    grep -a -i -E 'sending SIG|fatal signal|kernel panic|oops:|firmadyne: inet_accept|Comm:' \
        "$REP/serial-window.log" > "$REP/decisive.txt" 2>/dev/null || : > "$REP/decisive.txt"
    docker rm -f "$CTR" >/dev/null 2>&1 || true
    echo "[repro] attempt $ATTEMPT rc=$RC (vault rc=$VAULT_RC)"
    if [ "$RC" = "$VAULT_RC" ]; then
        ledger "$ATTEMPT" "$RC" "$BOOT_S" ""
        break
    fi
    if [ "$RC" = 4 ]; then
        # verify-run rule: rc=4 (poc_error) is deterministic — NEVER retried
        echo "[repro] rc=4 (poc_error) — deterministic, never retried (verify-run rule)"
        ledger "$ATTEMPT" "$RC" "$BOOT_S" "repro.fail-$ATTEMPT"
        mv "$REP" "$ENTRY/repro.fail-$ATTEMPT" 2>/dev/null || true
        break
    fi
    ledger "$ATTEMPT" "$RC" "$BOOT_S" "repro.fail-$ATTEMPT"
    mv "$REP" "$ENTRY/repro.fail-$ATTEMPT" 2>/dev/null || true
    RC=-9
done

if [ "$RC" != "$VAULT_RC" ]; then
    mkdir -p "$REP"
    python3 - "$REP/repro.json" "$ATTEMPT" "$RC" "$VAULT_RC" "$LEDGER" <<'EOF'
import json, sys, os, datetime
p, a, rc, vrc, led = sys.argv[1:6]
attempts_ledger = [json.loads(l) for l in open(led) if l.strip()] \
    if os.path.exists(led) else []
json.dump({"state": "missed-replay", "attempts": int(a), "last_rc": int(rc),
           "vault_rc": int(vrc), "attempts_ledger": attempts_ledger,
           "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
           "note": "no video: the live replay did not reproduce the vaulted "
                   "verdict class; rendering from stale evidence is refused"},
          open(p, "w"), indent=1)
EOF
    python3 - "$ENTRY/meta.json" "$ATTEMPT" <<'EOF'
import json, sys, datetime
p, a = sys.argv[1], int(sys.argv[2])
m = json.load(open(p))
m["repro"] = {"state": "missed-replay", "attempts": a,
              "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
json.dump(m, open(p, "w"), indent=2, ensure_ascii=False)
EOF
    echo "[repro] MISSED-REPLAY after $ATTEMPT attempt(s) — no video written" >&2
    exit 3
fi
fi   # end of the replay arm (--prose-only skips it)


if [ -z "$NO_AGENT" ] && [ -f "$SCRIPTS/repro-prompt.md" ] && [ -f "$ROOT/.env" ] \
   && command -v claude >/dev/null 2>&1; then
    read -r KLASS MARKER < <(python3 -c '
import json, sys
v = json.load(open(sys.argv[1])).get("verdict", {})
k = "CI" if v.get("ci") else "BOF" if v.get("bof") else "DoS" if v.get("service_down") else "?"
print(k, v.get("marker", ""))' "$REP/report.json" 2>/dev/null || echo "? -")
    mkdir -p "$REP/.agent-run"
    sed -e "s|{{ENTRY}}|$ENTRY|g" -e "s|{{VENDOR}}|$VENDOR|g" \
        -e "s|{{MODELNAME}}|$MODELNAME|g" -e "s|{{UNIT}}|$UNIT|g" \
        -e "s|{{POCNAME}}|$(basename "$POCFILE")|g" -e "s|{{RC}}|$RC|g" \
        -e "s|{{KLASS}}|$KLASS|g" -e "s|{{MARKER}}|$MARKER|g" \
        -e "s|{{MODEL}}|$MODEL|g" \
        "$SCRIPTS/repro-prompt.md" > "$REP/.agent-run/prompt.rendered.md"
    echo "[repro] launching static organizer agent (timeout ${AGENT_TIMEOUT}s, cwd $ENTRY)"
    set +e
    (
        set -a; . "$ROOT/.env"; set +a
        cd "$ENTRY"
        env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH \
            -u CLAUDE_CODE_MESSAGING_SOCKET -u CLAUDE_CODE_MESSAGING_TOKEN \
            -u CLAUDE_CODE_SESSION_ID -u CLAUDE_CODE_SESSION_ATTENDED \
            -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_PID -u CLAUDE_EFFORT -u AI_AGENT \
            IS_SANDBOX=1 \
            bash -c '
set -u
TO="$2"; MARKER="$3"; EFF="$4"
rm -f "$MARKER"
START=$(date +%s)
setsid claude -p "$(cat "$1")" --effort "$EFF" --dangerously-skip-permissions &
PID=$!
(   while kill -0 "$PID" 2>/dev/null; do
        sleep 5
        if [ $(( $(date +%s) - START )) -ge "$TO" ]; then
            touch "$MARKER"
            kill -TERM -- "-$PID" 2>/dev/null; sleep 30
            kill -KILL -- "-$PID" 2>/dev/null; exit 0
        fi
    done ) &
WD=$!
wait "$PID"; RC=$?
kill "$WD" 2>/dev/null
[ -f "$MARKER" ] && exit 124 || exit "$RC"
' _ "$REP/.agent-run/prompt.rendered.md" "$AGENT_TIMEOUT" "$REP/.agent-run/.timed-out" high
    ) 2>&1 | tee -a "$REP/.agent-run/agent.log"
    AGENT_RC=${PIPESTATUS[0]}
    set -e
    if [ -s "$REP/REPRO.md" ]; then
        echo "[repro] REPRO.md written (agent rc=$AGENT_RC)"
    else
        echo "[repro] WARN: agent produced no REPRO.md (rc=$AGENT_RC) — video uses template captions"
    fi
fi

python3 "$SCRIPTS/repro-video.py" "$ENTRY" --rc "$RC" --attempts "$ATTEMPT" \
    || { echo "[-] render failed" >&2; exit 1; }
python3 - "$ENTRY" "$RC" "$ATTEMPT" "$BOOT_S" "$CTR" "$IMAGE" "$PORT" "$LEDGER" <<'EOF'
import json, sys, os, hashlib, datetime
entry, rc, att, boots, ctr, image, port, led = sys.argv[1:9]
rep = os.path.join(entry, "repro")
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
files = {}
for n in sorted(os.listdir(rep)):
    p = os.path.join(rep, n)
    if os.path.isfile(p):
        files[n] = {"bytes": os.path.getsize(p), "sha256": sha(p)}
meta = json.load(open(os.path.join(entry, "meta.json")))
rj = json.load(open(os.path.join(rep, "report.json")))
n_ev = sum(1 for _ in open(os.path.join(rep, "session.jsonl"), encoding="utf-8", errors="replace"))
info = {
    "state": "done", "ts": rj.get("ts"), "rc": int(rc), "vault_rc": int(meta.get("rc")),
    "attempts": int(att), "boot_s": int(boots), "container": ctr, "image": image,
    "port": int(port), "session_events": n_ev,
    "stdout_lines_retimed": True,
    "attempts_ledger": [json.loads(l) for l in open(led) if l.strip()]
                       if os.path.exists(led) else [],
    "video": files.get("repro.mp4", {}), "files": files,
    "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
}
json.dump(info, open(os.path.join(rep, "repro.json"), "w"), indent=1)
meta["repro"] = {"state": "done", "video": "repro/repro.mp4", "srt": "repro/repro.srt",
                 "rc": int(rc), "at": info["at"]}
json.dump(meta, open(os.path.join(entry, "meta.json"), "w"), indent=2, ensure_ascii=False)
print("[repro] done: %s/repro/repro.mp4 (%d bytes) events=%d boot=%ss" % (
    entry, files.get("repro.mp4", {}).get("bytes", 0), n_ev, boots))
EOF
exit 0
