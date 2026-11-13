#!/bin/bash
# agent-scan :: deterministic harness-side verification (INSIDE the task container)
#
# Runs AFTER the agent exits. Trusts nothing the agent produced — no
# result/web/ping files, no task.yaml: those are the agent's claims, not
# evidence. Instead this script re-boots the firmware from a clean process
# state ONCE PER BOOT MODE and verifies the mode matrix that deterministic
# grading (scripts/taint/poc-run.sh) actually rides:
#
#   run    : web answers HTTP 200 with a real page     (BOF/DoS channels,
#            baseline — the classic success gate)
#   debug  : web 200 ∧ guest backdoor (telnetd 31338)  (the CI/canary
#            channel — grading boots here): executes `echo <nonce>` and
#            reads the nonce back — proves the /bin/a injection log is
#            READABLE end-to-end, not just that a port opens
#
# HARD GATE: harness_result=true only when BOTH modes pass; each mode
# gets its own verdict file so the agent sees the complete picture in one
# pass (no stop-at-first-failure). The kernel execve audit ("analyze") is
# NOT gated on: measured 2026-11-13 it only records the boot/initrd phase
# on our ARM and MIPS kernels and goes silent (or faults) at the root
# pivot, so no grading channel depends on it — debug is the CI mode.
#
# Exit 0 = verified; exit 1 = not verified (reason in harness_reason).
# Writes /work/output/{harness_result,harness_time_to_web,harness_ip,
# harness_http_size,harness_reason,harness_mode_{run,debug},
# harness_modes} for the host-side harvest.
#
# Env: HARNESS_VERIFY_TIMEOUT  per-mode boot budget in seconds (default 360)
set -u
FIRMAE=/opt/FirmAE-pro
OUT=/work/output
BUDGET=${HARNESS_VERIFY_TIMEOUT:-360}
GRACE=30   # seconds before we start treating a missing QEMU as a crash
mkdir -p "$OUT"

# SIGTERM, give QEMU a moment to tear down its block devices, then force.
# Patterns are anchored (^) so we only ever match QEMU itself — never an
# unrelated process whose command line merely mentions "qemu-system".
qemu_alive() {
    # zombie QEMUs (unreaped orphans) are dead — they hold no IP/tap and
    # must not count as "running"
    local p
    for p in $(pgrep -f '^qemu-system' 2>/dev/null); do
        [ "$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)" != "Z" ] && return 0
    done
    return 1
}

stop_qemu() {
    pkill -f '^qemu-system' 2>/dev/null
    sleep 2
    qemu_alive && pkill -9 -f '^qemu-system' 2>/dev/null
    return 0
}

fail() {  # fatal infra error: no verdict matrix possible
    echo "harness_verify=false"
    # always leave an explicit verdict file — a missing file must never be
    # mistaken for "not run yet" or inherited from a previous run
    echo false > "$OUT/harness_result"
    echo "$1" > "$OUT/harness_reason"
    [ -f /tmp/hverify-boot.log ] && cp /tmp/hverify-boot.log "$OUT/" 2>/dev/null
    echo "harness: FAIL ($1)"
    stop_qemu
    exit 1
}

IID=$(ls "$FIRMAE/scratch" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -1)
[ -n "$IID" ] || fail "no-scratch-dir"
WORK="$FIRMAE/scratch/$IID"
# candidate IPs, both spellings: inferNetwork writes plain `ip`, but
# makeNetwork writes `ip.0`, `ip.1`, ... when the LAN/web sits on a numbered
# interface (observed on W30E: emulation healthy, harness aborted at the
# lookup without ever booting). The web service may answer on any interface,
# so every candidate is polled and the answering one is recorded.
IPS=()
_ipfile() { local v; v=$(cat "$1" 2>/dev/null); [ -n "$v" ] && IPS+=("$v"); return 0; }
_ipfile "$WORK/ip"
for f in "$WORK"/ip.[0-9]*; do
    [ -f "$f" ] && _ipfile "$f"
done
[ ${#IPS[@]} -gt 0 ] || fail "no-ip-for-iid-$IID"
[ -f "$WORK/run.sh" ] || fail "no-run-sh"
[ -f "$WORK/image.raw" ] || fail "no-image-raw"
# mode symlinks: run.sh switches on basename $0 ("debug" -> guest backdoor).
# FirmAE ships them; recreate defensively.
ln -sf ./run.sh "$WORK/run_debug.sh"

echo "harness: verifying iid=$IID ip=${IPS[*]} mode-matrix=run,debug (budget ${BUDGET}s each)"

del_taps() {
    for t in $(ip -o link 2>/dev/null | awk -F': ' '$2 ~ /^tap[0-9]/ {print $2}'); do
        ip link del "$t" 2>/dev/null
    done
}

boot_and_wait_web() {  # boot_and_wait_web <entry> -> echo "<elapsed> <ip> <size>"
    local entry="$1"
    # clean slate between modes: a stale QEMU would hold the tap/IP and mask
    # a broken final state
    stop_qemu; del_taps
    # boot: run.sh resolves its paths relative to FIRMAE_DIR — must cd there
    # (running it from inside scratch/<iid>/ doubles the relative path)
    cd "$FIRMAE" || return 1
    "./scratch/$IID/$entry" > /tmp/hverify-boot.log 2>&1 &
    local start elapsed code size IP
    start=$(date +%s)
    while :; do
        sleep 5
        elapsed=$(( $(date +%s) - start ))
        [ "$elapsed" -ge "$BUDGET" ] && return 1
        if [ "$elapsed" -ge "$GRACE" ] && ! qemu_alive; then
            return 1
        fi
        # Redirects are followed: a vendor admin UI 302-ing / to its login
        # page is a healthy web service; redirect loops / dead targets still
        # fail naturally (curl error -> 000).
        for IP in ${IPS[@]+"${IPS[@]}"}; do
            code=$(curl -sL --max-redirs 5 -o /tmp/hverify-page.html -w '%{http_code}' \
                        --max-time 8 "http://$IP/" 2>/dev/null)
            if [ "$code" = "200" ]; then
                size=$(wc -c < /tmp/hverify-page.html)
                [ "$size" -gt 100 ] || return 1
                echo "$elapsed $IP $size"
                return 0
            fi
        done
    done
}

backdoor_ok() {  # backdoor_ok <ip> — real exec round-trip via telnetd 31338
    local ip="$1"
    {
        exec 3<>/dev/tcp/"$ip"/31338 || exit 1
        printf 'echo HVNOK7x\r\n' >&3
        sleep 1
        timeout 3 cat <&3
    } 2>/dev/null | grep -aq HVNOK7x
}

declare -A VERDICT
for m in run debug; do VERDICT[$m]="fail:not-run"; done

# ---------------------------------------------------------------- run ------
# boot log tail for reasons
echo "harness: [1/2] mode run"
if R=$(boot_and_wait_web run.sh); then
    read -r WEB_T WEB_IP WEB_SIZE <<<"$R"
    VERDICT[run]="pass"
    echo "  run PASS — HTTP 200 ${WEB_SIZE}B from $WEB_IP after ${WEB_T}s"
else
    VERDICT[run]="fail:web-not-serving"
    echo "  run FAIL — $(tail -1 /tmp/hverify-boot.log 2>/dev/null)"
fi

# -------------------------------------------------------------- debug ------
echo "harness: [2/2] mode debug (web + backdoor exec)"
if R=$(boot_and_wait_web run_debug.sh); then
    read -r D_T D_IP D_SIZE <<<"$R"
    bok=0
    for _t in 1 2 3; do
        backdoor_ok "$D_IP" && { bok=1; break; }
        sleep 5
    done
    if [ "$bok" = 1 ]; then
        VERDICT[debug]="pass"
        echo "  debug PASS — web ${D_SIZE}B after ${D_T}s, backdoor exec confirmed on $D_IP"
    else
        VERDICT[debug]="fail:backdoor-exec-unreachable"
        echo "  debug FAIL — web ok but telnetd 31338 exec check failed on $D_IP"
    fi
else
    VERDICT[debug]="fail:web-not-serving"
    echo "  debug FAIL — $(tail -1 /tmp/hverify-boot.log 2>/dev/null)"
fi

# clean shutdown before the host harvests / commits the solved image
stop_qemu

# ------------------------------------------------------------ verdict ------
ALLPASS=1
MODES=""
for m in run debug; do
    echo "${VERDICT[$m]}" > "$OUT/harness_mode_$m"
    MODES="$MODES $m=${VERDICT[$m]}"
    [ "${VERDICT[$m]}" = "pass" ] || ALLPASS=0
done
echo "$MODES" | sed 's/^ //' > "$OUT/harness_modes"

if [ "$ALLPASS" = 1 ]; then
    echo true > "$OUT/harness_result"
    echo "$WEB_T" > "$OUT/harness_time_to_web"
    echo "$WEB_IP" > "$OUT/harness_ip"
    echo "$WEB_SIZE" > "$OUT/harness_http_size"
    echo "harness: PASS — mode matrix complete:$MODES"
    exit 0
else
    # main web evidence still recorded when run-mode passed (useful for triage)
    if [ "${VERDICT[run]}" = "pass" ]; then
        echo "$WEB_T" > "$OUT/harness_time_to_web"
        echo "$WEB_IP" > "$OUT/harness_ip"
        echo "$WEB_SIZE" > "$OUT/harness_http_size"
    fi
    echo false > "$OUT/harness_result"
    echo "mode-matrix incomplete:$MODES" > "$OUT/harness_reason"
    echo "harness: FAIL — mode-matrix incomplete:$MODES"
    exit 1
fi
