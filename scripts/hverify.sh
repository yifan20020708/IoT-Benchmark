#!/bin/bash
# agent-scan :: deterministic harness-side verification (INSIDE the task container)
#
# Runs AFTER the agent exits. Trusts nothing the agent produced — no
# result/web/ping files, no task.yaml: those are the agent's claims, not
# evidence. Instead this script re-boots the firmware from a clean process
# state using the pre-rendered scratch/<iid>/run.sh and checks the web
# service with plain curl (redirects followed — see the criterion note in
# the poll loop). Ground truth = live QEMU + HTTP 200 + a real page.
#
# Exit 0 = verified; exit 1 = not verified (reason in harness_reason).
# Writes /work/output/{harness_result,harness_time_to_web,harness_ip,
# harness_http_size,harness_reason} for the host-side harvest.
#
# Env: HARNESS_VERIFY_TIMEOUT  total budget in seconds (default 360)
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

fail() {
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
IP=$(cat "$FIRMAE/scratch/$IID/ip" 2>/dev/null)
[ -n "$IP" ] || fail "no-ip-for-iid-$IID"
[ -f "$FIRMAE/scratch/$IID/run.sh" ] || fail "no-run-sh"
[ -f "$FIRMAE/scratch/$IID/image.raw" ] || fail "no-image-raw"

echo "harness: verifying iid=$IID ip=$IP (budget ${BUDGET}s)"

# clean slate: the agent may have left anything running behind.
# A stale QEMU would hold the tap/IP and mask a broken final state.
stop_qemu
for t in $(ip -o link 2>/dev/null | awk -F': ' '$2 ~ /^tap[0-9]/ {print $2}'); do
    ip link del "$t" 2>/dev/null
done

# boot: run.sh resolves its paths relative to FIRMAE_DIR — must cd there
# (running it from inside scratch/<iid>/ doubles the relative path).
cd "$FIRMAE" || fail "cd-firmae"
./scratch/"$IID"/run.sh > /tmp/hverify-boot.log 2>&1 &

start=$(date +%s)
while :; do
    sleep 5
    elapsed=$(( $(date +%s) - start ))
    [ "$elapsed" -ge "$BUDGET" ] && fail "timeout-${BUDGET}s-no-web"
    # after the grace window, a missing QEMU means the boot itself broke
    if [ "$elapsed" -ge "$GRACE" ] && ! qemu_alive; then
        fail "qemu-died (boot log: $(tail -1 /tmp/hverify-boot.log 2>/dev/null))"
    fi
    # Redirects are followed: a vendor admin UI 302-ing / to its login page
    # is a healthy web service (nearly every router/NVR does this), and the
    # OLD plain-/-must-200 criterion pushed agents into binary-patching the
    # GUEST web server instead of emulating it faithfully. Redirect loops
    # and dead redirect targets still fail naturally (curl error -> 000).
    code=$(curl -sL --max-redirs 5 -o /tmp/hverify-page.html -w '%{http_code}' \
                --max-time 8 "http://$IP/" 2>/dev/null)
    if [ "$code" = "200" ]; then
        size=$(wc -c < /tmp/hverify-page.html)
        if [ "$size" -le 100 ]; then
            fail "tiny-page-${size}B"
        fi
        echo true    > "$OUT/harness_result"
        echo "$elapsed" > "$OUT/harness_time_to_web"
        echo "$IP"    > "$OUT/harness_ip"
        echo "$size"  > "$OUT/harness_http_size"
        echo "harness: PASS — HTTP 200, ${size}B from http://$IP/ after ${elapsed}s"
        # leave a clean, committable container behind (no running QEMU)
        stop_qemu
        exit 0
    fi
done
