#!/bin/bash
# agent-scan :: emu — drive the solved firmware emulation from inside the container
#
# Baked into task:<name>:solved images next to the one-click entrypoint
# (solved-entrypoint). Where that entrypoint boots the verified emulation
# unattended, `emu` exposes the same machinery to an agent or a human:
#
#   emu run        normal boot; waits for the web service, prints IP + URL
#   emu debug      debug boot; guest root backdoor: nc <ip> 31337 / telnet 31338
#   emu boot       gdb-frozen boot (-s -S); gdbserver on :1234, attach + continue
#   emu analyze    analysis boot (verbose kernel logging — watch `emu serial -f`)
#   emu stop       clean stop: TERM -> grace -> KILL; run.sh tears down its tap
#   emu status     mode / QEMU pids / uptime / IP / web / backdoor port
#   emu serial     tail the serial log (-f to follow)
#   emu ip         print the guest IP
#   emu verify     deterministic harness verification (hverify) — acceptance,
#                  not a boot: it restarts from a clean state and KILLS QEMU
#                  when it passes, leaving a clean container behind
#
# Each mode execs the pre-rendered scratch/<iid>/run_<mode>.sh symlink in the
# background (RUN_MODE switches on basename $0), from /opt/FirmAE-pro — never
# from inside scratch/, whose relative paths would double. Mode switches
# rewrite the guest's /firmadyne/debug.sh, so run/debug/boot/analyze may be
# interleaved freely as long as each boot is stopped first (emu enforces this).
# State lives in /tmp/emu: mode, launcher pid, boot.log.
#
# Env: EMU_WEB_TIMEOUT   seconds to wait for the service (default 300)
set -u

FIRMAE=/opt/FirmAE-pro
STATE=/tmp/emu
WEB_TIMEOUT=${EMU_WEB_TIMEOUT:-300}
GRACE=30   # after this, a missing QEMU means the boot itself broke

iid() { ls "$FIRMAE/scratch" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -1; }

# anchored pattern — matches only QEMU itself, never a command line that
# happens to mention it. Zombie QEMUs are dead (hold no tap/IP), see hverify.
qemu_pids() {
    local p
    for p in $(pgrep -f '^qemu-system' 2>/dev/null); do
        [ "$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)" != "Z" ] && echo "$p"
    done
    return 0
}
qemu_alive() { [ -n "$(qemu_pids)" ]; }

ensure_pg() {
    pg_isready -q -h 127.0.0.1 2>/dev/null && return 0
    service postgresql start >/dev/null 2>&1 || true
    local _
    for _ in $(seq 1 30); do
        pg_isready -q -h 127.0.0.1 2>/dev/null && return 0
        sleep 1
    done
    echo "emu: PostgreSQL failed to start" >&2
    return 1
}

port_open() { timeout 2 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
web_code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$1/" 2>/dev/null; }

# ---------------------------------------------------------------------------
# start <run|debug|boot|analyze>
# ---------------------------------------------------------------------------
cmd_start() {
    local mode="$1"
    local IID; IID=$(iid)
    [ -n "$IID" ] || { echo "emu: no scratch dir under $FIRMAE/scratch" >&2; return 1; }
    local dir="$FIRMAE/scratch/$IID"
    [ -f "$dir/run.sh" ] || { echo "emu: $dir/run.sh missing" >&2; return 1; }
    [ -f "$dir/image.raw" ] || { echo "emu: $dir/image.raw missing" >&2; return 1; }
    if qemu_alive; then
        echo "emu: already running (mode=$(cat "$STATE/mode" 2>/dev/null || echo '?')) — emu stop first" >&2
        return 1
    fi
    ensure_pg || return 1

    # FirmAE ships run/debug/boot/analyze symlinks; recreate defensively —
    # ln -sf is idempotent and costs nothing. NOTE: mode `run` has no
    # run_run.sh — plain run.sh IS the run mode (RUN_MODE=basename).
    ln -sf ./run.sh "$dir/run_debug.sh"
    ln -sf ./run.sh "$dir/run_boot.sh"
    ln -sf ./run.sh "$dir/run_analyze.sh"
    local entry="$dir/run.sh"
    [ "$mode" = run ] || entry="$dir/run_${mode}.sh"

    mkdir -p "$STATE"
    local IP; IP=$(cat "$dir/ip" 2>/dev/null || echo '?')
    echo "emu: starting iid=$IID mode=$mode ip=$IP (boot log: $STATE/boot.log)"

    # setsid: run.sh must outlive this emu invocation (docker exec exits);
    # the pid file is informational — QEMU pgrep is the source of truth
    ( cd "$FIRMAE" && exec setsid "$entry" >"$STATE/boot.log" 2>&1 ) &
    echo "$!" > "$STATE/pid"
    echo "$mode" > "$STATE/mode"

    if [ "$mode" = run ] || [ "$mode" = debug ]; then
        local start elapsed code
        start=$(date +%s)
        while :; do
            sleep 5
            elapsed=$(( $(date +%s) - start ))
            if [ "$elapsed" -ge "$GRACE" ] && ! qemu_alive; then
                echo "emu: QEMU died during boot — last serial lines:" >&2
                tail -3 "$dir/qemu.final.serial.log" 2>/dev/null >&2
                return 1
            fi
            code=$(web_code "$IP")
            if [ "$code" = 200 ]; then
                echo "emu: web ready after ${elapsed}s — http://$IP/"
                [ "$mode" = debug ] && {
                    echo "  root shell : nc $IP 31337   (then: id, ls /, ...)"
                    echo "  telnet     : telnet $IP 31338"
                }
                return 0
            fi
            if [ "$mode" = debug ] && port_open "$IP" 31337; then
                echo "emu: backdoor ready after ${elapsed}s (web: $code)"
                echo "  root shell : nc $IP 31337   (then: id, ls /, ...)"
                echo "  telnet     : telnet $IP 31338"
                return 0
            fi
            [ "$elapsed" -ge "$WEB_TIMEOUT" ] && break
        done
        echo "emu: not ready after ${WEB_TIMEOUT}s — boot continues in background (emu status / emu serial -f)" >&2
        return 1
    fi

    if [ "$mode" = boot ]; then
        # -s -S: gdbserver on tcp:1234, CPU frozen until gdb continues
        local _
        for _ in $(seq 1 30); do port_open 127.0.0.1 1234 && break; sleep 1; done
        if port_open 127.0.0.1 1234; then
            echo "emu: gdbserver up on :1234, CPU frozen. Attach and continue:"
            echo "  gdb -ex 'target remote localhost:1234' -ex c"
            return 0
        fi
        echo "emu: gdbserver did not appear — check $STATE/boot.log" >&2
        return 1
    fi

    # analyze: output is the serial console
    echo "emu: analyze mode started — follow with: emu serial -f"
    return 0
}

# ---------------------------------------------------------------------------
cmd_stop() {
    if ! qemu_alive; then
        rm -f "$STATE/pid" "$STATE/mode"
        echo "emu: not running"
        return 0
    fi
    pkill -f '^qemu-system' 2>/dev/null || true
    # run.sh notices QEMU's exit, tears down its tap, and exits — give it time
    local _
    for _ in $(seq 1 30); do qemu_alive || break; sleep 1; done
    if qemu_alive; then
        pkill -9 -f '^qemu-system' 2>/dev/null || true
        sleep 2
    fi
    qemu_alive && { echo "emu: QEMU refuses to die" >&2; return 1; }
    # belt & braces: a stale tap would break the next boot (same sweep as the
    # entrypoint; taps live in this netns so they can only be ours)
    for t in $(ip -o link 2>/dev/null | awk -F': ' '$2 ~ /^tap[0-9]/ {print $2}'); do
        ip link del "$t" 2>/dev/null
    done
    rm -f "$STATE/pid" "$STATE/mode"
    echo "emu: stopped clean"
    return 0
}

cmd_status() {
    local IID; IID=$(iid)
    echo "iid      : ${IID:-none}"
    echo "mode     : $(cat "$STATE/mode" 2>/dev/null || echo '-')"
    if [ -n "$IID" ]; then
        echo "ip       : $(cat "$FIRMAE/scratch/$IID/ip" 2>/dev/null || echo '?')"
    fi
    if qemu_alive; then
        local p line
        for p in $(qemu_pids); do
            line=$(ps -o stat=,etimes= -p "$p" 2>/dev/null | head -1)
            echo "qemu     : pid $p (state ${line%% *}, up ${line##* }s)"
        done
        local IP; IP=$(cat "$FIRMAE/scratch/$IID/ip" 2>/dev/null)
        [ -n "$IP" ] && {
            echo "web      : HTTP $(web_code "$IP") at http://$IP/"
            port_open "$IP" 31337 && echo "backdoor : nc $IP 31337 OPEN" \
                                   || echo "backdoor : closed (run/debug mode only)"
        }
    else
        echo "qemu     : not running"
    fi
    return 0
}

cmd_serial() {
    local IID; IID=$(iid)
    [ -n "$IID" ] || { echo "emu: no scratch dir" >&2; return 1; }
    local log="$FIRMAE/scratch/$IID/qemu.final.serial.log"
    [ -f "$log" ] || { echo "emu: no serial log yet ($log)" >&2; return 1; }
    if [ "${1:-}" = "-f" ]; then exec tail -f "$log"; fi
    tail -n "${1:-50}" "$log"
    return 0
}

cmd_verify() {
    [ -x /usr/local/bin/hverify ] || { echo "emu: /usr/local/bin/hverify missing" >&2; return 1; }
    echo "emu: hverify restarts from a clean state and kills QEMU on PASS"
    exec env HARNESS_VERIFY_TIMEOUT="${EMU_VERIFY_TIMEOUT:-360}" /usr/local/bin/hverify
}

usage() {
    sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
    run)     shift; cmd_start run     "$@" ;;
    debug)   shift; cmd_start debug   "$@" ;;
    boot)    shift; cmd_start boot    "$@" ;;
    analyze) shift; cmd_start analyze "$@" ;;
    stop)    shift; cmd_stop  "$@" ;;
    status)  shift; cmd_status "$@" ;;
    serial)  shift; cmd_serial "$@" ;;
    ip)
        IID=$(iid)
        [ -n "$IID" ] || { echo "emu: no scratch dir" >&2; exit 1; }
        cat "$FIRMAE/scratch/$IID/ip" ;;
    verify)  shift; cmd_verify "$@" ;;
    *)       usage; exit 1 ;;
esac
