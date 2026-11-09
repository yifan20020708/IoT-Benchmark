#!/bin/bash
# agent-scan :: build-deps.sh — provision the vendored dependencies under deps/
#
# deps/ is gitignored, so a fresh clone of agent-scan cannot build anything
# until deps/ is populated. This script provisions the two dependencies the
# rehost pipeline actually needs, at pinned versions:
#
#   deps/FirmAE-pro            engine source tree — the ONLY deps/ input of
#                              the docker builds (Dockerfile.base COPYs it;
#                              .dockerignore passes nothing else through).
#                              Everything else the image needs (binwalk v2
#                              module + v3 CLI, sasquatch, apt/pip tools) is
#                              installed by the Dockerfile itself from its
#                              own upstream pins — deps/ is not involved.
#   deps/ghidra_12.1.4_PUBLIC  Ghidra for the HOST-side deterministic rootfs
#                              decompilation (scripts/rehost/ghidra-batch).
#                              It never enters any docker image. Needs
#                              JDK >= 21 on the host (checked, warned).
#
# Anything else you may find lying under deps/ (binwalk-3.1.1/, FirmAE/,
# rea/, ...) is local reference material no build references.
#
# Usage: build-deps.sh [--force] [<dep> ...]
#   deps:    firmae-pro | ghidra      (default: both)
#   --force  re-provision even when present and validating
#
#   DEPS_DIR=<path>  env override for the target directory (default:
#                    <repo>/deps) — handy for testing the fresh path.
#
# Idempotent: an existing dep that validates against the pins below is left
# untouched. The pins are the reproducibility anchors:
#   firmae-pro : git commit (== origin/main at pin time)
#   ghidra     : official release zip, SHA-256 as published on the release
#                page (github.com/NationalSecurityAgency/ghidra)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPS="${DEPS_DIR:-$ROOT/deps}"

FIRMAE_REPO="https://github.com/Blackhole23-Lab/FirmAE-pro.git"
FIRMAE_COMMIT="0afd7c5ce7a46fbd3bf2f9bccfe600d29e47f4e4"

GHIDRA_VERSION="12.1.4"
GHIDRA_TAG="Ghidra_12.1.4_build"
GHIDRA_ZIP="Ghidra_12.1.4_PUBLIC_20260921.zip"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/${GHIDRA_ZIP}"
GHIDRA_SHA256="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_JAVA_MIN="21"

FORCE=0
want=()
while [ $# -gt 0 ]; do
    case "$1" in
        --force)     FORCE=1; shift ;;
        -h|--help)   sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           want+=("$1"); shift ;;
    esac
done
[ "${#want[@]}" -gt 0 ] || want=(firmae-pro ghidra)
mkdir -p "$DEPS"

# ---------------------------------------------------------------------------
java_check() {
    if ! command -v java >/dev/null 2>&1; then
        echo "[!] no 'java' on PATH — Ghidra headless needs JDK >= $GHIDRA_JAVA_MIN"
        echo "    e.g.: apt-get install -y openjdk-${GHIDRA_JAVA_MIN}-jdk"
        return 0
    fi
    local v
    v=$(java -version 2>&1 | head -1 | grep -oE '"[0-9]+' | tr -d '"' | head -1)
    if [ -z "$v" ] || [ "$v" -lt "$GHIDRA_JAVA_MIN" ]; then
        echo "[!] JDK too old for Ghidra $GHIDRA_VERSION (needs >= $GHIDRA_JAVA_MIN): $(java -version 2>&1 | head -1)"
    fi
}

# ---------------------------------------------------------------------------
firmae_pro() {
    local d="$DEPS/FirmAE-pro"
    if [ -d "$d/.git" ]; then
        local head dirty
        head=$(git -C "$d" rev-parse HEAD 2>/dev/null || true)
        dirty=$(git -C "$d" status --porcelain 2>/dev/null | wc -l)
        if [ "$head" = "$FIRMAE_COMMIT" ] && [ "$dirty" -eq 0 ]; then
            echo "[deps] FirmAE-pro: ok (pinned commit, clean tree) — skipping"
            return 0
        fi
        if [ "$FORCE" -eq 0 ]; then
            echo "[-] $d exists but does not match the pin (HEAD=${head:-none}, dirty=$dirty)." >&2
            echo "    Resolve manually, or rerun with --force to re-clone from scratch." >&2
            return 1
        fi
    elif [ -e "$d" ] && [ "$FORCE" -eq 0 ]; then
        echo "[-] $d exists but is not a git checkout. Rerun with --force." >&2
        return 1
    fi

    rm -rf "$d"
    echo "[deps] cloning FirmAE-pro @ ${FIRMAE_COMMIT:0:8} ..."
    git clone -q "$FIRMAE_REPO" "$d"
    git -C "$d" checkout -q -B main "$FIRMAE_COMMIT"

    # post-conditions: the commit AND the layout the builds assume
    [ "$(git -C "$d" rev-parse HEAD)" = "$FIRMAE_COMMIT" ] \
        || { echo "[-] clone landed on the wrong commit" >&2; return 1; }
    local p
    for p in binaries/kernels sources core/unstuff install.sh; do
        [ -e "$d/$p" ] || { echo "[-] cloned tree misses '$p' — upstream layout changed?" >&2; return 1; }
    done
    echo "[deps] FirmAE-pro: provisioned ($(git -C "$d" rev-parse --short HEAD), $(du -sh "$d" | cut -f1))"
}

# ---------------------------------------------------------------------------
ghidra() {
    local d="$DEPS/ghidra_${GHIDRA_VERSION}_PUBLIC"
    if [ -f "$d/Ghidra/application.properties" ] \
       && grep -q "application.version=$GHIDRA_VERSION" "$d/Ghidra/application.properties" 2>/dev/null \
       && [ -x "$d/support/analyzeHeadless" ]; then
        echo "[deps] ghidra: ok ($GHIDRA_VERSION, analyzeHeadless present) — skipping"
        java_check
        return 0
    fi
    if [ -e "$d" ] && [ "$FORCE" -eq 0 ]; then
        echo "[-] $d exists but does not validate. Rerun with --force to re-provision." >&2
        return 1
    fi

    (
        set -e
        tmp=$(mktemp -d /tmp/agent-scan-ghidra.XXXXXX)
        trap 'rm -rf "$tmp"' EXIT

        echo "[deps] downloading $GHIDRA_ZIP (~500MB) ..."
        curl -fSL --retry 3 -o "$tmp/$GHIDRA_ZIP" "$GHIDRA_URL"

        echo "[deps] verifying sha256 ..."
        echo "$GHIDRA_SHA256  $tmp/$GHIDRA_ZIP" | sha256sum -c - \
            || { echo "[-] sha256 mismatch — not the pinned release" >&2; \
                 echo "    (a corrupted transfer lands here; nothing was touched — just rerun)" >&2; exit 1; }

        echo "[deps] extracting ..."
        unzip -q "$tmp/$GHIDRA_ZIP" -d "$tmp/x"
        [ -d "$tmp/x/ghidra_${GHIDRA_VERSION}_PUBLIC" ] \
            || { echo "[-] unexpected zip layout (no ghidra_${GHIDRA_VERSION}_PUBLIC/ top dir)" >&2; exit 1; }

        # stage + validate BEFORE replacing anything: an interrupted run
        # must leave an existing install untouched
        rm -rf "${d}.incoming"
        mv "$tmp/x/ghidra_${GHIDRA_VERSION}_PUBLIC" "${d}.incoming"
        grep -q "application.version=$GHIDRA_VERSION" "${d}.incoming/Ghidra/application.properties"
        [ -x "${d}.incoming/support/analyzeHeadless" ] \
            || { echo "[-] analyzeHeadless missing after extract" >&2; exit 1; }

        rm -rf "$d"
        mv "${d}.incoming" "$d"
        echo "[deps] ghidra: provisioned ($GHIDRA_VERSION, $(du -sh "$d" | cut -f1))"
    ) || return 1
    java_check
}

# ---------------------------------------------------------------------------
rc=0
for dep in "${want[@]}"; do
    case "$dep" in
        firmae-pro|firmae_pro|FirmAE-pro) firmae_pro || rc=1 ;;
        ghidra|Ghidra)                    ghidra      || rc=1 ;;
        *) echo "[-] unknown dep: $dep (firmae-pro | ghidra)" >&2; rc=1 ;;
    esac
done
exit $rc
