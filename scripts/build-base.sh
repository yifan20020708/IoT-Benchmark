#!/bin/bash
# agent-scan :: build the firmae-base image
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker build -f "$ROOT/scripts/Dockerfile.base" -t firmae-base:latest "$ROOT"
