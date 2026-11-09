# agent-scan :: rehost

Turn stock IoT firmware into **harness-verified, one-click-bootable emulations**.
An autonomous agent patches the FirmAE-pro engine inside a per-task container
until the firmware's web service is genuinely reachable; the harness then
freezes that working state into a `:solved` Docker image.

This directory holds every script of the rehost stage. The two Dockerfiles
stay one level up (`scripts/Dockerfile.base`, `scripts/Dockerfile.task`) —
only their build instructions reference paths in here.

## Pipeline

```
 build-base.sh ───▶ firmae-base:latest            engine + tools, built once
                        │
 collect-firmware.sh ─▶ data/firmware/<vendor>/<model>/
   (collection agent        firmware  +  task.json  +  rootfs/  +  decompiled-rootfs/
    runs on the host)            │
                        │   agent-run.sh  [single task]   or
                        │   batch-run.sh  [whole tree, N parallel workers]
                        │         staging → build task-<id>:raw → run container
                        │         → agent patches engine → hverify (independent)
                        │         → result.json + output/
                        │                 │
                        │         (status=success only)
                        │         commit-solved.sh
                        │                 │
                        ▼                 ▼
                 (next task)      task-<id>:solved    frozen, one-click / lab mode
```

Three image tiers, deliberately:

1. **`firmae-base:latest`** — FirmAE-pro full source, binwalk (v2 module +
   v3 CLI dual-track), PostgreSQL with the schema pre-imported,
   Node + `claude` CLI. Built once; every task image derives from it.
2. **`task-<vendor__model>:raw`** — the agent's entire world: firmware +
   task.json in `/work`, analysis assets in `/home/{rootfs,decompiled-rootfs}`,
   engine in `/opt/FirmAE-pro` (a git repo — the working-tree diff *is* the
   patch). Ephemeral by design.
3. **`task-<id>:solved`** — the raw container after a verified success:
   cleaned of agent session state, committed with a static one-click
   entrypoint (pre-rendered QEMU launch, no DB lookups at boot).

## The verdict contract

Everything downstream keys off **`result.json`**, and the harness never
trusts the agent:

- Success means **`hverify`'s own** clean re-boot serves HTTP 200 to a plain
  `curl -sL` (redirects followed — a 302 to a login page is healthy). The
  agent's self-report is never sufficient.
- The agent is killed at its wall-clock budget; the **on-disk state is then
  verified as-is**. A timed-out agent whose engine state still boots and
  serves counts as success.
- Statuses: `success | fail | agent_timeout | agent_error | infra_error`
  (priority: harness truth > timeout marker > agent exit code).
- Only `success` promotes to `:solved`. Failed chains keep their container
  for diagnosis (serial logs, process tree, patch).

## Scripts

| Script | Role |
|---|---|
| `build-deps.sh` | Provision `deps/` (gitignored): pinned FirmAE-pro clone + the official Ghidra release zip, sha256-verified. Idempotent — validating installs are skipped. Host-side Ghidra needs JDK ≥ 21. |
| `build-base.sh` | Build `firmae-base:latest` from `../Dockerfile.base`. |
| `collect-firmware.sh` | Stage 1: a host-side collection agent finds the vendor's official sources, fetches the newest firmware per model, unpacks it (binwalk via the base image — same extractor as emulation), rejects what won't unpack, writes the model folder. Then a deterministic Ghidra mirror-decompile of every rootfs. Driver independently re-validates each folder. |
| `agent-run.sh` | Stage 2 driver for one task: staging → build `:raw` → run → install tools → run the agent under a watchdog → harness verify → harvest → `result.json`. |
| `commit-solved.sh` | Stage 3: promote a `success` container to `:solved` (guards, hygiene, commit, cleanup). Auto-chained by `batch-run.sh`. |
| `batch-run.sh` | Schedule a whole firmware tree: `--jobs N` work slots, skips tasks that already have `result.json` (delete it to retry), auto-promotes successes, per-task `batch.log`. Ctrl-C safe; resumable. |
| `batch-monitor.sh` | Live dashboard for a batch root. Everything on screen is real state: `docker ps` containers, `result.json` history, host-side QEMU→container phase attribution. |
| `run-solved.sh` | One-click boot of a `:solved` image (`--restart unless-stopped` self-healing). |
| `emu.sh` / `emu-shell.sh` | Lab mode: enter a solved image without booting, then drive the emulation — `emu run / debug (guest root backdoor) / boot (gdbserver) / analyze / stop / status / serial / ip / verify`. |
| `hverify.sh` | The harness verdict, also usable by the agent as self-check: clean re-boot, plain curl, only its own HTTP 200 passes. Baked/cp'd into every task container. |
| `emu-check.sh` | One-shot FirmAE-pro pipeline inside the container: extract → arch → image → network arbitration boots → final boot → web check. Result lands in `scratch/<iid>/result`. |
| `solved-entrypoint.sh` | The `:solved` ENTRYPOINT: start PostgreSQL, then exec the pre-rendered `run.sh`. |
| `docker-entrypoint.sh` | Base/task image ENTRYPOINT: start the baked PostgreSQL, then hand over to the container command. |
| `agent-prompt.md` | The emulation agent's mission brief (goal, environment, rules, deliverables). |
| `collect-prompt.md` | The collection agent's mission brief. |
| `ghidra-batch/` | Deterministic decompilation: `decompile-rootfs.sh` mirrors a whole rootfs (one `<function>_<addr>.c` per function, symlink farm navigable, resumable, per-ELF timeouts); `decompile-all.sh` does one binary. |
| `loop-shim/` | Parallel-safety shims (see below). |

## Parallel safety (`loop-shim/`)

Task containers share the host's `/dev`, and the kernel loop-device pool is
global. Unshimmed, concurrent agents kill each other three ways:
`losetup -Pf` free-device races, improvised `losetup -D` nukes, and
same-path collisions (every container's image is `scratch/1/image.raw`).
`agent-run.sh` installs `loop-shim/{losetup,kpartx}` into each container as
`/usr/local/sbin/{losetup,kpartx}` (PATH shadowing):

- a global cross-container `flock` on `/dev` serializes every loop mutation;
- attaches go through per-container hardlink aliases
  (`/tmp/loop-alias/<container-id>-N`) — globally unique path strings, so
  partition mounting can never claim another container's image;
- `losetup -D` is translated to "detach only loops this container
  registered"; listings are projected back to original paths and hide
  foreign rows.

With the shims installed, any number of tasks may run concurrently; without
them, `agent-run.sh` falls back to a host-wide serial lock. Validated by
direct loop-device stress tests and a real 3-parallel agent batch (72
attach/detach cycles, concurrent windows, zero interference).

## Usage

Prerequisites: Docker; `/dev/kvm` plumbed through (the generated QEMU command
line currently runs TCG — KVM is there for future speedups); JDK ≥ 21 on the
host for the Ghidra decompile phase; a repo-root `.env` with the LLM
credentials for the `claude` CLI (unquoted `KEY=VALUE` lines,
bash-sourceable). `deps/` is gitignored — `build-deps.sh` provisions it from
pinned sources (FirmAE-pro commit, Ghidra release checksum).

```bash
# 0 — provision deps/ and build the base image (once per machine)
bash scripts/rehost/build-deps.sh
bash scripts/rehost/build-base.sh

# 1 — collect a vendor's firmware (agent on the host, then decompile)
bash scripts/rehost/collect-firmware.sh tenda 20 data/firmware/tenda
#      exit 0 = outdir holds >= 20 valid model folders

# 2 — run one task (default agent budget 7200s)
bash scripts/rehost/agent-run.sh data/firmware/netgear/R7000
bash scripts/rehost/agent-run.sh --timeout 14400 data/firmware/netgear/R7000

# 2' — or the whole tree, 4 workers, 4h budgets, auto-promote
bash scripts/rehost/batch-run.sh --jobs 4 --timeout 14400 data/firmware/netgear
bash scripts/rehost/batch-monitor.sh data/firmware/netgear     # live view

# 3 — success promotes automatically; manually:
bash scripts/rehost/commit-solved.sh data/firmware/netgear/R7000

# 4 — solved lifecycle
bash scripts/rehost/run-solved.sh netgear__r7000                # one-click
docker run -dit --privileged --device /dev/kvm -v /dev:/dev \
    --entrypoint /usr/local/bin/emu-shell task-netgear__r7000:solved   # lab
#    inside: emu run | debug | boot | stop | ip | verify ...
```

Resuming: `batch-run.sh` skips any task folder that already has
`result.json`; delete that file to force a retry. Interrupted tasks have no
`result.json` and are rebuilt automatically.

## Task folder contract

Input — `data/firmware/<vendor>/<model>/`:

```
<firmware-file>      the stock firmware archive, named by task.json
task.json            brand, model, firmware, version, sha256, ... (+ agent fields)
rootfs/              unpacked root filesystem (static analysis asset)
decompiled-rootfs/   Ghidra mirror-decompile of rootfs/
```

Output, written by the driver (never the agent): `result.json` (status,
timestamps, agent details, harness verdict) and `output/`
(`agent-fixes.patch`, agent-updated `task.json`, `agent.log`,
`agent-transcripts.tar`, `harness_*`).

Timing reality: a single task runs minutes-to-hours under TCG — budget 1–4 h;
a solved image boots its web service in ~1–2 minutes.
