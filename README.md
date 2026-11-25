# agent-scan

Turn stock IoT firmware into **verified emulations**, let autonomous
agents **hunt vulnerabilities in them**, then **turn each proven PoC into a
working exploit** — with every verdict produced by a deterministic grader
that needs neither a human nor an LLM. Three stages, one repo, one direction
of trust: agents may claim anything, the harness re-checks everything.

| stage | directory | input | output |
|---|---|---|---|
| **rehost** | `scripts/rehost/` | stock vendor firmware | `task-<id>:solved` — one-click-bootable emulation images |
| **taint** | `scripts/taint/` | a `:solved` image | `data/round/` — the findings vault: PoC + evidence + report per hit |
| **exploit** | `scripts/exploit/` | a vault PoC + its `:solved` image | `<entry>/exploit/` — working exp + writeup + flag-compare verdict per PoC |

Each stage has its own README with full detail; this one is the umbrella.

## Pipeline

```
 vendor website
             │
             │    collect-firmware.sh  (host agent: official vendor
             ▼    sources only → unpack → Ghidra mirror-decompile)
┌──────────────────────────────────────────────────────────────────────┐
│  data/firmware/<vendor>/<model>/   ·   the TASK                      │
│    firmware · task.json · rootfs/ · decompiled-rootfs/               │
└──────────────────────────────────────────────────────────────────────┘
             │
             │    agent-run.sh / batch-run.sh --jobs N  (one worker
             ▼    per task)
╔═══════════════════════ REHOST — make it boot ════════════════════════╗
║                                                                      ║
║  task-<id>:raw   the agent's whole world: it patches the             ║
║                  FirmAE-pro engine in place — the git                ║
║                  working-tree diff IS the patch · a wall-            ║
║                  clock watchdog; when it fires, the on-              ║
║                  disk state is graded as-is                          ║
║             │                                                        ║
║             ▼                                                        ║
║     ┌────────────────┐   run   : curl -sL → HTTP 200                 ║
║     │ hverify · GATE │   debug : web + backdoor 31338                ║
║     │ 2 clean boots  │   echoes a command round-trip                 ║
║     └───────┬────────┘   the harness re-boots and checks             ║
║      pass ──┤            with its own hands — the agent              ║
║             │            is never trusted · fail → the               ║
║             │            container is kept for diagnosis             ║
║             ▼                                                        ║
║  task-<id>:solved  frozen · one-click boot · lab mode (emu)          ║
║                                                                      ║
╚════════════╤═════════════════════════════════════════════════════════╝
             │
             │    mapper-run.sh / mapper-batch.sh   (Phase-1)
             ▼
╔═════════════════ TAINT — map it, hunt it, grade it ══════════════════╗
║                                                                      ║
║  MAP      Phase-1 · one Mapper agent per model → the                 ║
║           work packages: boundary binaries · dispatch                ║
║           routes · a proven auth recipe · per-function               ║
║           source/getter call sites                                   ║
║             │                                                        ║
║             │            hunt-batch.sh --parallel N   (Phase-2)      ║
║             ▼                                                        ║
║  HUNT     Phase-2 · ONE agent container per function unit            ║
║           — static leads → own hypotheses → PoCs · two               ║
║           lenses: the call graph, and stored state read              ║
║           back by a LATER request · the poc archive is               ║
║           the only artifact ever replayed                            ║
║             │                                                        ║
║             ▼                                                        ║
║  VERIFY   LLM-free scoring: one FRESH container + boot               ║
║           PER poc → poc-run.sh replay · rc 0 (CI/BOF) and            ║
║           rc 2 (DoS) are graded HITS · all else is not               ║
║             │                                                        ║
║             ▼                                                        ║
║  REPORT   report-agent.sh → vault entry + REPORT.md +                ║
║           AUDIT.json · 3-tier confidence DERIVED from the            ║
║           audit dimensions, never agent-asserted                     ║
║                                                                      ║
╚════════════╤═════════════════════════════════════════════════════════╝
             │
             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  data/round/<vendor>/<model>/   ·   THE FINDINGS VAULT               │
│    one append-only entry per graded hit:                             │
│      poc · evidence · meta.json · REPORT.md · AUDIT.json             │
│    round-view.py → one self-contained HTML ledger                    │
│      (--serve PORT: live — hits land on the page alone)              │
└──────────────────────────────────────────────────────────────────────┘
             │
             │    exploit-run.sh / exploit-batch.sh --jobs N
             ▼    (one vault PoC per worker)
╔═════════════════ EXPLOIT — turn the PoC into RCE ════════════════════╗
║  One :solved image derives TWO containers joined by a shared         ║
║  volume — the only agent↔target channel:                             ║
║    target · flag injected into the guest disk · boots RUN mode       ║
║             (no backdoor) · the exp runs dropped to nobody           ║
║    agent  · vault PoC + REPORT + decompile · writes the exp ·        ║
║             may boot a local flag-less copy to debug                 ║
║              │                                                       ║
║              ▼                                                       ║
║  GRADE    LLM-free: a FRESH target + FRESH random flag per           ║
║           attempt · the exp reads the flag by PATH, never the        ║
║           value · byte-compare ⇒ EXPLOITED / NOT_EXPLOITED ·         ║
║           infra-scoped boot retry, never a goalpost move             ║
║              │                                                       ║
║              ▼                                                       ║
║  ARCHIVE  every outcome → <entry>/exploit/: writeup.md (exploit      ║
║           writeup, or an honest gap report) + grade-result.json      ║
║           + evidence/ · the working exp too on EXPLOITED             ║
╚════════════╤═════════════════════════════════════════════════════════╝
             │
             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  <entry>/exploit/   ·   back into the vault entry                    │
│    exp (on EXPLOITED) · writeup.md · grade-result.json · evidence/   │
└──────────────────────────────────────────────────────────────────────┘
```

## The contracts

The design rules that hold across all three stages — each is enforced by a
script, not by convention:

- **The grader is deterministic and LLM-free.** The final scoring standard
  *is* `poc-run.sh`'s exit code, replayed by `verify-run.sh` in a fresh
  container with the CURRENT copy of the script. Same for promotion in
  rehost: `hverify`'s own clean re-boot, never the agent's self-report.
  Agent judgment shapes the *search*; it never decides the *verdict*.
- **Exactly three graded vulnerability classes**: command injection (the
  `/bin/a` canary record in the guest injection log), memory corruption (a
  NEW fatal-signal line in the run window), DoS (a liveness delta with no
  crash line and no reboot). Info-leaks and auth-bypasses have no
  deterministic oracle here and are not findings.
- **The current script is the grader.** `poc-run.sh` and the decompiled
  rootfs are `docker cp`-injected when an agent container is derived —
  never baked into images — so every grading replays the script as it
  stands on disk today.
- **One poc per fresh boot.** A destructive poc poisons its container's
  writable layer in place; the reset button is a new container (which
  `verify-run.sh` creates per poc). And FirmAE's "reboot" interception is
  an in-place init restart — no second kernel banner ever appears — so
  window attribution, never banners, is the only truth.
- **The exploit verdict is a flag compare, LLM-free.** `exploit-run.sh
  grade` boots a FRESH target with a FRESH random flag
  (`flag{HMAC-SHA256(seed, run_id)[:32]}`), runs the exp dropped to
  `nobody`, and byte-compares the flag it reads out. The exp hardcodes the
  flag PATH, never the value, so a fresh flag replays cleanly; the seed
  lives only in host `state.json`. A target that never boots is retried
  (infra) — the bar itself never moves. An optional static LLM-judge
  (`--llm-judge`, default off) then gates a *proven* exploit on causal
  necessity + anti-cheat (`LEGITIMATE`/`ILLEGITIMATE`); it reviews the code,
  never re-grades the flag compare, and an illegitimate verdict downgrades
  the entry without touching the deterministic verdict.
- **Measured engine defects are design constraints.** The kernel execve
  audit (`[ANALYZE]` lines) records only the boot phase and goes silent or
  page-faults after the root pivot (measured on ARM and MIPS alike) —
  therefore no pipeline stage relies on `emu analyze`; everything rides
  `emu debug`, where all three grading channels exist.
- **Agents are scoped; drivers own the outputs.** An agent never sees
  Dockerfiles, `.env`, or host infrastructure. `result.json`, work-folder
  contracts and the vault are written by driver scripts; the vault is
  append-only and never overwrites a landed hit.

## Repository layout

```
agent-scan/
  scripts/
    Dockerfile.base       firmae-base image definition (built once)
    Dockerfile.task       per-task raw image definition
    round-view.py         the vault dashboard — cross-stage read layer
    rehost/               stage 1 — collect, rehost, solved lifecycle
    taint/                stage 2 — mapper, hunt, verify, vault
    exploit/              stage 3 — PoC → working exp, flag-compare grade
  data/                   gitignored — all generated state
    firmware/<vendor>/<model>/    task inputs (written by stage 1's collect)
    round/<vendor>/<model>/       the findings vault (+ dashboard.html)
    exploit/<vendor>/<model>/     stage-3 process files (state.json w/ seed)
  deps/                   gitignored — pinned FirmAE-pro + Ghidra release
  .env                    gitignored — LLM credentials (template: .env.example)
```

## Setup

Prerequisites: Docker; `/dev/kvm` + `/dev` plumbed through (the generated
QEMU command line currently runs TCG — KVM is there for future speedups);
JDK ≥ 21 on the host for the Ghidra decompile phases; a repo-root `.env`
with credentials for the `claude` CLI against an Anthropic-compatible
endpoint. `.env.example` documents the format: unquoted `KEY=VALUE` lines,
bash-sourceable. **Single-token policy: one token, one endpoint — no
failover proxy.** The credentials are sourced by host-side drivers
(collection, rehost, report) and passed into task/hunt containers via
`docker run --env-file`.

Build the shared base image once per machine:

```bash
bash scripts/rehost/build-deps.sh    # provisions deps/ (pinned, sha256-verified)
bash scripts/rehost/build-base.sh    # builds firmae-base:latest
```

## Usage

The canonical path through the whole pipeline (stage READMEs carry every
flag and the resuming rules):

```bash
# 1 — collect a vendor's firmware (host agent; unpacks + mirror-decompiles)
bash scripts/rehost/collect-firmware.sh tenda 20 data/firmware/tenda

# 2 — rehost the tree: N workers, auto-promote successes to :solved
bash scripts/rehost/batch-run.sh --jobs 4 --timeout 14400 data/firmware/tenda
bash scripts/rehost/batch-monitor.sh data/firmware/tenda      # live view

# 3 — map (Phase-1): one model, or the whole vendor
bash scripts/taint/mapper-run.sh data/firmware/tenda/W30EV2.0
bash scripts/taint/mapper-batch.sh --jobs 2 data/firmware/tenda

# 4 — hunt + grade (Phase-2): one unit by hand, or the whole model
bash scripts/taint/hunt-run.sh --timeout 3600 data/firmware/tenda/W30EV2.0 \
    bin__httpd__formSetAcAdvanced
bash scripts/taint/verify-run.sh data/firmware/tenda/W30EV2.0 bin__httpd__formSetAcAdvanced
bash scripts/taint/hunt-batch.sh --parallel 2 --timeout 3600 data/firmware/tenda/W30EV2.0
bash scripts/taint/hunt-batch-monitor.sh data/firmware/tenda/W30EV2.0

# 5 — exploit (stage 3): PoC → working exp, graded on a fresh target + flag
bash scripts/exploit/exploit-run.sh run --timeout 3600 \
    --image task-tenda__w30ev2.0:solved --entry data/round/tenda/W30EV2.0/<poc-entry>
bash scripts/exploit/exploit-batch.sh --jobs 8 --timeout 28800 data/round
bash scripts/exploit/exploit-batch-monitor.sh data/round    # live view

# 6 — the vault as one self-contained page
python3 scripts/round-view.py                 # data/round/dashboard.html
python3 scripts/round-view.py --serve 8080    # live: hits appear by themselves
```

Lab mode and hand grading (a solved image is a normal docker container):

```bash
bash scripts/rehost/run-solved.sh tenda__w30ev2.0          # one-click boot
docker exec <ctr> poc-run /work/poc/whatever.py; echo rc=$?  # grade one poc
```

Timing reality: a rehost task runs minutes-to-hours under TCG (budget
1–4 h); a hunt unit's default budget is 1 h; an exploit agent's is 1 h
(batch 8 h); verify and grade each cost one TCG boot (~1 core) per
attempt, parallelized.

## Data layout

Written by the drivers, never by agents directly:

```
data/firmware/<vendor>/<model>/
  firmware + task.json          the task (collect stage)
  rootfs/ + decompiled-rootfs/  static-analysis assets (one .c per function)
  taint-work-output/            Phase-1 contract deliverables
  taint-work/                   Phase-1 scratch + standing tools (cached)
  hunt-output/functions/<unit>/ pocs/ + evidence/ + verify/ + run/
  output/ + result.json         rehost harvest

data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/
  poc + evidence/ + meta.json   the graded hit (append-only)
  REPORT.md + AUDIT.json        static-only report agent output; the
                                archiver extends AUDIT.json with the
                                deterministic finality + derived confidence
  exploit/                      stage-3 archive: exp (on EXPLOITED) +
                                writeup.md + grade-result.json + evidence/

data/exploit/<vendor>/<model>/<entry-name>/
  state.json                    HOST secret: seed + expected_flag (gitignored)
  agent/ + exec/ + grade/       exp source, dev feedback, every grade attempt
```

## The dashboard

`scripts/round-view.py` is the vault's read layer — one self-contained
HTML ledger over ALL of `data/round` (deterministic, stdlib-only, zero
external requests — inline CSS/JS/markdown-renderer, works from `file://`;
the embedded template lives in the script — no side-car assets). It sits
at the scripts top level because it is the cross-stage display surface
(rehost / taint / exploit), not a tool of any one stage.

Security-desk layout, TWO TIERS routed on `#/v/<vendor>/m/<model>`:
tier 1 = fleet overview (vendor dropdown rail, the two ratio rings and
direct CONFIRMED∩0-DAY / CONFIRMED∩N-DAY cross-counts with per-class
CI/BOF/DoS tallies — the one-dim rings cannot express the intersection;
one card per model — status ratio ring with the total in the hub, paired
0-DAY|N-DAY and CONFIRMED|REJECTED stat boxes, class chips, handler
count); tier 2 = that model's hit ledger (search + listbox filters
Novelty/Status/Attribution/Class; cards carry status dot, class, flow
chip direct/cross, novelty with unverified-CVE flag, TOKEN/WINDOW,
marker, graded date). The right drawer holds a meta grid (verdict ·
finality · status · confidence · novelty · marker · class · flow ·
graded) and tabs *Evidence audit · PoC · Report · Repro* — the entry's
full REPORT.md, AUDIT.json dimensions and exact poc bytes embedded; the
Repro tab (CONFIRMED ∩ 0-DAY entries only) plays the live-replay video
inline with a download link (bytes + sha256 shown), the repro.json
machine facts, the decisive serial lines verbatim, the full downloadable
attachment manifest and the rendered REPRO.md. Status is CONFIRMED /
REJECTED only: high|medium ⇒ CONFIRMED, low ⇒ REJECTED (confidence
grades the attribution chain, never reality).

Plain run rebuilds `<root>/dashboard.html` atomically (snapshot — re-run
after new hits); `--serve PORT` serves it LIVE: every request rescans
the vault and the page polls `/__data__` (state-hash ts) every 4 s, so a
landing hit appears by itself and the ratio rings animate as it does. A
LOGIN GATE fronts every request — one fixed organization credential pair
(`--org`/`--password`, defaults `netsec`/`netsecpassword`, env
`ROUND_VIEW_ORG`/`ROUND_VIEW_PASSWORD`), no registration: the sign-in
page renders in the ledger's own design tokens, a successful POST buys
an HttpOnly SameSite=Strict cookie session (7 days), deep-link hashes
survive the gate, and a `sign out` header link (live mode only) clears
it.

## The stage READMEs

- `scripts/rehost/README.md` — image tiers, the hverify 2-mode verdict
  contract, loop-device parallel safety, solved-image layout.
- `scripts/taint/README.md` — the poc-run exit-code oracle, grading
  protocol, mapper/hunt work-folder contracts, the vault.
- `scripts/exploit/README.md` — the two-container flag mailbox, the
  fresh-flag compare oracle, anti-cheat hardening, batch & monitor.
