# agent-scan :: taint

Find vulnerabilities in solved IoT emulations **autonomously**, and grade the
findings with a **deterministic script that needs no human and no LLM**.
Two phases share this directory: Phase-1 (Mapper) turns a solved image into
function-granularity taint work packages; Phase-2 (Hunt) hands each package
to an agent that must produce a PoC the grader replays green.

The final scoring standard *is* `poc-run.sh`: an independent verify
container replays the agent's archived poc files with the CURRENT copy of
this script. Same evidence classes a human judge would use, no judgment.

## Pipeline

```
 rehost stage (scripts/rehost) ──▶ task-<id>:solved
                │
 Phase-1 · Mapper (host-side agent, per model)
   mapper-run.sh ──▶ <model>/taint-work-output/
   mapper-batch.sh      boundary.json  dispatch.json  auth.json
   (N models parallel)  functions/<binary>__<func>/{sources,getters}.json
                │            ▲ static leads, NOT dynamically verified
 Phase-2 · Hunt (one agent container per function unit)
   hunt-run.sh ──▶ hunt-output/functions/<unit>/pocs/   (the archive)
                │        + evidence/, run/{agent.log,result.json,transcripts}
   verify-run.sh ─▶        verify/{result.json,evidence/}
   (deterministic: ONE FRESH CONTAINER+BOOT PER POC, poc-run replay only)
                │ hit (rc0/rc2)
   report-agent.sh ─▶      data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/
   (write-once vault: poc + evidence + meta.json, then a STATIC-only agent —
    no boot, no re-verification — writes REPORT.md + AUDIT.json; the archiver
    extends AUDIT.json with deterministic finality + derived 3-tier confidence)
                │ CONFIRMED ∩ 0-DAY entry (CNVD submission material —
                │ auto-triggered by report-agent.sh, backlog via repro-batch.sh)
   repro-run.sh ─▶         <entry>/repro/{session.jsonl,repro.mp4,repro.srt,
   (deterministic replay:  serial-*.log,decisive.txt,report.json,REPRO.md,…}
    fresh boot, the CURRENT grader replays the sha-pinned poc byte-for-byte,
    a live serial tail records the event stream the video is rendered from;
    replay rc must equal the vault rc — else NO video. A static organizer
    agent writes REPRO.md + the subtitle explanation layer, prose only)
                │
   hunt-batch.sh  schedules the whole unit list; hunt-batch-monitor.sh watches
```

## The verdict contract

Everything keys off `poc-run.sh`'s exit code — stdout/stderr are silent
unless `--verbose`; the full report lands in `<out-root>/<run>/report.{txt,json}`
and `latest` always symlinks the newest run.

| rc | verdict | evidence the script actually looks for |
|---|---|---|
| 0 | **TRIGGERED** | CI: marker in an `[ANALYZE]` execve serial line, `/bin/a` canary argv0, or canary-file delta via the guest backdoor's `/firmadyne/os_cmd_injection_log`. BOF: a NEW fatal-signal line in the window (MIPS `sending SIGSEGV to <comm>`, ARM lowercase `potentially unexpected fatal signal 11`; pre-run crashers fingerprinted away) |
| 1 | not_triggered | nothing moved |
| 2 | **service_down** | TCP alive→dead, no crash line, no reboot signature — a graded DoS finding |
| 3 | inconclusive | baseline gate (box wasn't serving) or vendor reboot landed in the window — about the environment, never about the poc; replay on a fresh boot |
| 4 | poc error | bad usage / compile failure — the poc itself is broken |

Three vulnerability classes are detectable, full stop: **command
injection, memory corruption, DoS**. Info-leaks or auth-bypasses have no
deterministic oracle here and are not findings.

**Grading protocol** (also in the script header):

- one poc per **fresh boot**; a destructive poc poisons its container's
  raw in place — the writable layer is the reset button (verify-run.sh
  recreates the container per poc);
- exploration may chain pocs in one boot — per-run markers make
  self-pollution impossible anyway;
- a crash line grades rc=0 *even if the box dies after* (triggered
  beats service_down); a service respawned by a watchdog shows no
  liveness delta — there the crash line is the only channel;
- vendor `config apply → delayed reboot` endpoints (proven: AC15
  SetIPTVCfg, +95 s) would hand free DoS credit to benign traffic —
  reboot signatures in the window downgrade service_down to rc=3.

## Known engine defects (measured, not assumed)

- **The kernel execve audit never records at runtime on our engines.**
  `[ANALYZE]` lines appear only for the boot/initrd phase; at the root
  pivot the hook goes silent (measured on MIPS wr841n) or page-domain-
  faults on every execve (ARM AC15; on W30E it kills init at ~0.8 s).
  Therefore `analyze` / `debug-analyze` are not grading modes anywhere
  in this pipeline: **everything rides `emu debug`** — CI = the canary
  file read over the backdoor, BOF = the crash line, DoS = liveness.
  (The token clause in the rc=0 row above is what the script *can*
  match, not what will fire on these targets.)
- Booting `:solved` twice in one container is a lie: FirmAE's reboot
  interception is an **in-place init restart** — kernel uptime continues,
  no second `Linux version` banner ever appears. Window attribution, not
  banners, is the only truth.

## Scripts

| Script | Role |
|---|---|
| `mapper-run.sh` | Phase-1 driver, one model: host-side `claude` (effort=max) under a watchdog → contract check (shape only, zero content judgment) → `taint-work/mapper-run/result.json`. Preserves `taint-work/ghidra-projects/` across reruns (cache only). |
| `mapper-batch.sh` | Whole tree, `--jobs N`; resumable; maintains the state file `mapper-batch-monitor.sh` reads. |
| `mapper-batch-monitor.sh` | Live dashboard (four boxes; success rate fits Phase-1, packages/src/get shown). |
| `call-site-dump.sh` + `CallSiteDump.java` | Host-side deterministic Ghidra-headless extraction of EVERY call site in EVERY function of a binary: call/return addresses, per-position physical argument slots with resolved constants (`const_string`), ABI return register, bounded forward consumer scan. Ghidra project cached under `taint-work/ghidra-projects/`. Shipped to hunt containers as `/work/taint/` — the raw static ground the Mapper's sources/getters are cut from. |
| `frontend-surface.py` | A dumb extractor of the frontend's request vocabulary (URLs, fields, controls — tagged, never filtered or judged); the JOIN against the binaries is the Mapper's job. |
| `mapper-prompt.md` | The Mapper's mission brief (deliverable schemas included). |
| `poc-run.sh` | **The deterministic grader (v3).** Contract, channels and protocol above. BOF crashes are keyed by a `(signal, comm)` fingerprint computed with the `[uptime]` prefix stripped and matched against the WHOLE pre-window serial, so boot-phase crashers suppress only their own kind (and the `debug:`-substring pseudo-banner is permanently known-good). service_down requires a 3-for-3 liveness handshake (initial dead + two 2 s retries); a flaked canary baseline read disables the CI file-delta channel for that run (`NA`) instead of ghost-baselining it into a hit. Never baked into images — `docker cp`'d at derive time so every grading replays the CURRENT script. |
| `hunt-prompt.md` | The Hunter's mission brief: unit ammunition description, the two data-dependency lenses (call graph / storage channel) each with a real mined W30E case, the three graded classes, rc semantics, archive contract. Describes the task; does not constrain technique. |
| `hunt-run.sh` | One unit, one derived agent container: stage `/work/hunt` (unit jsons + auth/dispatch/boundary) + `/work/taint` (call-site-dump, surface, notes) + CURRENT `poc-run`/`emu` + decompiled-rootfs host fallback → in-container agent under watchdog → harvest archive/evidence/transcripts → driver-written `run/result.json`. |
| `verify-run.sh` | The LLM-free scoring pass per unit: one fresh container+boot per archived poc ATTEMPT, `emu debug`, serving-wait on the model's ATTACK-SURFACE port (boundary.json `service_port` > `--port` > 80 — the gate must watch the daemon under attack, never an early-answering unrelated static server) with a STABILITY CONFIRMATION after the first "up" (`--gate-confirm S`, default 8, 0 = old single-probe: an image whose daemon listens then dies — R7000 httpd#1 listens 0.5-1.6 s, SIGSEGV at 0x17350, watchdog respawn — must not hand the grader its death blip), `poc-run --out-root` → `verify/result.json` with rc/verdict/evidence per poc (a previous pass is kept as `verify.pre-<ts>`, never silently overwritten). A verdict that is neither TRIGGERED nor service_down is RE-GRADED on a fresh container+boot up to `--retries N` extra times (default 5, 0 = old single-shot) — the anti-flake and race-condition arm: probabilistic obstacles get their shots, race-condition triggers get several boots to win; the score of record is the LAST attempt and every attempt is preserved (`evidence/<n>-<poc>/attempt-<k>/` + `attempts[]` ledger + `attempts_used` in result.json — best-of-N inflation stays auditable). rc=4 (poc_error) is deterministic and never retried. POC JOBS RUN IN PARALLEL (`--parallel N`, default 4 — dedicated container names `verify-<unit>-<idx>`, per-job jsonl parts merged in index order; each TCG boot ~1 core). Archive files outside the `.py`/`.c` contract are listed as violations, never executed. Every hit (rc0/rc2) additionally lands in the round vault: snapshot inline (fast, deterministic — yields the `round` path), report agent DETACHED (grading never waits on an LLM); `--no-report` opts out. |
| `report-agent.sh` | Round vault archiver + report writer for ONE graded hit: snapshots poc/evidence/meta.json (meta carries the deterministic `finality` read from the grader's report.json) to `data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/` (append-only — the grading timestamp makes names collision-proof, a poc already vaulted by hash is REUSED not duplicated, and REPORT.md+AUDIT.json are never overwritten; `index.json` ledger rebuilt per pass) and launches a host-side STATIC-only agent (cwd = vault entry, watchdog'd, `--effort high` default) that writes the English `REPORT.md` plus the machine-readable `AUDIT.json` judgment ledger (attribution / threat_model / artifact_check / novelty / flow — the `flow.channel` is `direct` when attacker bytes reach the corrupting copy inside ONE graded request along the call graph, `cross` when a first request persists the bytes (config/flash/file/IPC) and a later read-back request runs the corrupting copy; the archiver normalizes any other value to `unknown`; novelty is binary 0-DAY/N-DAY by version×route×parameter triple, no demonstrated N-Day match IS 0-day; cited CVEs flagged `citation_verified:false` for driver confirmation). The script then extends AUDIT.json with the overall 3-tier `confidence` (high = CLOSED+TOKEN+pure remote+no affirmed artifact; low = guest delivery step/non-remote attack vector/affirmed artifact (`yes`)/CHECK; an unproven `maybe` and read-only guest self-measurement (observation whose result the attack never consumes) pass the gate, and `remote_vector: l2-adjacent` counts raw-Ethernet wire attacks as remote — else medium) — DERIVED from the dimensions, never agent-asserted. `--snapshot-only`/`--render-only` exercise the vault without spending an agent. |
| `report-prompt.md` | The report agent's brief: eleven-section vendor-disclosure structure (path source→sink with decompiled citations, proof mechanics + the five-dimension evidence audit, evidence index into `evidence/`, impact incl. shared-primitive grep across the root, severity rationale) with the static-only hard rules and the AUDIT.json schema — no HTML-comment footers anywhere. |
| `repro-run.sh` | CNVD authenticity pack for ONE vaulted hit: fresh container+boot per attempt, stability-confirmed serving gate, then the CURRENT `poc-run` replays the sha-pinned archived poc byte-for-byte while a live serial tailer records every guest line into a timestamped event stream (`repro/session.jsonl`); harvests serial-full/window/decisive + canary deltas + the grader's report.json, runs the static organizer agent (REPRO.md + `subtitles.json`; `--no-agent` skips), and renders `repro.mp4`/`repro.srt` ONLY if the replay rc equals the vault rc — otherwise fresh-boot retries ALIGNED with verify-run (`--retries N`, default 5 like verify's; rc=4 poc_error is deterministic and NEVER retried; every attempt lands in repro.json's `attempts_ledger`, failed attempts preserved as `repro.fail-<n>/` — best-of-N stays auditable), and after them `repro.state=missed-replay` with NO video (never rendered from stale evidence). Append-only: a previous `repro/` is parked as `repro.pre-<ts>`; evidence/, REPORT.md, AUDIT.json are never touched. meta.json gains a `repro` object. |
| `repro-video.py` | The deterministic renderer: the video's bytes come ONLY from the replay's `session.jsonl` — it re-times, never adds. Scenes: title → declared 20× boot time-lapse → baseline probe → attack window (split screen: poc stdout verbatim ∥ live serial tail, decisive lines highlighted as they land; 1:1 real time, except a pathologically long window is re-timed piecewise — head 45s + tail 105s stay 1:1, the middle is a declared 20× fast-forward) → verbatim evidence exhibit (serial / canary / probe per class) → grader verdict summary → provenance card. Frames stream into ffmpeg as drawn (O(1) memory at any window length). Captions are burned in (Chinese, for CNVD reviewers) + written as an srt sidecar in two layers: the FACT layer is class templates filled from this run's bytes; the EXPLANATION layer is the agent's `subtitles.json` when present, template sentences otherwise. A multi-attempt run discloses the attempt count in the verdict scene (the video shows the matching one, earlier attempts stay sealed in `repro.fail-*/`), and the provenance card states the verify-run-aligned retry rule. |
| `repro-prompt.md` | The organizer agent's brief (English): read every artifact of the entry, write exactly two files — `repro/REPRO.md` (English CNVD-style overall document: attack steps, per-line annotation of the decisive serial lines, why the deterministic verdict fired, video timeline index, attachment manifest) and `repro/subtitles.json` (Chinese sentences — burned into the video for CNVD reviewers). Strictly organizer-only: no boot, no traffic, no re-verification, no verdict edits; every quoted line verbatim from `repro/`/`evidence/`. |
| `repro-batch.sh` | Batch reproduction packs over the vault: selects the CONFIRMED ∩ 0-DAY entries (confidence ∈ high\|medium AND novelty == 0-DAY — CNVD material is produced for 0-day findings only; `--novelty N-DAY\|any` overrides) lacking a `done` replay — `--force` also re-runs done entries and retries missed-replay ones; `--prose-only` inverts the selection to done entries only (sealed-replay reuse for prompt tweaks); `--vendor`/`--model`/`--entries` narrow it; `--parallel N` workers (each ≈ one QEMU boot + one static agent); `--timeout S` per-entry wall budget (default 7200; on expiry the worker is TERM'd and repro-run's exit trap removes its container — booked TIMEOUT); pass-through `--no-agent`/`--agent-timeout`/`--retries`. Resumable by construction — the vault's own `meta.repro` is the state file, no ledger to corrupt. Per-entry logs + `schedule.json`/`events.jsonl`/`summary.json` under `<vault>/.repro-batch/<UTC-stamp>/`. |
| `repro-batch-monitor.sh` | Live dashboard over a repro batch (four boxes, mapper-monitor style): header (filters, jobs, timeout, queue, elapsed/ETA), progress bar + video-rate/avg-wall/video-MB stats, running workers with per-entry elapsed, timeout-fraction gauge and phase (`replay` vs `agent` — from a real /proc scan of repro-run wrappers and claude cwd), recent completions (done ✓ / missed ✖ / timeout ⧗ / failed). Everything derives from real state: `schedule.json` + `events.jsonl` + /proc + each entry's `meta.repro`. `--once` for a single frame. |
| `round-view.py` | The vault's read layer: one self-contained HTML ledger over ALL of `data/round` (deterministic, stdlib-only, zero external requests — inline CSS/JS/markdown-renderer, works from `file://`; the embedded template lives in this file — no side-car assets). Security-desk layout, TWO TIERS routed on `#/v/<vendor>/m/<model>`: tier 1 = fleet overview (left rail lists VENDORS with entry counts, plus the two ratio rings and direct CONFIRMED∩0-DAY / CONFIRMED∩N-DAY cross-counts with per-class CI/BOF/DoS tallies — the one-dim rings cannot express the intersection; one big card per model — status ratio ring with the total in the hub, paired stat boxes (0-DAY|N-DAY novelty, CONFIRMED|REJECTED status), CI/BOF/DoS chips, handler count); tier 2 = that model's hit ledger (rail swaps to search + listbox filters Novelty/Status/Attribution/CLASS — vendor filtering is meaningless inside a model — rings scoped to the model; cards carry status dot, class, flow chip direct/cross, 0-DAY/N-DAY with unverified-CVE flag, TOKEN/WINDOW, marker, graded date). Right drawer with a meta grid (verdict · finality · status · confidence · novelty · marker · class · flow · graded · repro) and tabs *Evidence audit · PoC · Report · Repro* — the entry's full REPORT.md, AUDIT.json dimensions and exact poc bytes embedded; the Repro tab plays the live-replay video inline with a download-to-local link (bytes + sha256 shown), the machine facts from repro.json, the decisive serial lines verbatim, the full attachment manifest (every file downloadable through the raw-vault route, `.mp4`/`.srt` included) and the rendered REPRO.md. Status is CONFIRMED/REJECTED only: high\|medium ⇒ CONFIRMED, low ⇒ REJECTED (confidence grades the attribution chain, never reality). Plain run rebuilds `<root>/dashboard.html` atomically (snapshot — re-run after new hits); `--serve PORT` serves it LIVE: every request rescans the vault and the page polls `/__data__` (state-hash ts) every 4 s, so a landing hit appears by itself and the ratio rings animate as it does; `--token <t>` gates every request — `?token=<t>` once buys an HttpOnly cookie session. |
| `hunt-batch.sh` | Schedules unit pipelines (`hunt-run → verify-run`, one worker pair per unit, `--parallel N`, resumable per stage; `--verify-retries`/`--verify-gate-confirm` pass through to verify-run's retry/gate-confirm knobs), writes the live state file, final `summary.json`. |
| `hunt-batch-monitor.sh` | Live dashboard: scoreboard in POCs (archived/graded/hits + T-S-n-I-P-B histogram), never a success rate; budget gauge per hunting worker. |

## Usage

Prerequisites: everything of `scripts/rehost` (a `:solved` image is the
input), repo-root `.env` with LLM credentials, `/dev/kvm` + `/dev`.

```bash
# Phase-1 — map one model (agent boots the solved image itself for auth probing)
bash scripts/taint/mapper-run.sh data/firmware/tenda/W30EV2.0
bash scripts/taint/mapper-batch.sh --jobs 2 data/firmware/tenda      # whole vendor
bash scripts/taint/mapper-batch-monitor.sh data/firmware/tenda

# Phase-2 — hunt one unit, then grade its archive
bash scripts/taint/hunt-run.sh --timeout 3600 data/firmware/tenda/W30EV2.0 \
    bin__httpd__formSetAcAdvanced
bash scripts/taint/verify-run.sh data/firmware/tenda/W30EV2.0 bin__httpd__formSetAcAdvanced

# the batch (each worker = hunt pair + verify pair, resumable)
bash scripts/taint/hunt-batch.sh --parallel 2 --timeout 3600 data/firmware/tenda/W30EV2.0
bash scripts/taint/hunt-batch.sh --units bin__httpd__setWanL2tp,bin__httpd__UploadCfg ...
bash scripts/taint/hunt-batch-monitor.sh data/firmware/tenda/W30EV2.0   # live view

# grade a single poc by hand (inside any booted lab container)
docker exec <ctr> poc-run /work/poc/whatever.py; echo rc=$?

# CNVD authenticity pack for one vaulted hit (fresh-boot replay -> video +
# serial logs + REPRO.md; --no-agent skips the organizer, --retries N arms
# extra fresh boots when the replay misses the vaulted verdict class)
bash scripts/taint/repro-run.sh data/round/netgear/RAX50/<entry>
# the backlog: packs for ALL CONFIRMED ∩ 0-DAY entries lacking one (resumable —
# the vault itself is the state file; --dry-run previews the selection)
bash scripts/taint/repro-batch.sh --parallel 2 --dry-run
bash scripts/taint/repro-batch.sh --vendor tenda --parallel 10 --timeout 7200
bash scripts/taint/repro-batch-monitor.sh            # live view (newest batch)

# the whole vault as one self-contained page (open/scp data/round/dashboard.html)
python3 scripts/taint/round-view.py
# the same page LIVE from a port, token-gated (open http://<ip>:<port>/?token=<t>
# once; an HttpOnly cookie keeps the session)
python3 scripts/taint/round-view.py --serve 8080 --token "$(cat <token-file>)"
```

Resuming: a unit is skipped entirely once `verify/result.json` exists
(`--reverify` overrides); the hunt stage is skipped once
`run/result.json` says success (`--rehunt` overrides). Interrupted units
resume from the missing stage — restarting the batch costs only what is
unfinished.

## Work-folder contract

Per model, written by Phase-1 (never by Phase-2):

```
taint-work-output/          the contract: boundary/dispatch/auth.json +
  functions/<bin>__<func>/  {sources.json,getters.json} — requests[] carry the
                            routing recipe, sources[]/getters[] verbatim call sites
taint-work/                 agent scratch + standing tools (call-site-dump/,
                            map/, frontend-surface.json, ghidra-projects/ cache)
```

Per unit, written by Phase-2 drivers (never by the agent except via the
archive contract):

```
hunt-output/functions/<unit>/
  pocs/        the agent's /work/archive — the ONLY replayed artifact
  evidence/    poc-run reports gathered from the agent container (exploration)
  verify/      result.json + per-poc grading evidence (the score of record)
  run/         agent.log, prompt.rendered.md, result.json, transcripts
hunt-output/_batch/<stamp>/  per-unit driver logs + batch summary.json
```

