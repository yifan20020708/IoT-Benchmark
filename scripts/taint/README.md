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
| `poc-run.sh` | **The deterministic grader.** Contract, channels and protocol above. Never baked into images — `docker cp`'d at derive time so every grading replays the CURRENT script. |
| `hunt-prompt.md` | The Hunter's mission brief: unit ammunition description, the two data-dependency lenses (call graph / storage channel) each with a real mined W30E case, the three graded classes, rc semantics, archive contract. Describes the task; does not constrain technique. |
| `hunt-run.sh` | One unit, one derived agent container: stage `/work/hunt` (unit jsons + auth/dispatch/boundary) + `/work/taint` (call-site-dump, surface, notes) + CURRENT `poc-run`/`emu` + decompiled-rootfs host fallback → in-container agent under watchdog → harvest archive/evidence/transcripts → driver-written `run/result.json`. |
| `verify-run.sh` | The LLM-free scoring pass per unit: one fresh container+boot per archived poc, `emu debug`, serving-wait, `poc-run --out-root` → `verify/result.json` with rc/verdict/evidence per poc. POC JOBS RUN IN PARALLEL (`--parallel N`, default 4 — dedicated container names `verify-<unit>-<idx>`, per-job jsonl parts merged in index order; each TCG boot ~1 core). Archive files outside the `.py`/`.c` contract are listed as violations, never executed. Every hit (rc0/rc2) additionally lands in the round vault: snapshot inline (fast, deterministic — yields the `round` path), report agent DETACHED (grading never waits on an LLM); `--no-report` opts out. |
| `report-agent.sh` | Round vault archiver + report writer for ONE graded hit: snapshots poc/evidence/meta.json (meta carries the deterministic `finality` read from the grader's report.json) to `data/round/<vendor>/<model>/<poc-stem>-<graded-ts>/` (append-only — the grading timestamp makes names collision-proof, a poc already vaulted by hash is REUSED not duplicated, and REPORT.md+AUDIT.json are never overwritten; `index.json` ledger rebuilt per pass) and launches a host-side STATIC-only agent (cwd = vault entry, watchdog'd, `--effort high` default) that writes the English `REPORT.md` plus the machine-readable `AUDIT.json` judgment ledger (attribution / threat_model / artifact_check / novelty — binary 0-DAY/N-DAY by version×route×parameter triple; no demonstrated N-Day match IS 0-day; cited CVEs flagged `citation_verified:false` for driver confirmation). The script then extends AUDIT.json with the overall 3-tier `confidence` (high = CLOSED+TOKEN+pure remote+no artifact doubt; low = guest-side/non-remote/artifact doubt/CHECK; else medium) — DERIVED from the dimensions, never agent-asserted. `--snapshot-only`/`--render-only` exercise the vault without spending an agent. |
| `report-prompt.md` | The report agent's brief: eleven-section vendor-disclosure structure (path source→sink with decompiled citations, proof mechanics + the four-dimension evidence audit, evidence index into `evidence/`, impact incl. shared-primitive grep across the root, severity rationale) with the static-only hard rules and the AUDIT.json schema — no HTML-comment footers anywhere. |
| `hunt-batch.sh` | Schedules unit pipelines (`hunt-run → verify-run`, one worker pair per unit, `--parallel N`, resumable per stage), writes the live state file, final `summary.json`. |
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

