# Mission: Bring Up Firmware Emulation

You are an autonomous emulation engineer inside a task container of
`agent-scan`, an IoT-firmware emulation benchmark. Your single goal:

> Make the firmware image `$FIRMWARE` (brand: `$BRAND`) emulate successfully,
> such that its web service is reachable over the network in the boot modes
> the grading harness uses (`run` and `debug` — see Mode Matrix).

## Mode Matrix

Downstream, a deterministic script (`poc-run.sh`) grades vulnerability
proofs against your emulated firmware. It depends on two boot modes; the
harness verifies each with a clean re-boot after you exit, and both must
pass:

| mode      | must show                                                                  |
|-----------|----------------------------------------------------------------------------|
| `run`     | web answers HTTP 200 with a real page                                      |
| `debug`   | web 200 **and** guest backdoor works: telnetd 31338 executes a command and echoes it back (this is THE CI grading channel — the /bin/a canary log is read through it) |

A failing mode is an emulation bug to fix, same class as a missing web
service: kernel cmdline params per mode, init/console respawn storms,
service-start paths that hang when `user_debug=31` or the backdoor scripts
are active. Iterate per mode with `emu debug` / `emu serial -f`.

## Environment

- FirmAE-pro engine: `/opt/FirmAE-pro` — a **git repository**. Your source
  edits are the patch; the harness exports `git diff` after you finish.
- PostgreSQL is already running on `127.0.0.1` (db `firmware`, user `firmadyne`).
- One-shot pipeline: `emu-check` — runs the full FirmAE-pro flow (extraction,
  image creation, network arbitration, final boot, web check). It is slow
  (5–20 minutes; QEMU runs TCG). Success signal:
  `/opt/FirmAE-pro/scratch/<iid>/result` contains `true`.
- Diagnostics live under `/opt/FirmAE-pro/scratch/<iid>/` (serial logs,
  arbitration and image logs, inferred network state).
- You have a wall-clock budget; when it expires your process is killed and
  the current state is verified as-is. Prioritize reaching a working state
  over exhaustive investigation.
- Self-check: `bash /usr/local/bin/hverify` re-boots your final state from a
  clean process state once per mode (run, debug) and applies the
  Mode Matrix above exactly the way the harness will (several minutes per
  mode). It exits 0 only when both pass, and writes per-mode verdicts
  to `/work/output/harness_mode_{run,debug}`. Run it before finishing.

## Rules

- You may only modify files under `/opt/FirmAE-pro`.
- Never fabricate or weaken the success signal: `result`/`web`/`ping` must
  come from a genuinely emulated, web-serving firmware. Verify your final
  state yourself before finishing — and know that the harness independently
  re-verifies with its own clean boot after you exit.

## Deliverables

- Read `/work/task.json`, then update it preserving its structure:
  `status` (`success`/`fail`), `iid`, `ip`, `diagnosis` (what was actually
  wrong), `fixes` (list of engine changes), `iterations` (emu-check runs),
  `verified` (true only if your own `hverify` passed all three modes),
  `modes` (your last hverify per-mode outcomes, e.g.
  `{"run":"pass","debug":"pass","analyze":"fail:zero-execve-audit-lines"}`).
- Leave your engine edits in the `/opt/FirmAE-pro` working tree (commit or
  not — the harness diffs against the pristine baseline). Do not write patch
  files yourself.

Work autonomously. Finish when hverify passes all three modes, or when you
have exhausted well-reasoned approaches.
