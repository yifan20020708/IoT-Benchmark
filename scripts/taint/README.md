# agent-scan :: taint

Map the **network-input surface** of solved firmware emulations: which
binaries receive user requests, which functions inside them are the
intermediate taint sources (named accessors like `cJSON_GetString` plus
unnamed vendor wrappers), which strings dispatch requests to handlers, and —
proved dynamically — that request parameters actually reach those sources.

Stage 2 of the benchmark (`rehost` → **taint** → exploit-driven agent). Runs
only on tasks whose rehost stage produced `task-<id>:solved`.

## The division of labor

**The scripts are deterministic evidence providers; the agent makes every
firmware-specific decision.** No script in this directory knows a vendor, a
model, or an architecture-specific idiom beyond ABI facts. Which binary is a
boundary, which function is a wrapped taint source, which string routes a
request — that judgment belongs to the agent (`taint-prompt.md`); the driver
then re-proves the agent's claims with its own canaries.

## Pipeline

```
 taint-run.sh <model-dir>                     host-side driver
    │
    ├─ taint-prompt.md ──▶ claude agent (cwd = model dir, effort max, watchdog)
    │       frontend-keywords.py   ─▶ taint-source/frontend-keywords.json
    │       ghidra-index.sh        ─▶ taint-source/ghidra-index/*.json
    │       taint-query.py         ─▶ candidate exploration
    │       verify-request.sh      ─▶ self-check runs (agent authors the probes)
    │       writes taint-source-output/{summary.json,functions/*.json,probes.json}
    │
 ├─ driver validation (deterministic)
 │       schema + every call address cross-checked against the agent's own
 │       Ghidra index (fabricated call sites cannot survive)
 │
 ├─ driver verification (fresh canaries, fresh container)
 │       verify-request.sh re-runs probes.json ─▶ taint-run/verify-verdicts.json
 │                                            └─▶ taint-source-output/verified-callsites.json
 │
 └─ result.json   status = success | fail | agent_timeout | agent_error
```

## The verdict contract

- **The canary is the harness's secret.** `verify-request.sh` generates it,
  injects it into the agent's request template as `{{CANARY}}`, and never
  prints it. A `pass` verdict means gdb itself observed the canary in the
  taint source's argument buffers or return value. The agent cannot
  pre-plant evidence for a value it has not seen; the driver's final re-run
  uses fresh canaries anyway.
- **`ret_breaks` are the strongest evidence.** The recorder arms breakpoints
  at the return sites of chosen call sites (call address + arch delay), so a
  `ret_hit` with the canary proves the accessor *returned* attacker data.
- Verdicts per probe: `pass` | `no-canary` (source ran, canary absent) |
  `no-hit` (source never ran). Exit 0 = all pass.
- Statuses: `success` = schema valid AND the driver's own re-run passes;
  `fail` = invalid schema, missing probes, or failed verification.

## Scripts

| script | what it does | generality |
|---|---|---|
| `frontend-keywords.py` | whole-rootfs frontend file scan by suffix (markup/script/data), per-type parsers, 5 keyword buckets with counts/origins/files; client-side template blocks (`<script type="text/template">`, content-detected) are re-parsed as markup — their form vocabulary is invisible to the outer parse | pure suffix + generic web parsing; zero vendor constants |
| `ghidra-index.sh` (+ `IndexExporter.java`) | one-shot Ghidra headless analysis → per-function xref index (strings, call edges with args, decompiled text calls with resolved arithmetic); project cached under `taint-source/ghidra-projects/`; callers sorted for byte-reproducibility | architecture-neutral; 3 unioned evidence paths covering the ARM PIC (`DAT_x ± 0xCONST`) and the MIPS GOT/ELF-DYN (`PTR_lbl_slot ± 0xCONST`, `(*(code *)PTR_x)(...)`) idioms; big-endian validated |
| `taint-query.py` | query layer over the index: `callsites`, `strings-in`, `xrefs`, `callers`, `fn`, `colocate`, `list` | pure queries; `colocate` ranks candidates, never decides |
| `verify-request.sh` | deterministic dynamic verifier: fresh lab container → `emu boot` (CPU frozen, gdbstub 0.0.0.0:1234) → host gdb-multiarch recorder → send probes → verdicts | probe content entirely agent-authored; arch table is ABI facts (arm/aarch64/mips) |
| `gdb-recorder.py` | GDB-side passive recorder driven by env vars; every breakpoint auto-continues, logs `source_hit`/`entry_hit`/`ret_hit` events with canary matches | register tables per ABI; nothing firmware-specific |
| `taint-run.sh` | task driver: lock → clean outputs → host-side agent under watchdog → schema validation + index cross-check → fresh-canary re-verification → `result.json` | — |
| `taint-prompt.md` | the agent's mission brief (stages, tool contracts, output schemas, rules) | — |

## Output contract (per model folder)

```
<model>/taint-source/            intermediates: frontend-keywords.json,
                                 ghidra-index/, ghidra-projects/ (cache)
<model>/taint-source-output/     deliverables:
    summary.json                 boundary_binaries, taint_sources, entries
    functions/*.json             per containing function: every taint-source
                                 call (source, call_address, params)
    probes.json                  the final verify spec (harness re-runs it)
    verified-callsites.json      driver-produced: which call sites the
                                 fresh-canary re-run actually proved
<model>/taint-run/               driver artifacts: agent.log,
                                 agent-transcripts.tar, validation.json,
                                 verify-verdicts.json
```

The per-function records are the starting points for the next stage's
taint-analysis agent (its granularity: functions containing verified
taint-source calls).

## Host prerequisites

Ghidra (`deps/ghidra_12.1.4_PUBLIC`, see `rehost/build-deps.sh`) with Java 21,
`gdb-multiarch` (same version family as host gdb), Docker, and the solved
image. The gdb path needs no changes to solved images: QEMU's `-s` binds
`0.0.0.0:1234` and the driver attaches over the container bridge IP.

## Generality validation (three vendors, three binary flavors)

| firmware | arch / linkage | frontend style | result |
|---|---|---|---|
| tenda W30EV2.0 | ARM EXEC, symbols | static forms | 374 params, 92 endpoints; template fix changed nothing (regression-clean) |
| netgear R7000 | ARM EXEC, **stripped** (acos) | Genie forms + JS | 500 params, 258 endpoints; the accessor is a stripped local (`FUN_0001ae88`) — 43 call sites with real parameter names, colocate ranks the WAN/wireless handlers first |
| netgear GS310TPv2 | **MIPS big-endian**, ELF DYN | SPA + client-side templates | param extraction 0 → 162 after the template fix; GOT-slot arithmetic (`PTR_..._84128 + -0x6020` = string, verified against Ghidra's relocated memory) took `text_calls` 0 → 357 |

The `gdb-recorder.py` register tables are ABI facts (arm/aarch64/mips);
the MIPS/aarch64 dynamic paths await solved images of those architectures.

## Pilot status

W30E (ARM): all scripts verified E2E — probes against the `auth` login
module prove `password`/`time` reach `cJSON_GetString` (canary returned at
the exact call sites), negative control (unread parameter → `no-canary`)
fails correctly; the full agent run (`taint-run.sh`) is driven by
`taint-run/result.json` with the driver's own fresh-canary re-verification.
