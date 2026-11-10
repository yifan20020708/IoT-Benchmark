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
    ├─ driver verification (fresh canaries, fresh containers, parallel boots)
    │       verify-batch.sh splits probes.json into boot chunks (the agent's
    │       optional "chunks" hint) → parallel verify-request.sh runs →
    │       slow-zone analysis → repair round for failures
    │                                    ─▶ taint-run/verify-verdicts.json
    │                                    └─▶ taint-source-output/verified-callsites.json
    │
    └─ taint-result.json   status = success | fail | agent_timeout | agent_error
       (last step) assemble-functions.py splits the records into
       functions/<binary__function>/ (genuinely-RECEIVING functions only:
       >=1 dynamically-verified call site — the next stage's starting
       points, indexed by functions/INDEX.json) and functions-context/
       (sites never fed — storage-channel / seeding candidates); each
       folder's probes.json separates reception_probes (the requests that
       fed this function's sites) from context_probes (read-side
       inventory: pure getters' request templates for the next stage's
       setter->storage->getter channel)
```

## The verdict contract

- **The canary is the harness's secret.** `verify-request.sh` generates it,
  injects it into the agent's request template, and never prints it. Two
  channels: `{{CANARY}}` (a string, observed by gdb in the taint source's
  argument buffers or its returned string) and `{{CANARY_INT}}` (a number,
  observed by argument/return **register equality** — int-returning
  accessors like `cJSON_GetInt` can never surface a string canary). The
  agent cannot pre-plant evidence for a value it has not seen; the driver's
  final re-run uses fresh canaries anyway.
- **Parallel boot chunks.** A full-coverage batch (every entry, every call
  site armed) cannot run in one boot — the armed breakpoints also sit on
  the guest's own init path and grind it. The driver's re-run splits the
  spec into chunks (the agent may set a top-level `"chunks": <int>` in
  probes.json), one boot each, all in parallel; per-probe distinct,
  per-run fresh canary values make cross-chunk contamination impossible.
  A second repair round re-runs expected failures (pass- and unfed-expected)
  on clean boots: slow-send wedge suspects (trailing ~20s+ send gaps) run
  isolated alone, the rest with a fresh session bootstrap.
- **`ret_breaks` are the strongest evidence.** The recorder arms breakpoints
  at the return sites of chosen call sites (call address + arch delay), so a
  `ret_hit` with the canary proves the accessor *returned* attacker data.
- Verdicts per probe: `pass` | `no-canary` (source ran, canary absent) |
  `no-hit` (source never ran). Exit 0 = all pass (the verifier is
  expect-blind; the driver interprets).
- **`expect` semantics.** Each probe carries `"expect": "pass"` (default),
  `"expect": "unreachable"`, or `"expect": "unfed"`. Only pass-expected
  failures fail the run: a `no-hit` on an unreachable-expected probe is
  harness-verified PROOF of unreachability, and an unfed-expected probe
  (pure getter / read-only entry — requires `entry_break`) passes on
  dispatch evidence (entry hit, or the source family executing under the
  request): reception-negative is a complete answer, not incomplete work.
  Pure getters never own a function folder — they surface as
  `context_probes`, the read-side inventory of the cross-request storage
  channel that belongs to the NEXT stage (a setter persists input, a
  getter serves it back on another request; stage 2 maps reception only).
- **Every entry must be attempted** (one probe per module/form/endpoint)
  and **every recorded call site of the probed binary must be armed** in
  some probe's `ret_breaks` (breakpoints are free; a site that cannot
  execute is honestly `not-reached`, an unarmed site was never tested) —
  the dynamic contract is full call-site coverage, not a sample.
- **Write-back.** After its fresh-canary re-run, the driver annotates every
  function record's call sites with their dynamic status (`verified` |
  `reached-unfed` | `not-reached` | `not-attempted`) — `verified` means a
  return event AT THAT SITE carried the canary (per-site proof, not
  probe-level credit) — and writes `verified-callsites.json`; the next
  stage consumes verified claims, not static ones.
- Statuses: `success` = schema valid AND every entry attempted AND every
  call site of the probed binary armed AND every pass-expected probe passed
  the driver's own fresh-canary re-run AND every unfed-expected probe
  proved dispatch; `fail` = anything else (with `status_reasons` in
  taint-result.json).

## Scripts

| script | what it does | generality |
|---|---|---|
| `frontend-keywords.py` | whole-rootfs frontend file scan by suffix (markup/script/data), per-type parsers, 5 keyword buckets with counts/origins/files; client-side template blocks (`<script type="text/template">`, content-detected) are re-parsed as markup — their form vocabulary is invisible to the outer parse | pure suffix + generic web parsing; zero vendor constants |
| `ghidra-index.sh` (+ `IndexExporter.java`) | one-shot Ghidra headless analysis → per-function xref index (strings, call edges with args, decompiled text calls with resolved arithmetic); project cached under `taint-source/ghidra-projects/`; callers sorted for byte-reproducibility | architecture-neutral; 3 unioned evidence paths covering the ARM PIC (`DAT_x ± 0xCONST`) and the MIPS GOT/ELF-DYN (`PTR_lbl_slot ± 0xCONST`, `(*(code *)PTR_x)(...)`) idioms; big-endian validated |
| `taint-query.py` | query layer over the index: `callsites`, `strings-in`, `xrefs`, `callers`, `fn`, `colocate`, `list` | pure queries; `colocate` ranks candidates, never decides |
| `verify-request.sh` | deterministic dynamic verifier: fresh lab container → `emu boot` (CPU frozen, gdbstub 0.0.0.0:1234) → host gdb-multiarch recorder → send probes → verdicts; two canary channels (`{{CANARY}}` string, `{{CANARY_INT}}` register-equality); one spec = one boot; `--workdir` lets a batch driver own the artifact layout | probe content entirely agent-authored; arch table is ABI facts (arm/aarch64/mips) |
| `verify-batch.sh` | two-phase parallel re-verification of a full spec: chunk split → parallel boots (semaphore `--max-parallel`) → send-timing slow-zone analysis → repair round (victims on clean boots, wedge suspects isolated alone); merged verdicts keep the single-run schema | policy purely mechanical (spec order, curl jar semantics, 15s send-gap threshold); chunk count from `--chunks` / spec `chunks` hint / ceil(n/32) |
| `chunk-probes.py` | order-preserving spec splitter with session-bootstrap replication (the `-c` jar writer moved/copied to every reader chunk's front); `--isolate` gives listed probes a boot each; usable by the agent for its own big batches | generic curl semantics only |
| `merge-verdicts.py` | merges per-chunk verdicts/events pass-if-any (value-based canary attribution — chunks cannot cross-contaminate) and computes the repair analysis (failed / suspects / victims from send timings) | — |
| `assemble-functions.py` | last driver step: splits records into `functions/` (genuinely-receiving: ≥1 verified call site — the next stage's starting points, indexed in `functions/INDEX.json`) and `functions-context/` (unfed potentials); each folder's probes.json separates `reception_probes` (fed this function's sites) from `context_probes` (read-side inventory); a probe appears in every folder it serves but executes once, so verdicts are consistent by construction; idempotent, re-runnable in place | pure joins over existing artifacts; reports orphan probes |
| `gdb-recorder.py` | GDB-side passive recorder driven by env vars; every breakpoint auto-continues, logs `source_hit`/`entry_hit`/`ret_hit` events with canary matches (string scan in buffers + int register equality) | register tables per ABI; nothing firmware-specific |
| `taint-run.sh` | task driver: lock → clean outputs → host-side agent under watchdog → schema validation + index cross-check → fresh-canary re-verification → `taint-run/taint-result.json` | — |
| `taint-prompt.md` | the agent's mission brief (stages, tool contracts, output schemas, rules) | — |

## Output contract (per model folder)

```
<model>/taint-source/            intermediates: frontend-keywords.json,
                                 ghidra-index/, ghidra-projects/ (cache)
<model>/taint-source-output/     deliverables:
    summary.json                 boundary_binaries, taint_sources, entries
    functions/                   the next stage's STARTING POINTS:
                                 functions with >=1 verified call site
        INDEX.json               starting_points (verified-site count,
                                 reception/context probe counts), context_only
        <binary__function>/
                                 <binary__function>.json — the record,
                                 annotated with per-call-site verify status
                                 probes.json — reception_probes (the
                                 requests whose canary fed this function's
                                 sites: template, channel types, verdict)
                                 + context_probes (reached/armed without
                                 feeding — read-side inventory)
    functions-context/           every other record (sites never fed:
                                 state-gated potentials, storage-channel
                                 candidates) — same folder shape
    probes.json                  the final verify spec (harness re-runs it)
    verified-callsites.json      driver-produced: which call sites the
                                 fresh-canary re-run actually proved, plus
                                 the per-site status map
<model>/taint-run/               driver artifacts: agent.log,
                                 agent-transcripts.tar, validation.json,
                                 driver-probes.json, verify-verdicts.json,
                                 taint-result.json
```

The per-function folders under `functions/` are the starting points for the
next stage's taint-analysis agent: each agent is dispatched with one (or
several) folder(s) as its working directory and finds everything it needs
inside — the call inventory, the dynamic status of every site, and the
working request format that fed it. `functions-context/` and the
`context_probes` lists carry the rest of the inventory: unfed sites
(storage-channel / seeding candidates) and the getters' request templates
(read side of the cross-request storage transfer, the next stage's second
data-dependency kind — stage 2 maps reception only).

## Host prerequisites

Ghidra (`deps/ghidra_12.1.4_PUBLIC`, see `rehost/build-deps.sh`) with Java 21,
`gdb-multiarch` (same version family as host gdb), Docker, and the solved
image. The gdb path needs no changes to solved images: QEMU's `-s` binds
`0.0.0.0:1234` and the driver attaches over the container bridge IP.