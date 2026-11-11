#!/usr/bin/env python3
"""agent-scan :: taint — assemble per-function folders for the next stage.

Usage: assemble-functions.py <model-dir> [--verdicts F] [--events F]

Runs as the driver's LAST step, after dynamic verification and the
call-site write-back. It reorganizes taint-source-output/functions/ into
the NEXT STAGE's starting-point set — genuinely-RECEIVING functions only:

    functions/                  stage-3 starting points: functions with at
                                least one dynamically-VERIFIED call site
        INDEX.json              starting_points (verified-site count, the
                                probes that fed them) + context_only list
        <binary__function>/
            <binary__function>.json   the function record (moved as-is,
                                      with its verify annotations)
            probes.json               reception_probes — the probes whose
                                      canary reached THIS function's call
                                      sites (the proven feeding requests);
                                      context_probes — probes that reached
                                      or armed this function without
                                      feeding it (dispatch context, and
                                      the READ-SIDE inventory the next
                                      stage's storage channel needs)
    functions-context/          every other record: sites never fed by any
                                canary (state-gated potentials — the
                                storage-channel / seeding candidates);
                                same folder shape, same probe view

A probe belongs to a function when (a) its entry_break matches the
function (the dispatch handler — relation "handler") or (b) any of the
function's recorded call addresses is armed in the probe's ret_breaks
(a helper armed by that probe — relation "helper"). One probe can (and
does) appear in several folders; it EXECUTES once, so every folder sees
the same verdict — content and results stay consistent by construction.

Pure getters never own a folder (they hold no taint-source call records);
they surface only as context_probes — request templates for the read side
of the setter->storage->getter channel, which belongs to the NEXT stage.

Purely mechanical joins over existing artifacts (probes.json, the
function records, the merged driver verdicts, the merged events). A
report, not a gate: exit 0 always; probes mapping to no record are
reported as orphans. Idempotent: flat records and already-assembled
folders are both valid inputs, so the step can be re-run in place.
"""
import argparse, glob, json, os, re, shutil, sys


def norm(s):
    if isinstance(s, int):
        return format(s, "x")
    return re.sub(r"^0x", "", str(s)).lower().lstrip("0")


def ent_key(s):
    s = str(s or "").strip().lstrip("*").lower()
    return re.sub(r"^0x", "", s)


def hex_tail(s):
    m = re.search(r"([0-9a-f]{4,})$", str(s or ""))
    return m.group(1) if m else None


def canary_fields(request):
    """field -> channel type for every canary-bearing field in the -d body"""
    out = {}
    body = None
    for i, a in enumerate(request or []):
        if a == "-d" and i + 1 < len(request):
            body = request[i + 1]
            break
    if not body:
        return out
    for m in re.finditer(
            r'["\']?([A-Za-z0-9_\-\.]+)["\']?\s*[:=]\s*["\']([^"\']*)["\']',
            str(body)):
        field, val = m.group(1), m.group(2)
        if "{{CANARY_INT}}" in val:
            out[field] = "int"
        elif "{{CANARY}}" in val:
            out[field] = "string"
    return out


def load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def collect_records(out):
    """all function records, from flat files or already-assembled folders.
    Returns [(name, path, current_base)] where base is 'functions' or
    'functions-context' (None for a flat file under functions/)."""
    found = {}
    for base in ("functions", "functions-context"):
        d = os.path.join(out, base)
        for p in sorted(glob.glob(os.path.join(d, "*.json"))):
            if os.path.basename(p) == "INDEX.json":
                continue
            found.setdefault(os.path.basename(p)[:-5], (p, base))
        for p in sorted(glob.glob(os.path.join(d, "*", "*.json"))):
            if os.path.basename(p) != "probes.json":
                found.setdefault(os.path.basename(p)[:-5], (p, base))
    return [(n, p, b) for n, (p, b) in found.items()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("--verdicts", help="merged driver verdicts.json")
    ap.add_argument("--events", help="merged driver events.jsonl")
    args = ap.parse_args()

    out = os.path.join(args.model, "taint-source-output")
    fndir = os.path.join(out, "functions")
    ctxdir = os.path.join(out, "functions-context")

    spec = load(os.path.join(out, "probes.json"))
    if not isinstance(spec, dict) or not spec.get("probes"):
        sys.exit("[-] no probes.json under taint-source-output — nothing to assemble")
    probes = spec["probes"]

    verdicts = {}
    if args.verdicts and os.path.exists(args.verdicts):
        for r in (load(args.verdicts) or {}).get("probes", []):
            verdicts[r.get("probe")] = r

    # ret events -> {probe id: set(norm call addresses proven)} (a return
    # event's address is the call address + arch delay: 4 arm, 8 mips)
    verified_by_probe = {}
    if args.events and os.path.exists(args.events):
        for line in open(args.events, errors="replace"):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event") != "ret_hit" or not e.get("address") \
                    or not e.get("canary_hits") or not e.get("probe"):
                continue
            try:
                av = int(re.sub(r"^\*?0x", "", str(e["address"])), 16)
            except ValueError:
                continue
            for d in (4, 8):
                call = format(av - d, "x")
                verified_by_probe.setdefault(e["probe"], set()).add(call)
                break

    records = collect_records(out)
    if not records:
        sys.exit("[-] no function records under functions/ or "
                 "functions-context/ — nothing to assemble")

    matched_ids = set()
    index = {"starting_points": {}, "context_only": []}
    n_start = n_ctx = n_handler = n_helper = n_reception = n_bare = 0
    for name, path, base in records:
        rec = load(path)
        if not rec or not isinstance(rec.get("taint_source_calls"), list):
            continue
        call_set = {norm(c.get("call_address"))
                    for c in rec["taint_source_calls"]
                    if c.get("call_address")}
        # classification: the record's own write-back annotations decide;
        # events are the fallback when no write-back ran (nothing verified
        # then either, but the probe view still needs per-probe attribution)
        verified_sites = {norm(c.get("call_address")) for c in
                          rec["taint_source_calls"]
                          if c.get("verify") == "verified"}
        if not verified_sites:
            for p in probes:
                verified_sites |= verified_by_probe.get(p.get("id"), set()) & call_set
        starting = bool(verified_sites)

        fn_entry = ent_key(rec.get("function"))
        fn_tail = hex_tail(rec.get("function")) or hex_tail(rec.get("address"))
        fn_addr = norm(rec.get("address")) if rec.get("address") else None

        reception, context = [], []
        for p in probes:
            pid = p.get("id")
            armed_here = sorted(call_set & {norm(a)
                                            for a in (p.get("ret_breaks") or [])})
            entry_match = False
            pe = p.get("entry_break")
            if pe:
                pk, pt = ent_key(pe), hex_tail(pe)
                entry_match = (pk and pk == fn_entry) \
                    or (fn_tail and pt and pt == fn_tail) \
                    or (fn_addr and pk == fn_addr)
            if not (entry_match or armed_here):
                continue
            matched_ids.add(pid)
            v = verdicts.get(pid) or {}
            fed_here = sorted(verified_by_probe.get(pid, set()) & call_set)
            view = {
                "id": pid,
                "expect": p.get("expect") or "pass",
                "request": p.get("request"),
                "source_break": p.get("source_break"),
                "entry_break": pe,
                "ret_breaks": p.get("ret_breaks") or [],
                "canary_param": p.get("canary_param"),
                "canary_param_type":
                    canary_fields(p.get("request")).get(p.get("canary_param")),
                "canary_fields": canary_fields(p.get("request")),
                "relation": "handler" if entry_match else "helper",
                "driver_verdict": v.get("verdict"),
                "armed_sites_here": armed_here,
                "verified_sites_here": fed_here,
            }
            (reception if fed_here else context).append(view)
            if entry_match:
                n_handler += 1
            else:
                n_helper += 1

        target_base = "functions" if starting else "functions-context"
        target = os.path.join(out, target_base, name)
        os.makedirs(target, exist_ok=True)
        json.dump(rec, open(os.path.join(target, name + ".json"), "w"),
                  indent=2, ensure_ascii=False)
        json.dump({"function": name, "binary": rec.get("binary"),
                   "starting_point": starting,
                   "verified_sites": sorted(verified_sites),
                   "reception_probes": reception,
                   "context_probes": context},
                  open(os.path.join(target, "probes.json"), "w"),
                  indent=2, ensure_ascii=False)
        # remove the SOURCE location: a flat record is foldered in place; a
        # relocated record takes its whole old folder with it (when both a
        # flat file and an old folder existed, the writes above already
        # regenerated the folder's contents)
        if os.path.isfile(path) \
                and os.path.dirname(path) == os.path.join(out, base) \
                and os.path.realpath(path) != os.path.realpath(
                    os.path.join(target, name + ".json")):
            os.remove(path)
        old_dir = os.path.join(out, base, name)
        if base != target_base and os.path.isdir(old_dir) \
                and os.path.realpath(old_dir) != os.path.realpath(target):
            shutil.rmtree(old_dir)
        if starting:
            n_start += 1
            index["starting_points"][name] = {
                "binary": rec.get("binary"),
                "verified_sites": len(verified_sites),
                "reception_probes": len(reception),
                "context_probes": len(context),
            }
        else:
            n_ctx += 1
            index["context_only"].append(name)
        if not (reception or context):
            n_bare += 1
        if reception:
            n_reception += 1

    os.makedirs(fndir, exist_ok=True)
    json.dump(index, open(os.path.join(fndir, "INDEX.json"), "w"),
              indent=2, ensure_ascii=False)

    orphans = sorted(p.get("id") for p in probes
                     if p.get("id") not in matched_ids)
    print(f"[assemble] {n_start} starting-point folder(s) under functions/, "
          f"{n_ctx} under functions-context/; "
          f"{n_handler} handler + {n_helper} helper probe placements; "
          f"{n_reception} folder(s) with reception probes; "
          f"{n_bare} folder(s) without probes (static-only records)")
    if orphans:
        print(f"[assemble] {len(orphans)} probe(s) map to no function record"
              f" (first: {orphans[:5]})")


if __name__ == "__main__":
    main()
