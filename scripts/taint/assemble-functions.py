#!/usr/bin/env python3
"""agent-scan :: taint — assemble per-function folders for the next stage.

Usage: assemble-functions.py <model-dir> [--verdicts F] [--events F]

Runs as the driver's LAST step, after dynamic verification and the
call-site write-back. It reorganizes taint-source-output/functions/ from
flat record files into one folder per containing function, so each
next-stage agent gets a self-contained working directory:

    functions/<binary__function>/
        <binary__function>.json   the function record (moved as-is, with
                                  its verify annotations)
        probes.json               the probes that exercise THIS function:
                                  the verbatim request template (the
                                  proven-good network request format),
                                  source/entry breaks, ret_breaks,
                                  per-field canary channel types, the
                                  driver's final verdict, and which of
                                  this function's call sites the probe
                                  verified

A probe belongs to a function when (a) its entry_break matches the
function (the dispatch handler — relation "handler") or (b) any of the
function's recorded call addresses is armed in the probe's ret_breaks
(a helper armed by that probe — relation "helper"). One probe can (and
does) appear in several folders; it EXECUTES once, so every folder sees
the same verdict — content and results stay consistent by construction.

Purely mechanical joins over existing artifacts (probes.json, the flat
function records, the merged driver verdicts, the merged events). A
report, not a gate: exit 0 always; probes mapping to no record are
reported as orphans.
"""
import argparse, glob, json, os, re, sys


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("--verdicts", help="merged driver verdicts.json")
    ap.add_argument("--events", help="merged driver events.jsonl")
    args = ap.parse_args()

    out = os.path.join(args.model, "taint-source-output")
    fndir = os.path.join(out, "functions")

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

    records = sorted(glob.glob(os.path.join(fndir, "*.json")))
    if not records:
        sys.exit("[-] no flat function records under functions/ — nothing to assemble")

    matched_ids = set()
    n_handler = n_helper = n_bare = 0
    for path in records:
        rec = load(path)
        if not rec or not isinstance(rec.get("taint_source_calls"), list):
            continue
        name = os.path.basename(path)[:-5]
        call_set = {norm(c.get("call_address"))
                    for c in rec["taint_source_calls"]
                    if c.get("call_address")}
        fn_entry = ent_key(rec.get("function"))
        fn_tail = hex_tail(rec.get("function")) or hex_tail(rec.get("address"))
        fn_addr = norm(rec.get("address")) if rec.get("address") else None

        entries = []
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
            entries.append({
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
                "verified_sites_here": sorted(
                    verified_by_probe.get(pid, set()) & call_set),
            })
            if entry_match:
                n_handler += 1
            else:
                n_helper += 1

        folder = os.path.join(fndir, name)
        os.makedirs(folder, exist_ok=True)
        json.dump(rec, open(os.path.join(folder, name + ".json"), "w"),
                  indent=2, ensure_ascii=False)
        os.remove(path)
        json.dump({"function": name, "binary": rec.get("binary"),
                   "probes": entries},
                  open(os.path.join(folder, "probes.json"), "w"),
                  indent=2, ensure_ascii=False)
        if not entries:
            n_bare += 1

    orphans = sorted(p.get("id") for p in probes
                     if p.get("id") not in matched_ids)
    print(f"[assemble] {len(records)} function folder(s); "
          f"{n_handler} handler + {n_helper} helper probe placements; "
          f"{n_bare} folder(s) without probes (static-only records)")
    if orphans:
        print(f"[assemble] {len(orphans)} probe(s) map to no function record"
              f" (first: {orphans[:5]})")


if __name__ == "__main__":
    main()
