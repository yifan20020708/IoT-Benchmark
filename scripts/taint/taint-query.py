#!/usr/bin/env python3
"""
agent-scan :: taint — query layer over a Ghidra xref index (host-side)

Usage: taint-query.py <index.json> <command> [args...]

Commands (deterministic; all output human-readable unless --json):

  callsites <function>      every place that calls <function>: caller,
                            call address, argument strings — merged from the
                            reference-manager call_sites (with addresses) and
                            the decompiled text_calls (with resolved PIC
                            arithmetic args)
  strings-in <function>     all string constants <function> references
  xrefs <string>            all functions whose code references <string>
                            (strings list or call arguments)
  callers <function>        functions that call <function> (unique)
  fn <function>             full index entry of <function>
  colocate --keywords F     rank functions by co-location with the frontend
                            keyword set F (frontend-keywords.py output):
                            weighted hits across buckets — the wrapped-source
                            candidate detector (a by-name accessor must hold
                            the parameter names it looks up)
  list [--prefix P]         function names in the index (optionally filtered)

<function> matches a name (formSetWanIP) or name@address
(formSetWanIP@00048894) — LOCAL symbols may repeat, all matches are shown.
Exit 0 on success (empty results are still success), 1 on bad input/missing
function.
"""

import argparse
import json
import signal
import sys
from pathlib import Path

# die silently on SIGPIPE when output is piped into head/less
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

# frontend-keywords.py buckets and their co-location weights — the signal
# strength of "this string is a parameter/endpoint name"
BUCKET_WEIGHTS = {
    "js_net_keys": 3,
    "param_names": 3,
    "action_names": 2,
    "endpoints": 2,
    "js_keys": 1,
}


def load_index(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    for f in d["functions"]:
        f.setdefault("call_sites", [])
        f.setdefault("text_calls", [])
        f.setdefault("callers", [])
        f.setdefault("strings", [])
    return d


def fn_key(f):
    return f["name"] + "@" + f["address"]


def select_functions(index, pattern):
    """name or name@address; returns the matching entries."""
    if "@" in pattern:
        name, _, addr = pattern.partition("@")
        return [f for f in index["functions"]
                if f["name"] == name and f["address"].endswith(addr)]
    return [f for f in index["functions"] if f["name"] == pattern]


def cmd_callsites(index, pattern, as_json):
    targets = select_functions(index, pattern)
    if not targets:
        return fail(f"no such function: {pattern}")
    tnames = {t["name"] for t in targets}
    rows = []
    for f in index["functions"]:
        for cs in f["call_sites"]:
            if cs["to"] in tnames:
                rows.append({"caller": f["name"], "caller_address": f["address"],
                             "call_address": cs["address"], "args": cs["args"],
                             "origin": "ref"})
        for tc in f["text_calls"]:
            if tc["to"] in tnames:
                rows.append({"caller": f["name"], "caller_address": f["address"],
                             "call_address": None, "args": tc["args"],
                             "origin": "text"})
    rows.sort(key=lambda r: (r["caller"], r["call_address"] or ""))
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    print(f"{len(rows)} call site(s) of {pattern}:")
    for r in rows:
        at = r["call_address"] or "text"
        args = ", ".join(r["args"]) if r["args"] else "-"
        print(f"  {r['caller']:36s} @{at:10s} args: {args}")
    return 0


def cmd_strings_in(index, pattern, as_json):
    targets = select_functions(index, pattern)
    if not targets:
        return fail(f"no such function: {pattern}")
    for t in targets:
        if as_json:
            print(json.dumps({"function": fn_key(t), "strings": t["strings"]},
                             indent=2, ensure_ascii=False))
        else:
            print(f"{fn_key(t)}: {len(t['strings'])} strings")
            for s in sorted(t["strings"]):
                print(f"  {s!r}")
    return 0


def cmd_xrefs(index, string, as_json):
    rows = []
    for f in index["functions"]:
        origin = []
        if string in f["strings"]:
            origin.append("strings")
        for cs in f["call_sites"]:
            if string in cs["args"]:
                origin.append("call@" + cs["address"])
        for tc in f["text_calls"]:
            if string in tc["args"]:
                origin.append(f"call:{tc['to']}")
        if origin:
            rows.append({"function": fn_key(f), "origins": origin})
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    print(f"{len(rows)} function(s) referencing {string!r}:")
    for r in rows:
        print(f"  {r['function']:44s} {', '.join(r['origins'])[:70]}")
    return 0


def cmd_callers(index, pattern, as_json):
    targets = select_functions(index, pattern)
    if not targets:
        return fail(f"no such function: {pattern}")
    tnames = {fn_key(t) for t in targets}
    rows = []
    for f in index["functions"]:
        if any(fn_key(c) in tnames or c["name"] in {t["name"] for t in targets}
               for c in f["callers"]):
            rows.append(fn_key(f))
    if as_json:
        print(json.dumps(sorted(set(rows)), indent=2))
        return 0
    for r in sorted(set(rows)):
        print(f"  {r}")
    return 0


def cmd_fn(index, pattern, as_json):
    targets = select_functions(index, pattern)
    if not targets:
        return fail(f"no such function: {pattern}")
    if as_json:
        print(json.dumps(targets, indent=2, ensure_ascii=False))
        return 0
    for t in targets:
        print(json.dumps(t, indent=2, ensure_ascii=False))
    return 0


def cmd_colocate(index, keywords_path, as_json, top):
    kw = json.loads(Path(keywords_path).read_text(encoding="utf-8"))
    lookup = {}
    for bucket, weight in BUCKET_WEIGHTS.items():
        for entry in kw.get(bucket, []):
            name = entry["name"]
            lookup.setdefault(name, []).append((bucket, weight))
    rows = []
    for f in index["functions"]:
        hits = []
        for s in f["strings"]:
            if s in lookup:
                for bucket, weight in lookup[s]:
                    hits.append((s, bucket, weight))
        if hits:
            score = sum(h[2] for h in hits)
            rows.append({"function": fn_key(f), "score": score, "hits": hits})
    rows.sort(key=lambda r: -r["score"])
    if as_json:
        print(json.dumps(rows[:top], indent=2, ensure_ascii=False))
        return 0
    print(f"top {top} of {len(rows)} functions co-locating frontend keywords:")
    for r in rows[:top]:
        kws = " ".join(f"{h[0]}({h[1][:3]}={h[2]})" for h in r["hits"][:8])
        print(f"  {r['score']:4d}  {r['function']:40s} {kws}")
    return 0


def cmd_list(index, prefix, as_json):
    names = sorted({fn_key(f) for f in index["functions"]
                    if not prefix or f["name"].startswith(prefix)})
    if as_json:
        print(json.dumps(names, indent=2))
        return 0
    for n in names:
        print(f"  {n}")
    return 0


def fail(msg):
    print(f"[-] {msg}", file=sys.stderr)
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="query a Ghidra xref index (callsites/strings-in/"
                    "xrefs/callers/fn/colocate/list)")
    ap.add_argument("index", help="path to a ghidra-index.sh output JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("callsites", help="every place that calls <function>")
    p.add_argument("function")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("strings-in", help="strings referenced by <function>")
    p.add_argument("function")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("xrefs", help="functions referencing <string>")
    p.add_argument("string")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("callers", help="unique functions calling <function>")
    p.add_argument("function")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("fn", help="full index entry of <function>")
    p.add_argument("function")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("colocate", help="rank functions by frontend-keyword hits")
    p.add_argument("--keywords", required=True,
                   help="frontend-keywords.py output JSON")
    p.add_argument("--top", type=int, default=30)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("list", help="function names in the index")
    p.add_argument("--prefix", default="")
    p.add_argument("--json", action="store_true")

    args = ap.parse_args()
    index = load_index(args.index)
    if args.cmd == "callsites":
        sys.exit(cmd_callsites(index, args.function, args.json))
    if args.cmd == "strings-in":
        sys.exit(cmd_strings_in(index, args.function, args.json))
    if args.cmd == "xrefs":
        sys.exit(cmd_xrefs(index, args.string, args.json))
    if args.cmd == "callers":
        sys.exit(cmd_callers(index, args.function, args.json))
    if args.cmd == "fn":
        sys.exit(cmd_fn(index, args.function, args.json))
    if args.cmd == "colocate":
        sys.exit(cmd_colocate(index, args.keywords, args.json, args.top))
    if args.cmd == "list":
        sys.exit(cmd_list(index, args.prefix, args.json))


if __name__ == "__main__":
    main()
