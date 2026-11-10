#!/usr/bin/env python3
"""agent-scan :: taint — mechanical probe-batch splitter for parallel boots.

Usage: chunk-probes.py [--chunks N | --size K] [--isolate id,id,...]
                       [--prefix P] <spec.json> <outdir>

A full-coverage verify-request.sh batch (one probe per entry, every call
site armed) is too big for ONE boot: hundreds of armed breakpoints also
sit on the guest's own init path and grind it to a halt. This splitter
carves a spec into chunk specs so each chunk runs in its own container,
boot, and fresh-canary run — value-based canary attribution makes the
chunks independent evidence sources.

PURELY mechanical rules (no firmware knowledge, safe for the driver to
apply to any agent-authored spec):
  * order-preserving split of the probe list (the agent's probe order is
    its own firmware knowledge — state-mutating probes, re-login
    sequences — and is preserved within each chunk)
  * session bootstrap replication: a probe that WRITES a curl cookie jar
    (-c PATH) that other probes READ (-b PATH) is moved to the front of
    its chunk, or copied to the front of every reader chunk lacking it,
    so every fresh boot re-establishes its own session first
  * --isolate: the listed probe ids each get their own single-probe chunk
    (repair rounds: a slow/wedge-suspect probe can then only kill its
    own boot)
  * --group-by: chunk boundaries snap to handler groups — probes sharing
    an entry_break (each probe has exactly one) never split across
    chunks, so one chunk ≈ the probes of consecutive functions and the
    re-verification is function-granular (a repair round retries whole
    functions, and per-function probe views line up with the chunks)

Chunk count: --chunks N > spec's optional top-level "chunks" hint
(agent-specified, clamped to 1..32) > ceil(n/32). Chunk stems feed
verify-request.sh's container and work-dir naming, so the prefix must be
unique per batch. Writes <outdir>/<prefix>-chunk-01.json ... plus
<outdir>/manifest.json.
"""
import argparse, json, math, os, sys


def jar_paths(request, flag):
    """cookie-jar paths used with a given curl flag (-c write / -b read)"""
    paths = []
    for i, a in enumerate(request or []):
        if a == flag and i + 1 < len(request) \
                and not str(request[i + 1]).startswith("-"):
            paths.append(str(request[i + 1]))
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("outdir")
    ap.add_argument("--chunks", type=int, default=None,
                    help="number of chunks (default: spec 'chunks' hint, else ceil(n/32))")
    ap.add_argument("--size", type=int, default=None,
                    help="max probes per chunk (overrides --chunks)")
    ap.add_argument("--isolate", default="",
                    help="comma-separated probe ids that get one chunk each")
    ap.add_argument("--group-by", action="store_true",
                    help="snap chunk boundaries to entry_break (handler) groups")
    ap.add_argument("--prefix", default="chunk",
                    help="chunk stem prefix (must be unique per batch)")
    args = ap.parse_args()

    try:
        spec = json.load(open(args.spec))
    except Exception as e:
        sys.exit(f"[-] spec is not valid JSON: {e}")
    probes = spec.get("probes")
    if not isinstance(probes, list) or not probes:
        sys.exit("[-] spec must hold a non-empty 'probes' list")

    # ---- session bootstrap detection (generic curl semantics) ------------
    writes, reads = {}, {}          # jar path -> writers / reader ids
    for p in probes:
        for path in jar_paths(p.get("request"), "-c"):
            writes.setdefault(path, []).append(p)
        for path in jar_paths(p.get("request"), "-b"):
            reads.setdefault(path, set()).add(p.get("id"))
    bootstraps = {}                 # jar path -> writer probe (first in spec order)
    for path, writers in writes.items():
        if reads.get(path):
            bootstraps[path] = writers[0]

    by_id = {p.get("id"): p for p in probes}
    isolate = [i.strip() for i in args.isolate.split(",") if i.strip()]
    for i in isolate:
        if i not in by_id:
            sys.exit(f"[-] --isolate id not in spec: {i}")

    # ---- order-preserving split (+ isolated single-probe chunks) ----------
    rest = [p for p in probes if p.get("id") not in set(isolate)]
    if args.size:
        size = max(1, args.size)
    elif args.chunks:
        n = min(64, max(1, args.chunks))
        size = max(1, math.ceil(len(rest) / n))
    else:
        hint = spec.get("chunks")
        n = hint if isinstance(hint, int) and 1 <= hint <= 32 \
            else max(1, math.ceil(len(probes) / 32))
        size = max(1, math.ceil(len(rest) / n))
    chunks = []
    if args.group_by:
        # handler groups in first-appearance order; a group is never split
        # unless it alone exceeds the chunk size
        groups = {}
        for p in rest:
            groups.setdefault(str(p.get("entry_break") or ""), []).append(p)
        cur = []
        for g in groups.values():
            if len(g) > size:
                if cur:
                    chunks.append(cur)
                    cur = []
                chunks += [g[i:i + size] for i in range(0, len(g), size)]
            elif len(cur) + len(g) > size:
                chunks.append(cur)
                cur = list(g)
            else:
                cur += list(g)
        if cur:
            chunks.append(cur)
    else:
        chunks = [rest[i:i + size] for i in range(0, len(rest), size)]
    chunks += [[by_id[i]] for i in isolate]

    def ensure_bootstrap(chunk):
        """front-load the session bootstrap writer for every jar read here"""
        out = list(chunk)
        for path in sorted(bootstraps):
            writer = bootstraps[path]
            if not any(p.get("id") in reads[path] for p in out):
                continue          # nobody in this chunk needs that session
            if any(p.get("id") == writer.get("id") for p in out):
                w = next(p for p in out if p.get("id") == writer.get("id"))
                out.remove(w)     # move, never duplicate
                out.insert(0, w)
            else:
                out.insert(0, dict(writer))
        ids = [p.get("id") for p in out]
        if len(ids) != len(set(ids)):
            sys.exit("[-] internal error: duplicate probe id within a chunk")
        return out

    os.makedirs(args.outdir, exist_ok=True)
    manifest = {"prefix": args.prefix,
                "bootstraps": {p: w.get("id") for p, w in bootstraps.items()},
                "chunk_count": len(chunks), "chunks": []}
    total = 0
    for n, raw in enumerate(chunks, 1):
        chunk = ensure_bootstrap(raw)
        cs = dict(spec)
        cs["probes"] = chunk
        name = f"{args.prefix}-chunk-{n:02d}.json"
        json.dump(cs, open(os.path.join(args.outdir, name), "w"),
                  indent=2, ensure_ascii=False)
        manifest["chunks"].append({"file": name, "probes": len(chunk),
                                   "original": len(raw)})
        total += len(chunk)
    manifest["probe_slots"] = total
    manifest["probe_count"] = len(probes)
    json.dump(manifest, open(os.path.join(args.outdir, "manifest.json"), "w"),
              indent=2, ensure_ascii=False)
    bs = ", ".join(f"{p} -> {w}" for p, w in manifest["bootstraps"].items()) or "none"
    print(f"[chunk] {len(chunks)} chunk(s), {total} probe slots "
          f"(spec holds {len(probes)}; bootstrap copies: {total - len(probes)})")
    print(f"[chunk] session bootstraps: {bs}")


if __name__ == "__main__":
    main()
