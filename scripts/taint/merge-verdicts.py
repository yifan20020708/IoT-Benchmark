#!/usr/bin/env python3
"""agent-scan :: taint — merge parallel chunk verdicts + repair analysis.

Usage: merge-verdicts.py <spec.json> <chunk-dir>... --out F
                         [--events F] [--analysis F]

Each chunk dir holds one verify-request.sh run (verdicts.json,
events.jsonl, send-times.json); its chunk spec sits next to it as
<dirname>.json. The merge is pass-if-any per probe: canaries are
VALUE-based (per probe, per run) and every chunk boots its own container,
so a pass in any chunk is an independent fresh-canary proof and a pass in
chunk A cannot be faked by events from chunk B (different canary values).

The analysis half plans the repair round from MEASURED behavior only —
send-time gaps per chunk (healthy sends are 3-7s; a trailing run of
~20s+ gaps is the daemon-wedge signature: one probe's handler stops the
daemon after it responds). The two boundary probes of each trailing slow
run become suspects (isolated alone when retried, so a wedge probe can
only kill its own boot); failed probes outside the suspect set are
victims (retried on clean boots with a fresh session bootstrap).

Verdict priority when merging: pass > the latest chunk's verdict.
Analysis fields are expect-blind (the batch driver filters by expect).
"""
import argparse, json, os, sys

SLOW_GAP = 15.0   # healthy send+sleep gaps are 5-9s; wedged ones ~22s


def load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("chunkdirs", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--events")
    ap.add_argument("--analysis")
    args = ap.parse_args()

    spec = load(args.spec)
    if not isinstance(spec, dict) or not isinstance(spec.get("probes"), list):
        sys.exit("[-] spec is not a valid probe spec")
    probes = spec["probes"]

    chunks = []
    for d in args.chunkdirs:
        d = d.rstrip("/")
        name = os.path.basename(d)
        chunks.append({
            "name": name,
            "v": load(os.path.join(d, "verdicts.json")),
            "s": load(os.path.join(d, "send-times.json")) or {},
            "cs": load(os.path.join(d, "..", name + ".json")),
            "events": os.path.join(d, "events.jsonl"),
        })
    live = [c for c in chunks if c["v"] is not None]
    if not live:
        sys.exit("[-] no chunk produced verdicts.json — nothing to merge")

    # ---- merged events (annotated with the chunk they came from) --------
    if args.events:
        with open(args.events, "w") as ef:
            for c in chunks:
                if not os.path.exists(c["events"]):
                    continue
                with open(c["events"], errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            e = json.loads(line)
                        except Exception:
                            continue
                        e["chunk"] = c["name"]
                        ef.write(json.dumps(e, ensure_ascii=False) + "\n")

    # ---- per-probe merge (pass-if-any; evidence from a passing chunk) ----
    RANK = {"pass": 0, "no-canary": 1, "no-hit": 2}
    results = []
    all_pass = True
    for p in probes:
        pid = p.get("id")
        recs = []
        for c in chunks:
            for r in (c["v"] or {}).get("probes", []):
                if r.get("probe") == pid:
                    recs.append({"chunk": c["name"], "r": r})
        if not recs:
            results.append({"probe": pid, "verdict": "no-verdict"})
            all_pass = False
            continue
        passing = [x for x in recs if x["r"].get("verdict") == "pass"]
        chosen = passing[0]["r"] if passing else recs[-1]["r"]
        verdict = chosen.get("verdict")
        if verdict != "pass":
            all_pass = False
        out = {"probe": pid, "verdict": verdict,
               "verdicts_by_chunk": {x["chunk"]: x["r"].get("verdict")
                                     for x in recs},
               "source_symbol": chosen.get("source_symbol"),
               "source_hits": max((x["r"].get("source_hits") or 0)
                                  for x in recs),
               "entry_verified": any(x["r"].get("entry_verified")
                                     for x in recs),
               "entry_hits": max((x["r"].get("entry_hits") or 0)
                                 for x in recs),
               "canary_param_match": any(x["r"].get("canary_param_match")
                                         for x in recs),
               "canary_evidence": chosen.get("canary_evidence") or [],
               "return_evidence": chosen.get("return_evidence") or [],
               "request_sent_at": min(
                   (x["r"].get("request_sent_at") or 0) for x in recs
                   if x["r"].get("request_sent_at")) or None}
        results.append(out)

    merged = {"spec": os.path.basename(args.spec),
              "all_pass": all_pass,
              "web_ready": any(c["v"].get("web_ready") for c in live),
              "probes": results}
    json.dump(merged, open(args.out, "w"), indent=2, ensure_ascii=False)

    # ---- slow-zone analysis (mechanical, from send timings) --------------
    failed = [r["probe"] for r in results if r["verdict"] != "pass"]
    suspects, slow_zones, skipped = set(), [], []
    for c in chunks:
        sends = c["s"]
        for pid, v in sends.items():
            if isinstance(v, dict) and v.get("skipped"):
                skipped.append(pid)
        sent = sorted((v["t"], pid) for pid, v in sends.items()
                      if isinstance(v, dict) and isinstance(v.get("t"), (int, float)))
        if len(sent) < 2:
            continue
        gaps = [sent[i + 1][0] - sent[i][0] for i in range(len(sent) - 1)]
        slow = [g >= SLOW_GAP for g in gaps]
        if not any(slow):
            continue
        trailing = None
        for j in range(len(slow)):
            if all(slow[j:]):
                trailing = j
                break
        if trailing is None:
            continue
        run_len = len(slow) - trailing
        zone = {"chunk": c["name"], "trailing_slow_sends": run_len,
                "suspects": []}
        # boundary: the fast sender right before the slow run (poisoned the
        # daemon after answering) and the first slow sender (its own send
        # may be the one that hung)
        if trailing >= 1:
            zone["suspects"].append(sent[trailing - 1][1])
        zone["suspects"].append(sent[trailing][1])
        suspects.update(zone["suspects"])
        slow_zones.append(zone)

    analysis = {"failed": failed,
                "suspects": sorted(suspects),
                "victims": sorted(set(failed) - suspects),
                "skipped_budget": sorted(set(skipped)),
                "slow_zones": slow_zones,
                "infra_failed_chunks": [c["name"] for c in chunks
                                        if c["v"] is None],
                "chunk_pass": {c["name"]: sum(
                    1 for r in (c["v"] or {}).get("probes", [])
                    if r.get("verdict") == "pass") for c in live}}
    if args.analysis:
        json.dump(analysis, open(args.analysis, "w"), indent=2,
                  ensure_ascii=False)

    npass = sum(1 for r in results if r["verdict"] == "pass")
    print(f"[merge] {npass}/{len(results)} pass across {len(live)}/{len(chunks)} "
          f"chunk(s); failed={len(failed)} suspects={sorted(suspects)}")


if __name__ == "__main__":
    main()
