#!/usr/bin/env python3
# agent-scan :: taint — mapper-check.py — Phase-1 Mapper contract check
# (shape only), invoked by mapper-run.sh after the agent exits, and
# standalone to re-check an existing taint-work-output (e.g. one
# regenerated from the agent's own deterministic pipeline):
#
#   mapper-check.py <model-dir> <run-dir> <agent-rc> <agent-dur-s> <timeout-s> <task-id>
#
#   mapper-check.py --probe <model-dir>
#     read-only pre-flight with the SAME validation rules and zero side
#     effects: no prune/normalize rewrites, no folder removal, no
#     result.json. The mapper-prompt tells the agent to run this before
#     finishing so shape violations are fixed in-run; the post-exit gate
#     above stays the only writer (and the batch's resume semantics stay
#     intact — a probe never leaves a result.json behind).
#
# Zero content judgment — which call sites are real sources is the next
# phase's business. Two shape-level transforms, both archived and counted
# in <run-dir>/result.json:
#
# PRUNE — records the contract defines as invalid are DELETED (a dispatch
#   route with a null handler answers no Verifier question; an item
#   missing a required key is not an observation point). A class losing
#   more than 10% of its records to pruning is systematic deviation, not
#   variance: the run is output_incomplete (fix the prompt, rerun) —
#   never trimmed away silently.
#
# NORMALIZE — a mechanical field-name alias is RENAMED, never deleted: the
#   contract names the per-item key `field` in sources.json and `key` in
#   getters.json; an agent-side packer emitting the other name has the
#   content right and only the name wrong (TN3108: 1002/1002 getters
#   arrived as `field`). Lossless, archived, counted in result.json's
#   "normalized" — never guard-firing, because nothing is lost.
#
# Everything the checker rewrites is archived first, so pruned or renamed
# records stay recoverable: top-level files to <run-dir>/<name>.raw.json,
# functions/ files to <run-dir>/functions-raw/<pkg>/<kind>. The checker
# never invents values — it only deletes invalid records and renames
# aliases.
#
# Exit 0 iff status == success.
import glob, json, os, shutil, sys

# --probe <model-dir>: read-only shape pre-flight for the agent's own
# self-check (see header). All validation paths are shared; every mutation
# site (rewrite / prune / rmtree / result.json) is gated on not PROBE.
PROBE = len(sys.argv) > 1 and sys.argv[1] == "--probe"
if PROBE:
    if len(sys.argv) != 3:
        sys.exit("usage: mapper-check.py --probe <model-dir>")
    model = sys.argv[2]
    rundir = ""
    agent_rc, agent_dur, timeout, task = 0, 0, 0, "probe"
else:
    model, rundir = sys.argv[1:3]
    agent_rc, agent_dur, timeout, task = (int(sys.argv[3]), int(sys.argv[4]),
                                          int(sys.argv[5]), sys.argv[6])
out = os.path.join(model, "taint-work-output")
errors = []
pruned = {}
normalized = {}
PLACEHOLDER = ("None", "null", "N/A")
PRUNE_FRAC = 0.10
RAWDIR = os.path.join(rundir, "functions-raw")

def load(name):
    p = os.path.join(out, name)
    if not os.path.isfile(p):
        errors.append(f"missing {name}")
        return None
    try:
        return json.load(open(p))
    except Exception as e:
        errors.append(f"{name}: not valid JSON: {e}")
        return None

def truthy(v):
    return bool(v) and not (isinstance(v, str) and v.strip() in PLACEHOLDER)

def guard(cls, n_pruned, n_pre):
    """anti-hollowing line: >10% pruned in a class is systematic deviation
    (fix the prompt, rerun) — never variance to trim away"""
    if n_pre and n_pruned / n_pre > PRUNE_FRAC:
        errors.append(f"{cls}: pruned {n_pruned}/{n_pre} records (>10%) "
                      "— systematic deviation, rerun")

def rewrite(name, obj):
    """archive the agent's original into the run dir, write the pruned file"""
    if PROBE:
        return
    shutil.copyfile(os.path.join(out, name), os.path.join(rundir, name + ".raw.json"))
    json.dump(obj, open(os.path.join(out, name), "w"), indent=2, ensure_ascii=False)

# boundary.json
b = load("boundary.json")
if isinstance(b, dict) and isinstance(b.get("binaries"), list) and b["binaries"]:
    keep = [x for x in b["binaries"] if isinstance(x, dict) and truthy(x.get("path"))]
    if len(keep) < len(b["binaries"]):
        pruned["boundary.binaries"] = len(b["binaries"]) - len(keep)
        guard("boundary.json binaries", pruned["boundary.binaries"], len(b["binaries"]))
        b["binaries"] = keep
        rewrite("boundary.json", b)
    if not b["binaries"]:
        errors.append("boundary.json: empty 'binaries' after pruning")
elif isinstance(b, dict) and not errors:
    errors.append("boundary.json: empty 'binaries'")

# dispatch.json — a route with no handler answers no Verifier question:
# drop it (its reachability story belongs in auth.json, not here)
d = load("dispatch.json")
if isinstance(d, dict) and isinstance(d.get("routes"), list) and d["routes"]:
    keep = [r for r in d["routes"] if isinstance(r, dict)
            and truthy(r.get("endpoint"))
            and truthy(r.get("handler_function"))
            and truthy(r.get("handler_binary"))]
    if len(keep) < len(d["routes"]):
        pruned["dispatch.routes"] = len(d["routes"]) - len(keep)
        guard("dispatch.json routes", pruned["dispatch.routes"], len(d["routes"]))
        d["routes"] = keep
        rewrite("dispatch.json", d)
    if not d["routes"]:
        errors.append("dispatch.json: empty 'routes' after pruning")
elif isinstance(d, dict) and not errors:
    errors.append("dispatch.json: empty 'routes'")

# auth.json — no prunable shape: an unproven recipe is a real failure
a = load("auth.json")
if isinstance(a, dict):
    for k in ("mechanism", "acquisition", "attach",
              "no_auth_endpoints", "auth_required_endpoints", "evidence"):
        if k not in a:
            errors.append(f"auth.json: missing '{k}'")
    if a.get("tested") is not True:
        errors.append("auth.json: 'tested' is not true — recipe unproven")

# functions/<binary>__<function>/{sources,getters}.json
# itemkey = the contract's per-item key name; aliaskey = the other side's
# name — a packer emitting aliaskey with the value in place is renamed,
# not pruned (mechanical, lossless, archived, never guard-firing)
n_pkgs = n_src = n_get = 0
n_items = n_pruned_items = 0
hollowed = 0
for fd in sorted(glob.glob(os.path.join(out, "functions", "*"))):
    if not os.path.isdir(fd):
        continue
    fname = os.path.basename(fd)
    n_here = 0
    both_files = True
    for kind, listkey, itemkey, aliaskey in (
            ("sources.json", "sources", "field", "key"),
            ("getters.json", "getters", "key", "field")):
        p = os.path.join(fd, kind)
        if not os.path.isfile(p):
            errors.append(f"functions/{fname}/{kind}: missing")
            both_files = False
            continue
        try:
            j = json.load(open(p))
        except Exception as e:
            errors.append(f"functions/{fname}/{kind}: not valid JSON: {e}")
            both_files = False
            continue
        if not isinstance(j, dict):
            errors.append(f"functions/{fname}/{kind}: top-level "
                          f"{type(j).__name__}, expected an object")
            both_files = False
            continue
        for k in ("binary", "function", "function_addr", "requests", listkey):
            if k not in j:
                errors.append(f"functions/{fname}/{kind}: missing '{k}'")
        items = j.get(listkey) or []
        n_items += len(items)
        n_norm = 0
        for it in items:
            if isinstance(it, dict) and itemkey not in it and aliaskey in it:
                it[itemkey] = it.pop(aliaskey)
                n_norm += 1
        keep = [it for it in items if isinstance(it, dict)
                and all(k in it for k in
                        ("call_addr", "ret_site", "callee", itemkey, "callsite"))]
        if n_norm or len(keep) < len(items):
            if n_norm:
                key = f"functions.{listkey}.{aliaskey}_to_{itemkey}"
                normalized[key] = normalized.get(key, 0) + n_norm
            if len(keep) < len(items):
                n_pruned_items += len(items) - len(keep)
            if not PROBE:
                # archive the agent's original before any rewrite — pruned or
                # renamed records must stay recoverable
                dst = os.path.join(RAWDIR, fname, kind)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(p, dst)
                j[listkey] = keep
                json.dump(j, open(p, "w"), indent=2, ensure_ascii=False)
        if kind == "sources.json":
            n_src += len(keep)
        else:
            n_get += len(keep)
        n_here += len(keep)
    # a folder exists iff it holds at least one site: a both-empty folder
    # (agent-written or pruned-empty) is removed with its files
    if both_files and n_here == 0:
        if not PROBE:
            shutil.rmtree(fd)
        hollowed += 1
        continue
    n_pkgs += 1
if n_pruned_items:
    pruned["functions.items"] = n_pruned_items
    guard("functions items", n_pruned_items, n_items)
if hollowed:
    pruned["functions.packages_hollowed"] = hollowed
if n_pkgs == 0:
    errors.append("functions/: no work packages")

status = ("success" if not errors and agent_rc == 0
          else "agent_timeout" if agent_rc == 124
          else "output_incomplete" if agent_rc == 0
          else "agent_error")
result = {"task": task, "status": status, "agent_rc": agent_rc,
          "duration_s": agent_dur, "timeout_s": timeout,
          "packages": n_pkgs, "sources": n_src, "getters": n_get,
          "pruned": pruned, "normalized": normalized, "errors": errors[:20]}
if PROBE:
    # all violations to stdout (the agent fixes from this list); no files
    # touched, no result.json — the post-exit gate is the only writer
    print(f"[mapper-check probe] {'CLEAN — would pass the gate' if not errors else 'VIOLATIONS:'}")
    if pruned:
        print(f"  would-prune: {pruned}")
    if normalized:
        print(f"  would-normalize (lossless, auto-fixed at the gate): {normalized}")
    for e in errors:
        print(f"  ! {e}")
    sys.exit(0 if not errors else 1)

json.dump(result, open(os.path.join(rundir, "result.json"), "w"), indent=2)
print(f"[mapper-check] status={status} packages={n_pkgs} "
      f"sources={n_src} getters={n_get}")
if pruned:
    print(f"  pruned: {pruned}")
if normalized:
    print(f"  normalized: {normalized}")
for e in errors[:10]:
    print(f"  ! {e}")
sys.exit(0 if status == "success" else 1)
