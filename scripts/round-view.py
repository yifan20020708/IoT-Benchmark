#!/usr/bin/env python3
"""agent-scan — round-view: one static HTML ledger over data/round

Cross-stage read layer (rehost / taint / exploit) — lives at scripts/
top level, not inside any one stage.

Usage: round-view.py [--out PATH] [--root data/round]
       round-view.py --serve PORT [--org NAME --password PW]   (login gate)

Deterministic, stdlib-only, ZERO network dependencies (all CSS/JS inline —
no CDN, no webfont: this host's egress is restricted and a dashboard that
renders as a blank page is worse than a plain table).

What it shows
  (1) NOVELTY first: 0-DAY / N-DAY hero counters, N-DAY rows carry their
      CVE ID (cve_unverified entries are visibly flagged — citation law).
  (2) TRUTH mapping per benchmark policy: confidence grades the
      ATTRIBUTION chain, never the finding — the dashboard therefore
      collapses it to: high|medium -> CONFIRMED (real), low -> REJECTED,
      entries whose audit has not landed -> PENDING.
  (3) TWO TIERS: fleet overview = one card per model (status ring, total
      hits, 0-DAY/N-DAY/confirmed/rejected, class histogram) with the
      left rail scoping vendors (a dropdown like the filters, so the rail
      never grows with vendor count); a model card drills into the per-hit
      ledger (cards with class/rc/marker/graded-ts, filtered by
      novelty/status/attribution/class), and a card opens the full audit
      (dimensions + deterministic finality + novelty queries) plus the
      rendered REPORT.md, straight from vault files embedded in the
      page. Routing on #/v/<vendor>/m/<model>.

Default output: <root>/dashboard.html (a derived artifact — like
index.json it is rebuilt wholesale and never read by other scripts).
Exit 0; last stdout line = the HTML path.
"""
import argparse, datetime, glob, hashlib, html, json, os, re, sys

TRUTH = {"high": "CONFIRMED", "medium": "CONFIRMED", "low": "REJECTED"}
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))

def sub(dct, key):
    v = dct.get(key) if isinstance(dct, dict) else None
    return v if isinstance(v, dict) else {}

CVE_ID_RE = re.compile(r"\b((?:CVE|CNVD|CNNVD|AVD)-\d{4,}-\d{2,7})\b", re.I)

def clean_cve(s):
    """The chip shows the identifier, never the audit prose: an agent that
    stuffed caveats into novelty.cve still yields 'CVE-2020-27251' (first
    ID wins); a value with no ID at all is truncated, not paragraph'd."""
    s = "" if s is None else str(s).strip()
    if not s:
        return None
    mm = CVE_ID_RE.search(s)
    if mm:
        return mm.group(1).upper()
    return s if len(s) <= 24 else s[:23] + "…"

def load_entry(root, vendor, model, ed):
    try:
        m = json.load(open(os.path.join(ed, "meta.json")))
    except Exception:
        return None
    ap = os.path.join(ed, "AUDIT.json")
    aud = None
    if os.path.exists(ap):
        try:
            aud = json.load(open(ap))
        except Exception:
            aud = None
    aud = aud if isinstance(aud, dict) else {}
    rep = ""
    rp = os.path.join(ed, "REPORT.md")
    if os.path.exists(rp):
        try:
            rep = open(rp, encoding="utf-8", errors="replace").read()
        except Exception:
            rep = ""
    pocs = glob.glob(os.path.join(ed, "poc.*"))
    poc_src, poc_ext = "", ""
    if pocs:
        poc_ext = os.path.splitext(pocs[0])[1].lstrip(".")
        try:
            poc_src = open(pocs[0], encoding="utf-8", errors="replace").read()
        except Exception:
            poc_src = ""
    conf = sub(aud, "confidence").get("level") or m.get("confidence")
    # repro dimension (repro-run.sh): machine facts from repro.json + the
    # organizer agent's REPRO.md; the video itself is served as a raw file
    rj = {}
    try:
        rj = json.load(open(os.path.join(ed, "repro", "repro.json")))
    except Exception:
        rj = {}
    rj = rj if isinstance(rj, dict) else {}
    rmeta = sub(m, "repro")
    repro_md = ""
    rmp = os.path.join(ed, "repro", "REPRO.md")
    if os.path.exists(rmp):
        try:
            repro_md = open(rmp, encoding="utf-8", errors="replace").read()
        except Exception:
            repro_md = ""
    decisive = ""
    dp = os.path.join(ed, "repro", "decisive.txt")
    if os.path.exists(dp):
        try:
            decisive = open(dp, encoding="utf-8", errors="replace").read()[:8192]
        except Exception:
            decisive = ""
    # exploit dimension (exploit-run.sh): success = final_status EXPLOITED —
    # the deterministic fresh-target/fresh-flag capture gated by the
    # causal-necessity judge (ILLEGITIMATE downgrades to EXPLOITED_ILLEGITIMATE;
    # NOT_EXPLOITED / BOOT_FAILED are failures). Only successes get a surface:
    # no tab, no pane, no card tint for anything else.
    exg = {}
    try:
        exg = json.load(open(os.path.join(ed, "exploit", "grade-result.json")))
    except Exception:
        exg = {}
    exg = exg if isinstance(exg, dict) else {}
    exploited = exg.get("final_status") == "EXPLOITED"
    exp_src, exp_ext, writeup, exp_facts = "", "", "", {}
    if exploited:
        exps = sorted(glob.glob(os.path.join(ed, "exploit", "exp.*")))
        if exps:
            exp_ext = os.path.splitext(exps[0])[1].lstrip(".")
            try:
                exp_src = open(exps[0], encoding="utf-8", errors="replace").read()
            except Exception:
                exp_src = ""
        wp = os.path.join(ed, "exploit", "writeup.md")
        if os.path.exists(wp):
            try:
                writeup = open(wp, encoding="utf-8", errors="replace").read()
            except Exception:
                writeup = ""
        exp_facts = {k: exg.get(k) for k in
                     ("verdict", "rc", "judge_verdict", "final_status",
                      "expected_flag", "captured_flag")}
    truth = TRUTH.get(conf, "PENDING")
    attr = sub(aud, "attribution")
    tm = sub(aud, "threat_model")
    art = sub(aud, "artifact_check")
    fin = sub(aud, "finality") or sub(m, "finality")
    nov = sub(aud, "novelty")
    status = nov.get("status") or m.get("novelty") or "PENDING"
    fl = sub(aud, "flow")
    flow = m.get("flow") or fl.get("channel")
    flow = flow if flow in ("direct", "cross") else "unknown"
    return {
        "vendor": vendor, "model": model,
        "entry": os.path.basename(ed),
        "path": os.path.relpath(ed, REPO),
        "unit": m.get("unit"), "poc": m.get("poc"),
        "class": m.get("vuln_class"), "rc": m.get("rc"),
        "verdict": m.get("verdict"), "marker": m.get("marker"),
        "mode": m.get("mode"), "graded_at": m.get("graded_at"),
        "report_state": m.get("report"),
        "conf": conf, "truth": truth,
        "novelty": status, "cve": clean_cve(nov.get("cve") or m.get("cve")),
        "cve_unverified": bool(m.get("cve_needs_verification")),
        "similar": nov.get("similar"), "checked_at": nov.get("checked_at"),
        "queries": nov.get("queries") or [],
        "attr_grade": attr.get("grade"), "attr_marker": attr.get("marker_in_registers"),
        "attr_ev": attr.get("evidence"),
        "flow": flow, "flow_ev": fl.get("evidence"),
        "remote": tm.get("remote_http_only"), "guest": tm.get("guest_side"),
        "tm_ev": tm.get("evidence"),
        "artifact": art.get("emulation_artifact"), "art_ev": art.get("evidence"),
        "fin_grade": fin.get("grade"), "fin_basis": fin.get("basis"),
        "report": rep, "poc_src": poc_src, "poc_ext": poc_ext,
        "poc_sha": m.get("poc_sha256"),
        "vpath": os.path.relpath(ed, root),
        "repro_state": rmeta.get("state") or rj.get("state"),
        "repro_rc": rj.get("rc", rmeta.get("rc")),
        "repro_attempts": rj.get("attempts"),
        "repro_boot_s": rj.get("boot_s"),
        "repro_events": rj.get("session_events"),
        "repro_at": rj.get("at") or rmeta.get("at"),
        "repro_video": rj.get("video") or {},
        "repro_files": rj.get("files") or {},
        "repro_md": repro_md,
        "repro_decisive": decisive,
        "exploited": exploited,
        "exp_src": exp_src, "exp_ext": exp_ext,
        "exp_facts": exp_facts,
        "writeup": writeup,
    }

def scan(root):
    hits = []
    for vp in sorted(glob.glob(os.path.join(root, "*", "*"))):
        if not os.path.isdir(vp):
            continue
        vendor, model = os.path.basename(os.path.dirname(vp)), os.path.basename(vp)
        for ed in sorted(glob.glob(os.path.join(vp, "*"))):
            if os.path.isdir(ed) and os.path.exists(os.path.join(ed, "meta.json")):
                h = load_entry(root, vendor, model, ed)
                if h:
                    hits.append(h)
    hits.sort(key=lambda h: (h["graded_at"] or ""), reverse=True)
    return hits

TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Round Vault Ledger</title>
<style>
/* ── Round Vault Ledger — design plan (v2, review-driven) ────────
   Subject : security-integrity desk for the deterministic round vault.
   Layout  : left desk rail (search · custom listbox filters · fine
             ratio rings) → vendor-first, model-second card sections →
             right drawer: meta grid, tabs ending with the Report.
   Color   : cool slate neutrals biased toward brass; accent = brand &
             0-DAY; green/red dots = status; steel blue = N-DAY;
             violet = TOKEN.
   Type    : disciplined system UI + mono as the ledger currency;
             micro-uppercase labels, tabular numerals throughout.
   Theme   : dark-first, light mirrored via tokens, toggle wins both.
   ───────────────────────────────────────────────────────────────── */
:root{
  --bg:#0c1016; --surface:#10161f; --surface2:#161e2a; --raise:#1c2636;
  --line:#232e3f; --hair:#1a2330;
  --ink:#dce3ee; --mut:#8f9bb0; --faint:#5c6779;
  --accent:#d9a441; --accent-soft:rgba(217,164,65,.14);
  --ok:#5cb98c; --bad:#d2566b; --pend:#7d8aa0; --sky:#6d9fd4; --violet:#a08fe0;
  --shadow:0 14px 34px rgba(0,0,0,.38);
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    --bg:#f4f6f9; --surface:#ffffff; --surface2:#eef1f6; --raise:#e6ebf2;
    --line:#d9dfe9; --hair:#e8edf4;
    --ink:#1a2330; --mut:#5a6679; --faint:#8b95a7;
    --accent:#8a6110; --accent-soft:rgba(138,97,16,.12);
    --ok:#1e7a4d; --bad:#b23a52; --pend:#667185; --sky:#33689f; --violet:#5c48b5;
    --shadow:0 14px 34px rgba(30,42,64,.14);
    color-scheme:light;
  }
}
:root[data-theme="light"]{
  --bg:#f4f6f9; --surface:#ffffff; --surface2:#eef1f6; --raise:#e6ebf2;
  --line:#d9dfe9; --hair:#e8edf4;
  --ink:#1a2330; --mut:#5a6679; --faint:#8b95a7;
  --accent:#8a6110; --accent-soft:rgba(138,97,16,.12);
  --ok:#1e7a4d; --bad:#b23a52; --pend:#667185; --sky:#33689f; --violet:#5c48b5;
  --shadow:0 14px 34px rgba(30,42,64,.14);
  color-scheme:light;
}
*{box-sizing:border-box}
/* no native scrollbars anywhere — scroll still works, the chrome does not show */
html,*{scrollbar-width:none;-ms-overflow-style:none}
::-webkit-scrollbar,::-webkit-scrollbar-thumb,::-webkit-scrollbar-track{width:0;height:0;display:none;background:transparent}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:13.5px/1.55 var(--sans);font-variant-numeric:tabular-nums;overflow:hidden}
button,input{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:1px;border-radius:6px}
::selection{background:var(--accent-soft)}
.app{display:grid;grid-template-columns:320px minmax(0,1fr);height:100vh;height:100dvh;overflow:hidden}

/* ── rail ─────────────────────────────────────────────── */
.rail{background:var(--surface);border-right:1px solid var(--line);padding:22px 20px;display:flex;flex-direction:column;gap:24px;position:sticky;top:0;height:100vh;height:100dvh;overflow:hidden}
.brand{display:flex;gap:11px;align-items:center}
.brand svg{flex:none}
.brand .bn{font-size:14px;font-weight:680;letter-spacing:.01em}
.brand .bs{font:10px var(--mono);color:var(--faint);letter-spacing:.1em;text-transform:uppercase}
.search{position:relative}
.search svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);opacity:.5}
.search input{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:8px 34px 8px 32px;font:12.5px var(--mono)}
.search input::placeholder{color:var(--faint);font-family:var(--sans)}
.search kbd{position:absolute;right:9px;top:50%;transform:translateY(-50%);font:10px var(--mono);color:var(--faint);border:1px solid var(--line);border-radius:4px;padding:1px 5px}

/* custom listbox */
.fl{margin-bottom:13px}
.fl > label{display:block;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);margin-bottom:6px}
.cs{position:relative}
.cs-btn{width:100%;display:flex;align-items:center;justify-content:space-between;gap:8px;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:7px 11px;font-size:12.5px;cursor:pointer;transition:border-color .15s}
.cs-btn:hover{border-color:var(--faint)}
.cs-btn .cv{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cs-btn .ca{flex:none;width:7px;height:7px;border-right:1.5px solid var(--mut);border-bottom:1.5px solid var(--mut);transform:translateY(-2px) rotate(45deg);transition:transform .18s}
.cs-btn[aria-expanded="true"]{border-color:var(--accent)}
.cs-btn[aria-expanded="true"] .ca{transform:translateY(1px) rotate(225deg)}
.cs-list{position:absolute;left:0;right:0;top:calc(100% + 6px);z-index:25;background:var(--surface2);border:1px solid var(--line);border-radius:11px;padding:4px;box-shadow:var(--shadow);animation:pop .16s cubic-bezier(.33,1,.6,1);max-height:min(56vh,384px);overflow-y:auto}
@keyframes pop{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.cs-list[hidden]{display:none}
.cs-opt{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:8px;font-size:12.5px;cursor:pointer;color:var(--mut)}
.cs-opt:hover,.cs-opt.hl{background:var(--raise);color:var(--ink)}
.cs-opt.sel{color:var(--accent);font-weight:650}
.cs-opt .tick{width:12px;flex:none;font-size:10px;color:var(--accent)}
#reset{background:none;border:none;color:var(--mut);font-size:12px;cursor:pointer;padding:2px 0;text-align:left;text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:3px}
#reset:hover{color:var(--ink)}

/* fine ratio rings */
/* middle scroll zone: ONLY this band moves; header and policy stay pinned */
.railmid{flex:1 1 auto;min-height:0;overflow-y:auto;display:flex;flex-direction:column;gap:24px}
.rings{display:flex;gap:16px;border-top:1px solid var(--line);padding-top:20px}
/* direct cross-counts under the two rings (tier 1 only): the one-dim
   rings can't express CONFIRMED∩0-DAY, so say it as a number */
.xstats{display:grid;grid-template-columns:1fr 1fr;gap:10px;border-top:1px solid var(--line);padding-top:14px}
.xstats .xs{display:flex;flex-direction:column;gap:2px;min-width:0}
.xstats b{font:19px/1.25 var(--mono);font-weight:700}
.xstats label{font-size:8px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.xstats .xcs{display:flex;flex-direction:column;gap:4px;margin-top:8px}
.xstats .xc{font:8.5px/1 var(--mono);letter-spacing:.05em;padding:4px 7px 5px;border-radius:6px;white-space:nowrap;display:flex;align-items:center;justify-content:space-between;gap:4px;color:var(--mut)}
.xstats .xc b{font-weight:700}
.xstats .xc-ci{color:var(--sky);background:color-mix(in srgb,var(--sky) 14%,transparent)}
.xstats .xc-bof{color:var(--violet);background:color-mix(in srgb,var(--violet) 14%,transparent)}
.xstats .xc-dos{color:var(--pend);background:color-mix(in srgb,var(--pend) 16%,transparent)}
.xstats .xc.z{opacity:.4}
.ring{flex:1;display:flex;flex-direction:column;align-items:center;gap:10px;min-width:0}
.ring .rt{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--faint)}
.rd{position:relative;width:104px;height:104px}
.rd svg{width:100%;height:100%;display:block;overflow:visible}
.rd .trk{stroke:var(--surface2)}
.rd .hair{stroke:var(--line);opacity:.6}
.rd circle[data-k]{transition:stroke-dasharray .9s cubic-bezier(.33,1,.3,1),stroke-dashoffset .9s cubic-bezier(.33,1,.3,1),opacity .4s;filter:drop-shadow(0 0 4px rgba(0,0,0,.25))}
.dc{position:absolute;inset:0;display:grid;place-items:center;text-align:center;pointer-events:none}
.dc b{font-size:20px;font-weight:700;display:block;line-height:1.05}
.dc i{font-style:normal;font-size:8px;color:var(--faint);text-transform:uppercase;letter-spacing:.14em}
.lg{width:100%;display:grid;gap:4px;font-size:11px;color:var(--mut)}
.lg div{display:flex;align-items:center;gap:6px}
.lg i{width:6px;height:6px;border-radius:50%;flex:none}
.lg b{color:var(--ink);font-weight:600}
.lg em{font-style:normal;color:var(--faint);font-size:10px;margin-left:auto}
.railfoot{margin-top:auto;border-top:1px solid var(--line);padding-top:14px;font-size:11px;color:var(--faint);line-height:1.65}
.railfoot b{color:var(--mut);font-weight:600}

/* ── main ─────────────────────────────────────────────── */
main{padding:0 30px;min-width:0;height:100vh;height:100dvh;display:flex;flex-direction:column;overflow:hidden}
.mhead{display:flex;align-items:baseline;gap:16px;padding:26px 0 10px;flex-wrap:wrap;flex:0 0 auto;background:var(--bg)}
#body{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;padding-bottom:8px}
.mhead h1{font-size:19px;font-weight:680;margin:0;letter-spacing:-.01em}
.mtools{margin-left:auto;display:flex;align-items:center;gap:14px;font:11.5px var(--mono);color:var(--faint)}
.live{display:inline-flex;align-items:center;gap:6px}
.live s{width:7px;height:7px;border-radius:50%;background:var(--ok);text-decoration:none;animation:pulse 2.4s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
#thm,#out{background:var(--surface);border:1px solid var(--line);color:var(--mut);border-radius:8px;padding:4px 10px;font-size:11px;cursor:pointer}
#thm:hover,#out:hover{color:var(--ink)}
#out{text-decoration:none}

.vhead{display:flex;align-items:baseline;gap:12px;margin:30px 0 4px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.vhead h2{margin:0;font-size:13px;font-weight:750;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.vhead .vc{font:11px var(--mono);color:var(--faint)}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px;padding-top:6px}

/* ── two-tier desk: fleet (t1) → model ledger (t2) ─────── */
body.t1 .t2only{display:none!important}
body.t2 .t1only{display:none!important}
.mbk{align-self:center;font:11.5px var(--mono);color:var(--mut);background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:4px 11px;text-decoration:none;transition:border-color .14s,color .14s}
.mbk:hover{color:var(--ink);border-color:var(--faint)}
.mcgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;padding-top:6px}
.mcard{display:flex;gap:24px;align-items:center;min-width:0;background:linear-gradient(165deg,var(--surface2),var(--surface));border:1px solid var(--line);border-radius:18px;padding:26px 28px;cursor:pointer;transition:transform .14s ease,border-color .14s,box-shadow .14s}
.mcard:hover{transform:translateY(-3px);border-color:var(--faint);box-shadow:var(--shadow)}
.mcring{width:118px;flex:none}
.mcring .rd{width:118px;height:118px;flex:none}
.mcring .dc b{font-size:27px}
.mcring .dc i{margin-top:3px}
.mcinfo{flex:1;min-width:0;display:flex;flex-direction:column;gap:10px}
.mcov{display:flex;align-items:center;gap:10px}
.vendo{font-size:10px;font-weight:750;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);overflow-wrap:anywhere}
.mcarrow{margin-left:auto;color:var(--faint);font-size:15px;transition:transform .14s,color .14s}
.mcard:hover .mcarrow{color:var(--ink);transform:translate(2px,-2px)}
.mcinfo h3{margin:-4px 0 0;font:17px var(--mono);font-weight:680;letter-spacing:-.01em;overflow-wrap:anywhere}
.qstats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.qpair{display:grid;grid-template-columns:1fr 1fr;background:var(--bg);border:1px solid var(--hair);border-radius:10px;overflow:hidden}
.qpair > div{padding:7px 11px 8px;display:flex;flex-direction:column;min-width:0}
.qpair > div + div{border-left:1px solid var(--hair)}
.qstats b{font:16px/1.3 var(--mono);font-weight:700}
.qstats label{font-size:8.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--faint);overflow-wrap:anywhere}
.mcc{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.mcc .chip{border:1px solid var(--line);border-radius:6px;padding:0 8px;font:10.5px var(--mono);color:var(--mut);letter-spacing:.06em}
.mcc .chip b{color:var(--ink);font-weight:650}
.mcc .chip.dim{opacity:.65}
.mcc .mut{font:10.5px var(--mono);color:var(--faint);margin-left:auto}
.qstats .zero{opacity:.4}
/* vendor dropdown uses the shared .cs-btn/.cs-list/.cs-opt set above */

.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px 17px 14px;cursor:pointer;min-width:0;transition:transform .12s ease,border-color .12s,box-shadow .12s;display:flex;flex-direction:column;gap:10px}
.card:hover{transform:translateY(-2px);border-color:var(--faint);box-shadow:var(--shadow)}
.card .ctop{display:flex;align-items:center;gap:8px}
.card .st{display:inline-flex;align-items:center;gap:7px;font-size:10.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;flex:none}
.dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)} .dot.pend{background:transparent;border:1.5px solid var(--pend)}
.card .nv{margin-left:auto;font-size:10.5px;font-weight:750;letter-spacing:.1em}
.day{color:var(--accent)} .nday{color:var(--sky)}
/* repro badge — a landed reproduction pack (video in the Repro tab).
   Quiet pill: hairline ok-tinted border, play-glyph drawn in CSS so it
   never depends on font coverage. */
.card .rp{display:inline-flex;align-items:center;gap:5px;border:1px solid rgba(92,185,140,.35);background:rgba(92,185,140,.08);border-radius:999px;padding:1.5px 8px 1.5px 7px;font:9.5px var(--mono);font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--ok);white-space:nowrap}
.card .rp::before{content:"";width:0;height:0;border-left:5px solid var(--ok);border-top:3.5px solid transparent;border-bottom:3.5px solid transparent;margin-right:1px}
.card:hover .rp{background:rgba(92,185,140,.14);border-color:rgba(92,185,140,.5)}
/* exploited card — a light-green wash over the WHOLE card so a weaponized
   poc reads at a glance in the tier-2 ledger. Success only (final_status
   EXPLOITED); failures keep the plain surface. The mix rides --ok so the
   tint stays coherent in both themes (pale green in light, green-tinted
   slate in dark). */
.card.x{background:color-mix(in srgb,var(--ok) 11%,var(--surface));border-color:color-mix(in srgb,var(--ok) 30%,var(--line))}
.card.x:hover{border-color:color-mix(in srgb,var(--ok) 55%,var(--line))}
.card .xp{display:inline-flex;align-items:center;gap:5px;border:1px solid color-mix(in srgb,var(--ok) 45%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent);border-radius:999px;padding:1.5px 8px;font:9.5px var(--mono);font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--ok);white-space:nowrap}
.card .xp svg{flex:none}
.card h4{margin:0;font:13px var(--mono);font-weight:650;letter-spacing:-.01em;overflow-wrap:anywhere}
.card .un{margin-top:-6px;font:11px var(--mono);color:var(--sky);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .cve{font:10.5px var(--mono);color:var(--faint);margin-top:-6px}
.card .cve u{text-decoration-color:var(--bad);color:var(--bad)}
.card .cfoot{display:flex;align-items:center;gap:8px;border-top:1px solid var(--hair);padding-top:9px;font:10.5px var(--mono);color:var(--mut);flex-wrap:wrap}
.card .cfoot .cls{letter-spacing:.1em;color:var(--mut)}
.card .cfoot .flw{border:1px solid var(--line);border-radius:5px;padding:0 6px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
.card .cfoot .tok{color:var(--violet);font-weight:700}
.card .cfoot .win{color:var(--faint)}
.card .cfoot .mk{color:var(--faint);margin-left:auto}
.card .cfoot .dt{color:var(--faint)}
.empty{padding:80px 0;text-align:center;color:var(--faint);font:12.5px var(--mono)}
footer{flex:0 0 auto;margin:0;color:var(--faint);font:11px var(--mono);border-top:1px solid var(--line);padding:12px 0 16px;background:var(--bg)}

/* ── drawer ───────────────────────────────────────────── */
#scrim{position:fixed;inset:0;background:rgba(5,8,12,.55);opacity:0;pointer-events:none;transition:opacity .25s;z-index:30}
#scrim.open{opacity:1;pointer-events:auto}
#drawer{position:fixed;top:0;right:0;bottom:0;width:min(820px,94vw);background:var(--surface);border-left:1px solid var(--line);transform:translateX(103%);transition:transform .3s cubic-bezier(.33,1,.3,1);z-index:31;display:flex;flex-direction:column;box-shadow:-30px 0 60px rgba(0,0,0,.35)}
#drawer.open{transform:none}
.dh{padding:26px 30px 0;border-bottom:1px solid var(--line)}
.dh .dt{display:flex;align-items:flex-start;gap:14px}
.dh h2{margin:0;font:16px var(--mono);font-weight:680;min-width:0;overflow-wrap:anywhere;line-height:1.3}
.dh .dgo{margin-left:auto;display:flex;gap:10px;align-items:center;flex:none}
.dsub{font:11.5px var(--mono);color:var(--sky);margin-top:4px}
.dclose{background:var(--surface2);border:1px solid var(--line);color:var(--mut);width:30px;height:30px;border-radius:8px;cursor:pointer;font-size:13px}
.dclose:hover{color:var(--ink)}
.dmeta{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;margin:22px 0 24px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.dmeta > div{background:var(--bg);padding:11px 16px 12px;min-width:0}
.dmeta label{display:block;font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
.dmeta b{font:12.5px var(--mono);font-weight:600;overflow-wrap:anywhere}
.dmeta .mk{color:var(--accent)}
.segs{display:flex;gap:2px;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:3px;width:max-content;margin-bottom:0}
.segs button{background:none;border:none;color:var(--mut);padding:6px 16px;border-radius:7px;cursor:pointer;font-size:12px}
.segs button.on{background:var(--raise);color:var(--ink);font-weight:600}
.dheadspace{height:18px}
.dbody{overflow:auto;padding:24px 30px 48px;flex:1}
.pane[hidden]{display:none}
.dimgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin:14px 0}
.dim{background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:15px 17px;min-width:0}
.dim h4{margin:0 0 8px;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);font-weight:650;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.dim h4 b{font-size:11px;letter-spacing:.04em;text-transform:none;font-weight:700;overflow-wrap:anywhere}
.dim p{margin:0;font-size:12.5px;color:var(--mut);overflow-wrap:anywhere}   /* novelty.similar-style unbroken slash-joined handler lists must wrap, not blow out the card */
pre.qs{margin:0;padding:12px 14px;background:var(--bg);border:1px solid var(--line);border-radius:10px;font:11.5px/1.65 var(--mono);color:var(--mut);white-space:pre-wrap;word-break:break-word;overflow:auto}
.shacap{font:11.5px var(--mono);color:var(--faint);margin:0 0 9px}
.shacap b{color:var(--accent)}
.sec{margin-bottom:24px;min-width:0}
.sec h5{margin:0 0 10px;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);font-weight:650}
.okk{color:var(--ok)} .badd{color:var(--bad)}
/* mini markdown */
.rpt{font-size:13.5px;min-width:0}
.rpt h1,.rpt h2,.rpt h3,.rpt h4{margin:24px 0 9px;line-height:1.3;text-wrap:balance}
.rpt h1{font-size:18px}.rpt h2{font-size:15px;border-bottom:1px solid var(--line);padding-bottom:5px}.rpt h3{font-size:13.5px}
.rpt p{margin:8px 0;max-width:70ch;overflow-wrap:anywhere}
.rpt code{font-family:var(--mono);background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:11.8px;overflow-wrap:anywhere}
.rpt pre{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px 14px;overflow:auto}
.rpt pre code{background:none;border:none;padding:0;font-size:11.5px}
.rpt ul,.rpt ol{margin:8px 0;padding-left:22px}
.rpt li{margin:3px 0;max-width:72ch;overflow-wrap:anywhere}
.rpt table{border-collapse:collapse;margin:10px 0;font-size:12.3px}
.rpt th,.rpt td{border:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
.rpt th{background:var(--surface2)}
.rpt blockquote{margin:8px 0;padding:2px 12px;border-left:2px solid var(--accent);color:var(--mut)}
.rpt a{color:var(--sky)}
#toast{position:fixed;right:20px;bottom:20px;background:var(--raise);border:1px solid var(--ok);color:var(--ink);padding:9px 14px;border-radius:10px;font:12px var(--mono);opacity:0;transition:opacity .4s;z-index:50;pointer-events:none}
#toast.show{opacity:1}
@media (max-width:1000px){
  html,body{height:auto}
  body{overflow:auto}
  .app{grid-template-columns:1fr;height:auto;overflow:visible}
  .rail{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}
  main{padding:0 16px 40px;height:auto;display:block;overflow:visible}
  #body{overflow:visible;flex:none}
  .mhead{position:static}
  .dmeta{grid-template-columns:repeat(2,minmax(0,1fr))}
  .mcgrid{grid-template-columns:1fr}
}
@media (prefers-reduced-motion: reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body class="t1">
<div class="app">
  <aside class="rail">
    <div class="brand">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.6"><path d="M12 2l8 4v6c0 5-3.5 8.4-8 10-4.5-1.6-8-5-8-10V6l8-4z"/><path d="M8.5 12.2l2.3 2.3 4.7-4.8" stroke="var(--ok)"/></svg>
      <div><div class="bn">Round Vault</div><div class="bs">agent-scan ledger</div></div>
    </div>
    <div class="t1only">
      <div class="fl"><label for="cs-vendor">Vendors</label><div class="cs" id="cs-vendor"></div></div>
    </div>
    <div class="t2only">
      <div class="search">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.5-4.5"/></svg>
        <input id="q" placeholder="poc · handler · marker · class…" autocomplete="off"><kbd>/</kbd>
      </div>
      <div style="margin-top:18px">
        <div class="fl"><label for="cs-nov">Novelty</label><div class="cs" id="cs-nov"></div></div>
        <div class="fl"><label for="cs-truth">Status</label><div class="cs" id="cs-truth"></div></div>
        <div class="fl"><label for="cs-attr">Attribution</label><div class="cs" id="cs-attr"></div></div>
        <div class="fl"><label for="cs-cls">Class</label><div class="cs" id="cs-cls"></div></div>
        <button id="reset">Clear filters</button>
      </div>
    </div>
    <div class="railmid">
    <div class="rings">
      <div class="ring"><div class="rt">Novelty</div>
        <div class="rd"><div id="dNov"></div><div class="dc" id="cNov"></div></div>
        <div class="lg" id="lNov"></div></div>
      <div class="ring"><div class="rt">Status</div>
        <div class="rd"><div id="dTru"></div><div class="dc" id="cTru"></div></div>
        <div class="lg" id="lTru"></div></div>
    </div>
    <div class="xstats t1only" id="xstats"></div>
    </div>
    <div class="railfoot">
      <b>CONFIRMED</b> = the grader proved it and attribution holds
      (high &amp; medium). <b>REJECTED</b> = low confidence. Ratio rings
      weigh audited entries only.
    </div>
  </aside>

  <main>
    <div class="mhead">
      <a class="mbk" id="mbk" href="#/" hidden>← All models</a>
      <h1 id="mtitle">Fleet Overview</h1>
      <div class="mtools">
        <span id="cnt"></span>
        <span class="live" id="live" hidden><s></s>live</span>
        <button id="thm">theme</button>
        <a id="out" href="/logout" hidden>sign out</a>
      </div>
    </div>
    <div id="body"></div>
    <footer>scripts/round-view.py · data/round · one poc, one fresh boot, one deterministic verdict — __GEN__</footer>
  </main>
</div>

<div id="scrim"></div>
<aside id="drawer" role="dialog" aria-modal="true">
  <div class="dh">
    <div class="dt">
      <div><h2 id="dName"></h2><div class="dsub" id="dSub"></div></div>
      <span class="dgo"><button class="dclose" id="dClose" title="close (Esc)">✕</button></span>
    </div>
    <div class="dmeta" id="dStrip"></div>
    <div class="segs" id="dTabs">
      <button data-t="audit">Evidence audit</button>
      <button data-t="poc">PoC</button>
      <button data-t="exploit">Exploit</button>
      <button data-t="writeup">Writeup</button>
      <button data-t="report">Report</button>
      <button data-t="repro">Repro</button>
    </div>
    <div class="dheadspace"></div>
  </div>
  <div class="dbody">
    <div class="pane" id="pane-audit"></div>
    <div class="pane" id="pane-poc" hidden></div>
    <div class="pane" id="pane-exploit" hidden></div>
    <div class="pane" id="pane-writeup" hidden></div>
    <div class="pane" id="pane-report" hidden></div>
    <div class="pane" id="pane-repro" hidden></div>
  </div>
</aside>
<div id="toast"></div>

<script id="DATA" type="application/json">__DATA__</script>
<script>
"use strict";
const D0 = JSON.parse(document.getElementById("DATA").textContent);
let H = D0.hits, DATA_TS = D0.ts;
const $ = s => document.querySelector(s);
const $$ = (s,r=document) => [...r.querySelectorAll(s)];
const esc = s => (s==null?"":String(s));
let F = {nov:"", truth:"", attr:"", cls:"", q:""};
let VS = "";                                      /* tier-1 vendor scope */
let VIEW = {tier:1, vendor:"", model:""};

/* ── custom listbox ───────────────────────────────────── */
function listbox(hostId, optsIn, onSel){
  const host = document.getElementById(hostId);
  let cur = "", opts = optsIn;
  host.innerHTML =
    `<button class="cs-btn" type="button" aria-haspopup="listbox" aria-expanded="false"><span class="cv"></span><span class="ca"></span></button>
     <div class="cs-list" role="listbox" tabindex="-1" hidden></div>`;
  const btn = host.querySelector(".cs-btn"), val = host.querySelector(".cv"),
        lst = host.querySelector(".cs-list");
  function paint(){
    val.textContent = opts.find(o=>o.v===cur)?.n ?? "All";
    lst.innerHTML = opts.map(o=>`<div class="cs-opt${o.v===cur?" sel":""}" role="option" tabindex="-1" data-v="${esc(o.v)}"><span class="tick">${o.v===cur?"·":""}</span>${esc(o.n)}</div>`).join("");
  }
  function close(){btn.setAttribute("aria-expanded","false");lst.hidden=true;}
  function open(){lst.hidden=false;btn.setAttribute("aria-expanded","true");
    const f=lst.querySelector(".cs-opt"); f&&f.focus();}
  btn.onclick=()=>{lst.hidden?open():close();};
  lst.addEventListener("click",e=>{const o=e.target.closest(".cs-opt");if(!o)return;cur=o.dataset.v;paint();close();btn.focus();onSel(cur);});
  lst.addEventListener("keydown",e=>{
    const os=$$(".cs-opt",lst); let i=os.indexOf(document.activeElement);
    if(e.key==="ArrowDown"){e.preventDefault();os[Math.min(i+1,os.length-1)]?.focus();}
    else if(e.key==="ArrowUp"){e.preventDefault();os[Math.max(i-1,0)]?.focus();}
    else if(e.key==="Enter"||e.key===" "){e.preventDefault();document.activeElement.click();}
    else if(e.key==="Escape"){close();btn.focus();}
  });
  btn.addEventListener("keydown",e=>{if(e.key==="ArrowDown"||e.key==="Enter"){e.preventDefault();open();}});
  document.addEventListener("mousedown",e=>{if(!host.contains(e.target))close();});
  paint();
  return {set:v=>{cur=v;paint();}, rebuild:o=>{opts=o;paint();}};
}
const SEL = {};
function initFilters(){
  SEL.nov = listbox("cs-nov", [{v:"",n:"All"},{v:"0-DAY",n:"0-DAY"},{v:"N-DAY",n:"N-DAY"}], v=>{F.nov=v;renderView();});
  SEL.truth = listbox("cs-truth", [{v:"",n:"All"},{v:"CONFIRMED",n:"Confirmed"},{v:"REJECTED",n:"Rejected"}], v=>{F.truth=v;renderView();});
  SEL.attr = listbox("cs-attr", [{v:"",n:"All"},{v:"TOKEN",n:"TOKEN"},{v:"WINDOW",n:"WINDOW"}], v=>{F.attr=v;renderView();});
  SEL.cls = listbox("cs-cls", [{v:"",n:"All"}], v=>{F.cls=v;renderView();});
  /* tier-1 vendor scope rides the same listbox as the filters — the old
     always-open row list grew with every vendor and squeezed the rings */
  SEL.vendor = listbox("cs-vendor", [{v:"",n:"All vendors"}], v=>{VS=v;renderView();});
  $("#q").oninput=e=>{F.q=e.target.value.toLowerCase();renderView();};
  $("#reset").onclick=()=>{F={nov:"",truth:"",attr:"",cls:"",q:""};
    SEL.nov.set("");SEL.truth.set("");SEL.attr.set("");SEL.cls.set("");$("#q").value="";renderView();};
  document.addEventListener("keydown",e=>{
    if(e.key==="/"&&VIEW.tier===2&&!/input|textarea|select/i.test(e.target.tagName)){e.preventDefault();$("#q").focus();}
    if(e.key==="Escape"){
      if($("#drawer").classList.contains("open"))closeDrawer();
      else if(VIEW.tier===2)location.hash="#/";
    }
  });
}
function fillCls(){
  const order=["CI","BOF","DoS"];
  const rank=c=>{const i=order.indexOf(c);return i<0?99:i;};
  const cs=[...new Set(H.map(h=>clsShort(h.class)).filter(Boolean))];
  cs.sort((a,b)=>rank(a)-rank(b)||a.localeCompare(b));
  SEL.cls.rebuild([{v:"",n:"All"}].concat(cs.map(c=>({v:c,n:c}))));
  SEL.cls.set(F.cls);
}

/* ── fine ratio rings ─────────────────────────────────── */
function donut(host, segs){
  const shown = segs.filter(s=>s.v>0), tot = segs.reduce((a,s)=>a+s.v,0);
  const GAP = tot ? Math.min(2.5, 100/(shown.length*2)) : 0;
  const apply = () => {
    let acc = 0;
    for(const s of segs){
      const c = host.querySelector(`circle[data-k="${s.k}"]`);
      const pct = tot ? 100*s.v/tot : 0;
      const len = Math.max(pct - GAP, 0.01);
      c.setAttribute("stroke-dasharray", len.toFixed(3)+" "+(100-len).toFixed(3));
      c.setAttribute("stroke-dashoffset", (25-acc-GAP/2).toFixed(3));
      c.style.opacity = s.v>0 ? 1 : 0;
      acc += pct;
    }
  };
  if(!host.dataset.built){
    host.innerHTML =
      `<svg viewBox="0 0 42 42">
        <circle class="hair" cx="21" cy="21" r="18.4" fill="none" stroke-width="0.25"></circle>
        <circle class="trk" cx="21" cy="21" r="15.915" fill="none" stroke-width="3.4" stroke-linecap="round"></circle>`+
      segs.map(s=>`<circle data-k="${s.k}" cx="21" cy="21" r="15.915" fill="none" stroke="${s.color}" stroke-width="3.4" stroke-linecap="round" stroke-dasharray="0 100" stroke-dashoffset="25"></circle>`).join("")+
      `<circle class="hair" cx="21" cy="21" r="13.4" fill="none" stroke-width="0.25"></circle></svg>`;
    host.dataset.built="1";
    requestAnimationFrame(apply);
    return tot;
  }
  apply();
  return tot;
}
function legend(el, segs, tot){
  el.innerHTML = segs.map(s=>
    `<div><i style="background:${s.color}"></i>${esc(s.name)} <b>${s.v}</b>${tot?`<em>${Math.round(100*s.v/tot)}%</em>`:""}</div>`).join("");
}
function stat(list){
  const cnt = f => list.filter(f).length;
  const seg1 = [{k:"a",v:cnt(h=>h.novelty==="0-DAY"),color:"var(--accent)",name:"0-DAY"},
                {k:"b",v:cnt(h=>h.novelty==="N-DAY"), color:"var(--sky)",  name:"N-DAY"}];
  const seg2 = [{k:"a",v:cnt(h=>h.truth==="CONFIRMED"),color:"var(--ok)", name:"Confirmed"},
                {k:"b",v:cnt(h=>h.truth==="REJECTED"), color:"var(--bad)",name:"Rejected"}];
  const t1 = donut($("#dNov"), seg1);
  donut($("#dTru"), seg2);
  legend($("#lNov"), seg1, t1);
  legend($("#lTru"), seg2, cnt(h=>h.truth!=="PENDING"));   /* rings weigh audited only */
  $("#cNov").innerHTML = `<div><b>${t1}</b><i>shown</i></div>`;
  const aud = cnt(h=>h.truth!=="PENDING");
  $("#cTru").innerHTML = `<div><b>${aud}</b><i>audited</i></div>`;
  const x0 = cnt(h=>h.truth==="CONFIRMED"&&h.novelty==="0-DAY");
  const xn = cnt(h=>h.truth==="CONFIRMED"&&h.novelty==="N-DAY");
  const xcs = pred => ["CI","BOF","DoS"].map(c=>{
    const n = cnt(h=>h.truth==="CONFIRMED"&&pred(h)&&clsShort(h.class)===c);
    return `<span class="xc xc-${c.toLowerCase()}${n?"":" z"}" title="${c}: ${n} confirmed">${c} <b>${n}</b></span>`;}).join("");
  $("#xstats").innerHTML =
    `<div class="xs"><b style="color:var(--accent)">${x0}</b><label title="CONFIRMED entries whose novelty is 0-DAY">confirmed · 0-day</label><div class="xcs">${xcs(h=>h.novelty==="0-DAY")}</div></div>`+
    `<div class="xs"><b style="color:var(--sky)">${xn}</b><label title="CONFIRMED entries whose novelty is N-DAY">confirmed · n-day</label><div class="xcs">${xcs(h=>h.novelty==="N-DAY")}</div></div>`;
}

/* ── filtering ────────────────────────────────────────── */
function pass(h){
  if(F.nov && h.novelty!==F.nov) return false;
  if(F.truth && h.truth!==F.truth) return false;
  if(F.attr && h.attr_grade!==F.attr) return false;
  if(F.cls && clsShort(h.class)!==F.cls) return false;
  if(F.q){const s=(h.poc+" "+h.unit+" "+h.model+" "+h.vendor+" "+h.marker+" "+(h.class||"")).toLowerCase();if(!s.includes(F.q))return false;}
  return true;
}

/* ── cards ────────────────────────────────────────────── */
function fmtDate(ts){
  const m=String(ts||"").match(/(\d{4})(\d{2})(\d{2})[-_]?(\d{2})(\d{2})/);
  if(!m) return esc(ts);
  const MO=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${m[3]} ${MO[+m[2]-1]} ’${m[1].slice(2)}`;
}
function clsShort(c){c=c||"";return /stack|overflow|bof/.test(c)?"BOF":/command|injection|ci/.test(c)?"CI":/denial|service/.test(c)?"DoS":c.toUpperCase();}
/* repro surface exists ONLY where it means something: a confirmed novel
   finding worth submitting. Everything else (REJECTED / N-DAY / PENDING)
   gets no Repro tab, no pane, no card badge — an always-present empty
   "not replayed yet" reads like a defect, not a state. */
function hasRepro(h){return h.truth==="CONFIRMED"&&h.novelty==="0-DAY";}
function card(h,i){
  const dot = h.truth==="CONFIRMED"?"ok":h.truth==="REJECTED"?"bad":"pend";
  const stTxt = h.truth==="CONFIRMED"?"Confirmed":h.truth==="REJECTED"?"Rejected":"—";
  return `<article class="card${h.exploited?" x":""}" tabindex="0" data-i="${i}" aria-label="${esc(h.poc)}">
    <div class="ctop"><span class="st"><span class="dot ${dot}"></span>${esc(stTxt)}</span>
      ${h.exploited?`<span class="xp" title="successfully exploited — the weaponized exp captured a fresh flag on a fresh target (judge LEGITIMATE); Exploit and Writeup tabs in the drawer"><svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg>exploited</span>`:""}
      ${hasRepro(h)&&h.repro_state==="done"?`<span class="rp" title="reproduction pack landed — replay video, serial logs and REPRO.md in the Repro tab">repro</span>`:""}
      <span class="nv ${h.novelty==="N-DAY"?"nday":"day"}">${esc(h.novelty)}</span></div>
    <h4>${esc(h.poc)}</h4>
    <div class="un">${esc(h.unit)}</div>
    ${h.cve?`<div class="cve">${esc(h.cve)}${h.cve_unverified?" <u>unverified</u>":""}</div>`:""}
    <div class="cfoot">
      <span class="cls">${esc(clsShort(h.class))}</span>
      <span class="flw">${esc(h.flow)}</span>
      <span class="${h.attr_grade==="TOKEN"?"tok":"win"}">${esc(h.attr_grade||"—")}</span>
      <span class="mk">${esc(h.marker)}</span>
      <span class="dt">${fmtDate(h.graded_at)}</span>
    </div>
  </article>`;
}
/* ── two-tier view: fleet (t1) → model ledger (t2) ────── */
function models(list){
  const m=new Map();
  for(const h of list){
    const k=h.vendor+" / "+h.model;
    let e=m.get(k);
    if(!e){e={vendor:h.vendor,model:h.model,n:0,d0:0,dn:0,np:0,conf:0,rej:0,pend:0,cls:{},units:new Set(),lo:"",hi:""};m.set(k,e);}
    e.n++; e.units.add(h.unit||h.poc||e.n);
    if(h.novelty==="0-DAY")e.d0++; else if(h.novelty==="N-DAY")e.dn++; else e.np++;
    if(h.truth==="CONFIRMED")e.conf++; else if(h.truth==="REJECTED")e.rej++; else e.pend++;
    const c=clsShort(h.class)||"—"; e.cls[c]=(e.cls[c]||0)+1;
    const d=(h.graded_at||"").replace(/\D/g,"").slice(0,8);
    if(d){if(!e.lo||d<e.lo)e.lo=d; if(!e.hi||d>e.hi)e.hi=d;}
  }
  /* catalog order — vendor alphabetical, then model alphabetical; the
     grid never reshuffles as new hits land (fixed desk, not a ranking) */
  return [...m.values()].sort((a,b)=>a.vendor.localeCompare(b.vendor)||a.model.localeCompare(b.model));
}
function mcard(m,i){
  const chips=[...["CI","BOF","DoS"].filter(c=>m.cls[c]).map(c=>`<span class="chip">${c} <b>${m.cls[c]}</b></span>`),
    ...Object.entries(m.cls).filter(([c])=>!["CI","BOF","DoS"].includes(c)).map(([c,n])=>`<span class="chip dim">${esc(c)} <b>${n}</b></span>`)].join("");
  const zero=v=>v?"":" zero";
  return `<article class="mcard" tabindex="0" data-i="${i}">
    <div class="mcring">
      <div class="rd"><div class="donut"></div>
        <div class="dc"><div><b>${m.n}</b><i>hits</i></div></div></div>
    </div>
    <div class="mcinfo">
      <div class="mcov"><span class="vendo">${esc(m.vendor)}</span><span class="mcarrow" aria-hidden="true">↗</span></div>
      <h3>${esc(m.model)}</h3>
      <div class="qstats">
        <div class="qpair">
          <div${zero(m.d0)}><b class="day">${m.d0}</b><label title="novelty: 0-DAY">0-day</label></div>
          <div${zero(m.dn)}><b class="nday">${m.dn}</b><label title="novelty: N-DAY">n-day</label></div>
        </div>
        <div class="qpair">
          <div><b style="color:var(--ok)">${m.conf}</b><label title="audit status: CONFIRMED">confirmed</label></div>
          <div><b style="color:var(--bad)">${m.rej}</b><label title="audit status: REJECTED">rejected</label></div>
        </div>
      </div>
      <div class="mcc">${chips}<span class="mut">${m.units.size} handlers</span></div>
    </div></article>`;
}
function parseHash(){
  const m=(location.hash||"").match(/^#\/v\/([^/]+)\/m\/([^/]+)$/);
  if(m){const v=decodeURIComponent(m[1]),mo=decodeURIComponent(m[2]);
    if(H.some(h=>h.vendor===v&&h.model===mo))return{tier:2,vendor:v,model:mo};}
  return{tier:1,vendor:"",model:""};
}
function renderView(){
  VIEW=parseHash();
  document.body.classList.toggle("t1",VIEW.tier===1);
  document.body.classList.toggle("t2",VIEW.tier===2);
  fillCls();
  if(VIEW.tier===1)renderTier1();else renderTier2();
}
window.addEventListener("hashchange",renderView);
function renderTier1(){
  const scoped=VS?H.filter(h=>h.vendor===VS):H;
  const ms=models(scoped);
  $("#mbk").hidden=true;
  $("#mtitle").textContent="Fleet Overview";
  const nm=models(H).length,nv=new Set(H.map(h=>h.vendor)).size;
  $("#cnt").textContent=`${H.length} entries · ${nm} model${nm===1?"":"s"} · ${nv} vendor${nv===1?"":"s"}`;
  const vs=[...new Set(H.map(h=>h.vendor))].sort();
  SEL.vendor.rebuild([{v:"",n:"All vendors · "+H.length}].concat(
    vs.map(v=>({v:v, n:v+" · "+H.filter(h=>h.vendor===v).length}))));
  stat(scoped);
  let out="";
  const byV=[];
  ms.forEach((m,i)=>{let g=byV.find(x=>x.v===m.vendor);if(!g){g={v:m.vendor,list:[]};byV.push(g);}g.list.push([m,i]);});
  for(const g of byV){
    const gN=g.list.reduce((a,[m])=>a+m.n,0);
    out+=`<div class="vhead"><h2>${esc(g.v)}</h2><span class="vc">${gN} hit${gN===1?"":"s"} · ${g.list.length} model${g.list.length===1?"":"s"}</span></div>`+
         `<div class="mcgrid">${g.list.map(([m,i])=>mcard(m,i)).join("")}</div>`;
  }
  $("#body").innerHTML=out||`<div class="empty">the vault is empty — no graded hit has landed yet</div>`;
  $$(".mcard").forEach(c=>{
    const m=ms[+c.dataset.i];
    const act=()=>{location.hash="#/v/"+encodeURIComponent(m.vendor)+"/m/"+encodeURIComponent(m.model);};
    c.onclick=act;c.onkeydown=e=>{if(e.key==="Enter")act();};
    donut(c.querySelector(".donut"),[
      {k:"a",v:m.conf,color:"var(--ok)",name:"Confirmed"},
      {k:"b",v:m.rej,color:"var(--bad)",name:"Rejected"},
      {k:"c",v:m.pend,color:"var(--pend)",name:"Pending"}]);
  });
}
function renderTier2(){
  const ent=H.map((h,i)=>[h,i]).filter(([h])=>h.vendor===VIEW.vendor&&h.model===VIEW.model);
  const vis=ent.filter(([h])=>pass(h));
  $("#mbk").hidden=false;
  $("#mtitle").textContent=VIEW.model;
  $("#cnt").textContent=`${vis.length} / ${ent.length} hits shown`;
  stat(vis.map(x=>x[0]));
  if(!vis.length){$("#body").innerHTML=`<div class="empty">${ent.length?"no entries match the filters":"no hits for this model"}</div>`;return;}
  $("#body").innerHTML=`<div class="mgrid">${vis.map(([h,i])=>card(h,i)).join("")}</div>`;
  $$(".card").forEach(c=>{
    c.onclick=()=>openDrawer(+c.dataset.i);
    c.onkeydown=e=>{if(e.key==="Enter")openDrawer(+c.dataset.i);};
  });
}

/* ── drawer ───────────────────────────────────────────── */
function dimCard(title, badge, ev){
  return `<div class="dim"><h4>${esc(title)} <b>${badge||""}</b></h4><p>${esc(ev||"—")}</p></div>`;}
function yes(v){return v===true?`<b class="okk">yes</b>`:v===false?`<b class="badd">no</b>`:`<b>—</b>`;}
function openDrawer(i){
  const h=H[i];
  $("#dName").textContent = h.poc;
  $("#dSub").textContent = h.vendor+" · "+h.model+" · "+h.unit;
  const dotc = h.truth==="CONFIRMED"?"var(--ok)":h.truth==="REJECTED"?"var(--bad)":"var(--pend)";
  $("#dStrip").innerHTML = `
    <div><label>verdict</label><b>${esc(h.verdict)} · rc=${esc(h.rc)}</b></div>
    <div><label>finality</label><b>${esc(h.fin_grade||"—")}</b></div>
    <div><label>status</label><b style="color:${dotc}">${esc(h.truth)}</b></div>
    <div><label>confidence</label><b>${esc(h.conf||"—")} · derived</b></div>
    <div><label>novelty</label><b>${esc(h.novelty)}${h.cve?" · "+esc(h.cve):""}</b></div>
    <div><label>marker</label><b class="mk">${esc(h.marker)}</b></div>
    <div><label>class</label><b>${esc(h.class)}</b></div>
    <div><label>flow</label><b>${esc(h.flow)}</b></div>
    <div><label>graded</label><b>${fmtDate(h.graded_at)}</b></div>`;
  const ab = h.attr_grade==="TOKEN"?`<span style="color:var(--violet)">TOKEN</span>`:`<span style="color:var(--faint)">${esc(h.attr_grade||"—")}</span>`;
  const ar = h.artifact==="no"?`<b class="okk">no</b>`:h.artifact?`<b class="badd">${esc(h.artifact)}</b>`:"—";
  $("#pane-audit").innerHTML = `
    <div class="sec"><h5>Deterministic finality — grader report.json</h5><pre class="qs">${esc(JSON.stringify(h.fin_basis||{},null,1))}</pre></div>
    <div class="sec"><h5>Evidence audit — five dimensions (report agent)</h5>
      <div class="dimgrid">
        ${dimCard("Attribution",ab,h.attr_ev)}
        ${dimCard("Data path",`<b style="color:var(--mut)">${esc(h.flow)}</b>`,h.flow_ev)}
        ${dimCard("Threat model",`${yes(h.remote)} remote · guest: ${esc(h.guest||"—")}`,h.tm_ev)}
        ${dimCard("Emulation artifact",ar,h.art_ev)}
        ${dimCard("Novelty",`${esc(h.novelty)}${h.cve?" · "+esc(h.cve):""} · checked ${esc(h.checked_at||"—")}`,h.similar?`resembles: ${esc(h.similar)}`:"no N-Day match demonstrated — 0-DAY by policy")}
      </div></div>
    <div class="sec"><h5>Novelty search log — ${(h.queries||[]).length} queries</h5>${(h.queries||[]).length?`<pre class="qs">${esc(h.queries.join("\n"))}</pre>`:`<pre class="qs">nothing was checked: no queries recorded</pre>`}</div>`;
  $("#pane-poc").innerHTML = h.poc_src
    ? `<p class="shacap">the exact bytes the grader replayed · sha256 <b>${esc((h.poc_sha||"").slice(0,16))}…</b></p><pre class="qs">${esc(h.poc_src)}</pre>`
    : `<pre class="qs">poc source not embedded</pre>`;
  $("#pane-report").innerHTML = `<div class="rpt">${md(h.report||"*no report yet — the report agent has not landed*")}</div>`;
  /* ── Repro pane: the live-replay video + machine facts + REPRO.md ──
     video bytes come ONLY from a same-class replay (repro-run.sh refuses
     to render otherwise); links are vault-relative raw-file routes. */
  const vurl = esc(h.vpath)+"/repro/repro.mp4";
  const vb = (h.repro_video||{}).bytes||0, vs = (h.repro_video||{}).sha256||"";
  const fl = Object.entries(h.repro_files||{});
  $("#pane-repro").innerHTML = hasRepro(h) ? (h.repro_state==="done" ? `
    <div class="sec"><h5>Reproduction video — this live replay (attack window 1:1 real time)</h5>
      <video controls preload="metadata" style="width:100%;max-height:430px;background:#000;border:1px solid var(--line)" src="${vurl}"></video>
      <p class="shacap"><a href="${vurl}" download>download repro.mp4</a> · ${(vb/1048576).toFixed(2)} MB · sha256 <b>${esc(vs.slice(0,16))}…</b> · <a href="${esc(h.vpath)}/repro/repro.srt" download>subtitles repro.srt</a></p></div>
    <div class="sec"><h5>Replay facts — repro.json (machine record, not prose)</h5><pre class="qs">${esc(JSON.stringify(
        {state:h.repro_state, replay_rc:h.repro_rc, vault_rc:h.rc, attempts:h.repro_attempts,
         boot_s:h.repro_boot_s, session_events:h.repro_events, at:h.repro_at},null,1))}</pre></div>
    ${h.repro_decisive?`<div class="sec"><h5>Decisive serial lines — decisive.txt (this replay, verbatim)</h5><pre class="qs">${esc(h.repro_decisive)}</pre></div>`:""}
    ${fl.length?`<div class="sec"><h5>Attachments — all downloadable for review</h5><pre class="qs">${fl.map(([n,f])=>`<a href="${esc(h.vpath)}/repro/${esc(n)}" download>${esc(n)}</a> <i style="color:var(--faint)">${((f.bytes||0)/1024).toFixed(0)}KB</i>`).join("\n")}</pre></div>`:""}
    <div class="sec"><h5>REPRO.md — overall reproduction document (organizer agent)</h5>
      <div class="rpt">${md(h.repro_md||"*no REPRO.md — the video still renders when the agent step fails; burned-in captions fall back to deterministic templates*")}</div></div>`
    : h.repro_state==="missed-replay" ? `
    <div class="sec"><h5>Repro — missed-replay (no video)</h5>
      <p>The live replay did not reproduce the vaulted verdict class. Per the integrity rule the video is <b>REFUSED</b> — never rendered from stale evidence. attempts=${esc(h.repro_attempts)} · at=${esc(h.repro_at||"—")}</p></div>`
    : `<div class="sec"><h5>Repro</h5><p class="qs">not replayed yet — repro-run.sh has not landed for this entry.</p></div>`) : "";
  /* ── Exploit + Writeup panes: the weaponization surface ──
     exists ONLY for a successful exploitation (exploit/grade-result.json
     final_status == EXPLOITED — deterministic fresh-flag capture gated by
     the causal-necessity judge). Failures get no tab, no pane, no tint. */
  $("#pane-exploit").innerHTML = h.exploited ? `
    <div class="sec"><h5>Exploit source — the weaponized exp, graded on a fresh target with a fresh flag</h5>
      ${h.exp_src?`<pre class="qs">${esc(h.exp_src)}</pre>`:`<pre class="qs">exp source not embedded</pre>`}</div>
    <div class="sec"><h5>Grade facts — exploit/grade-result.json (machine record, not prose)</h5><pre class="qs">${esc(JSON.stringify(h.exp_facts||{},null,1))}</pre></div>` : "";
  $("#pane-writeup").innerHTML = h.exploited
    ? `<div class="rpt">${md(h.writeup||"*no writeup landed for this entry*")}</div>` : "";
  $("#dTabs button[data-t=exploit]").hidden = !h.exploited;
  $("#dTabs button[data-t=writeup]").hidden = !h.exploited;
  $("#dTabs button[data-t=repro]").hidden = !hasRepro(h);
  switchTab("audit");
  $("#scrim").classList.add("open"); $("#drawer").classList.add("open");
  $(".dbody").scrollTop=0;
}
function closeDrawer(){$("#scrim").classList.remove("open");$("#drawer").classList.remove("open");}
$("#dClose").onclick=closeDrawer; $("#scrim").onclick=closeDrawer;
$("#dTabs").onclick=e=>{if(e.target.dataset.t)switchTab(e.target.dataset.t);};
function switchTab(t){
  $$("#dTabs button").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
  ["audit","poc","exploit","writeup","report","repro"].forEach(k=>{$("#pane-"+k).hidden = k!==t;});
}

/* ── live polling ─────────────────────────────────────── */
if(location.protocol.startsWith("http")){
  $("#live").hidden=false;
  $("#out").hidden=false;
  setInterval(async()=>{
    try{
      const r = await fetch("/__data__", {cache:"no-store"});
      if(r.status===401){location.reload();return;}   /* session gone → the login gate */
      const j = await r.json();
      if(j.ts !== DATA_TS){
        const grew = j.hits.length > H.length;
        H = j.hits; DATA_TS = j.ts;
        renderView();
        const t=$("#toast");
        t.textContent = grew ? "vault updated — a new hit landed" : "vault data refreshed";
        t.classList.add("show"); setTimeout(()=>t.classList.remove("show"), 3400);
      }
    }catch(e){}
  }, 4000);
}

/* ── theme ────────────────────────────────────────────── */
let thm=null; try{thm=localStorage.getItem("rv-theme");}catch(e){}
if(thm)document.documentElement.dataset.theme=thm;
$("#thm").onclick=()=>{
  const cur=document.documentElement.dataset.theme||
    (matchMedia("(prefers-color-scheme: light)").matches?"light":"dark");
  const next=cur==="dark"?"light":"dark";
  document.documentElement.dataset.theme=next;
  try{localStorage.setItem("rv-theme",next);}catch(e){}
};

/* ── mini markdown ────────────────────────────────────── */
function md(src){
  const L=src.replace(/\r/g,"").split("\n"); let o="",i=0;
  function inline(s){
    s=s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    s=s.replace(/`([^`]+)`/g,(x,c)=>"<code>"+c+"</code>");
    s=s.replace(/\*\*([^*]+)\*\*/g,"<b>$1</b>");
    s=s.replace(/(^|[^*])\*([^*\n]+)\*/g,"$1<i>$2</i>");
    s=s.replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,'<a href="$2" target="_blank" rel="noopener">$1</a>');
    return s;
  }
  while(i<L.length){
    const l=L[i];
    if(/^```/.test(l)){const code=[];i++;
      while(i<L.length&&!/^```/.test(L[i])){code.push(L[i].replace(/&/g,"&amp;").replace(/</g,"&lt;"));i++;}
      i++; o+="<pre><code>"+code.join("\n")+"</code></pre>"; continue;}
    if(/^\s*$/.test(l)){i++;continue;}
    let m=l.match(/^(#{1,4})\s+(.*)/);
    if(m){o+=`<h${m[1].length}>`+inline(m[2])+`</h${m[1].length}>`;i++;continue;}
    if(/^\|.*\|$/.test(l)){
      const rows=[];while(i<L.length&&/^\|.*\|$/.test(L[i])){rows.push(L[i]);i++;}
      const cells=r=>r.slice(1,-1).split("|").map(c=>c.trim());
      const head=cells(rows[0]);
      const body=rows.slice(1).filter(r=>!/^[\s|:-]+$/.test(r)).map(cells);
      o+="<table><thead><tr>"+head.map(c=>"<th>"+inline(c)+"</th>").join("")+"</tr></thead><tbody>"+
        body.map(r=>"<tr>"+r.map(c=>"<td>"+inline(c)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
      continue;}
    if(/^>\s?/.test(l)){o+="<blockquote>"+inline(l.replace(/^>\s?/,""))+"</blockquote>";i++;continue;}
    if(/^<!--/.test(l)){i++;continue;}
    {const t=/^\s*[-*]\s+/.test(l)?"ul":/^\s*\d+\.\s+/.test(l)?"ol":null;
     if(t){const items=[];
       while(i<L.length&&((t==="ul"?/^\s*[-*]\s+/:/^\s*\d+\.\s+/).test(L[i]))){
         items.push(L[i].replace(/^\s*(?:[-*]|\d+\.)\s+/,""));i++;}
       o+=`<${t}>`+items.map(x=>"<li>"+inline(x)+"</li>").join("")+`</${t}>`;continue;}}
    const para=[l];i++;
    while(i<L.length&&!/^\s*$/.test(L[i])&&!/^(#{1,4}\s|```|\|.*\|$|>\s?)/.test(L[i])
          &&!/^\s*[-*]\s+/.test(L[i])&&!/^\s*\d+\.\s+/.test(L[i])){para.push(L[i]);i++;}
    o+="<p>"+inline(para.join(" "))+"</p>";
  }
  return o;
}

initFilters(); renderView();
</script>
</body>
</html>
"""

def payload(root):
    """rescan the vault; ts fingerprints the LEDGER STATE (a newly
    finalized audit flips it too), so the page only re-renders on a
    real change."""
    hits = scan(root)
    key = json.dumps([[h["path"], h["report_state"], h["truth"], h["novelty"],
                      h["conf"], h["flow"], len(h["report"]), len(h["poc_src"]),
                      h.get("repro_state"), len(h.get("repro_md") or ""),
                      h.get("exploited"), len(h.get("exp_src") or ""),
                      len(h.get("writeup") or "")] for h in hits])
    return hits, hashlib.md5(key.encode()).hexdigest()

def build_page(hits, ts):
    gen = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    data = json.dumps({"ts": ts, "hits": hits}, ensure_ascii=False).replace("</", "<\\/")
    return (TEMPLATE
            .replace("__GEN__", html.escape(gen))
            .replace("__TOTAL__", str(len(hits)))
            .replace("__DATA__", data))

# ── login gate ─────────────────────────────────────────────────────
# Same design tokens as the ledger (slate + brass, dark-first, light
# mirrored, system UI + mono, micro-uppercase labels) so the gate reads
# as the desk's front door, not a different product. One fixed
# organization credential pair — no registration, no user store.
LOGIN = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · Round Vault</title>
<style>
:root{
  --bg:#0c1016; --surface:#10161f; --surface2:#161e2a; --raise:#1c2636;
  --line:#232e3f; --hair:#1a2330;
  --ink:#dce3ee; --mut:#8f9bb0; --faint:#5c6779;
  --accent:#d9a441; --accent-soft:rgba(217,164,65,.14); --accent-ink:#1a1206;
  --ok:#5cb98c; --bad:#d2566b; --sky:#6d9fd4;
  --shadow:0 14px 34px rgba(0,0,0,.38);
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    --bg:#f4f6f9; --surface:#ffffff; --surface2:#eef1f6; --raise:#e6ebf2;
    --line:#d9dfe9; --hair:#e8edf4;
    --ink:#1a2330; --mut:#5a6679; --faint:#8b95a7;
    --accent:#8a6110; --accent-soft:rgba(138,97,16,.12); --accent-ink:#ffffff;
    --ok:#1e7a4d; --bad:#b23a52; --sky:#33689f;
    --shadow:0 14px 34px rgba(30,42,64,.14);
    color-scheme:light;
  }
}
:root[data-theme="light"]{
  --bg:#f4f6f9; --surface:#ffffff; --surface2:#eef1f6; --raise:#e6ebf2;
  --line:#d9dfe9; --hair:#e8edf4;
  --ink:#1a2330; --mut:#5a6679; --faint:#8b95a7;
  --accent:#8a6110; --accent-soft:rgba(138,97,16,.12); --accent-ink:#ffffff;
  --ok:#1e7a4d; --bad:#b23a52; --sky:#33689f;
  --shadow:0 14px 34px rgba(30,42,64,.14);
  color-scheme:light;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:13.5px/1.55 var(--sans);
  font-variant-numeric:tabular-nums;display:grid;place-items:center;padding:16px;overflow:hidden}
/* ambient desk light: two soft glows + a hairline grid fading out from the card */
body::before{content:"";position:fixed;inset:0;pointer-events:none;background:
  radial-gradient(560px 380px at 16% -8%,var(--accent-soft),transparent 70%),
  radial-gradient(640px 440px at 88% 110%,color-mix(in srgb,var(--sky) 8%,transparent),transparent 70%)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;opacity:.55;
  background-image:linear-gradient(var(--hair) 1px,transparent 1px),
    linear-gradient(90deg,var(--hair) 1px,transparent 1px);
  background-size:44px 44px;
  -webkit-mask-image:radial-gradient(760px 540px at 50% 44%,#000 0%,transparent 76%);
  mask-image:radial-gradient(760px 540px at 50% 44%,#000 0%,transparent 76%)}
:focus-visible{outline:2px solid var(--accent);outline-offset:1px;border-radius:6px}
::selection{background:var(--accent-soft)}
.gate{position:relative;z-index:1;width:min(400px,100%);
  background:linear-gradient(165deg,var(--surface2),var(--surface));
  border:1px solid var(--line);border-radius:18px;padding:34px 32px 26px;
  box-shadow:var(--shadow);animation:rise .5s cubic-bezier(.33,1,.6,1)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.gate.err{animation:shake .4s cubic-bezier(.36,.07,.19,.97)}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(4px)}
  30%,50%,70%{transform:translateX(-6px)}40%,60%{transform:translateX(6px)}}
.brand{display:flex;flex-direction:column;align-items:center;gap:12px;text-align:center}
.tile{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;
  background:var(--accent-soft);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent)}
.bn{font-size:17px;font-weight:680;letter-spacing:.01em}
.bs{font:9.5px var(--mono);color:var(--faint);letter-spacing:.18em;text-transform:uppercase;margin-top:3px}
form{margin-top:26px;display:flex;flex-direction:column;gap:15px}
.fl label{display:block;font-size:10px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--faint);margin-bottom:6px}
.inp{position:relative}
input{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:9px;
  padding:10px 12px;font:13px var(--mono);color:var(--ink);
  transition:border-color .15s,box-shadow .15s}
input::placeholder{color:var(--faint);font-family:var(--sans);font-size:12.5px}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
#pw{padding-right:42px}
.eye{position:absolute;right:5px;top:50%;transform:translateY(-50%);background:none;border:none;
  color:var(--faint);cursor:pointer;padding:7px;border-radius:7px;display:grid;place-items:center}
.eye:hover{color:var(--ink);background:var(--raise)}
.errbox{display:flex;gap:9px;align-items:center;
  background:color-mix(in srgb,var(--bad) 10%,transparent);
  border:1px solid color-mix(in srgb,var(--bad) 38%,transparent);color:var(--bad);
  border-radius:9px;padding:8px 12px;font-size:12px}
.errbox svg{flex:none}
.go{margin-top:4px;width:100%;background:var(--accent);color:var(--accent-ink);border:none;
  border-radius:9px;padding:11px 14px;font-size:13.5px;font-weight:650;letter-spacing:.02em;
  cursor:pointer;transition:filter .15s,transform .12s}
.go:hover{filter:brightness(1.08);transform:translateY(-1px)}
.go:active{transform:none}
.go:disabled{opacity:.6;cursor:default;transform:none;filter:none}
.motto{margin-top:22px;text-align:center;font:10px var(--mono);color:var(--faint);letter-spacing:.04em}
@media (max-width:420px){.gate{padding:28px 22px 22px}}
@media (prefers-reduced-motion: reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<main class="gate__ERRCLASS__">
  <div class="brand">
    <div class="tile">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.6"><path d="M12 2l8 4v6c0 5-3.5 8.4-8 10-4.5-1.6-8-5-8-10V6l8-4z"/><path d="M8.5 12.2l2.3 2.3 4.7-4.8" stroke="var(--ok)"/></svg>
    </div>
    <div><div class="bn">Round Vault</div><div class="bs">agent-scan ledger</div></div>
  </div>
  <form method="post" action="/login" id="f">
    __ERRBOX__
    <div class="fl"><label for="org">Organization</label>
      <input id="org" name="org" type="text" value="__ORG__" placeholder="your organization"
        autocomplete="organization" autocapitalize="off" spellcheck="false" __AF_ORG__></div>
    <div class="fl"><label for="pw">Password</label>
      <div class="inp"><input id="pw" name="password" type="password" placeholder="shared lab password"
        autocomplete="current-password" __AF_PW__>
      <button class="eye" type="button" id="eye" title="show password" aria-label="show password"></button></div></div>
    <input type="hidden" name="next" id="next" value="__NEXT__">
    <button class="go" type="submit" id="go">Sign in</button>
  </form>
  <div class="motto">one poc · one fresh boot · one deterministic verdict</div>
</main>
<script>
"use strict";
/* the ledger's theme toggle persists here too — same origin, same key */
try{const t=localStorage.getItem("rv-theme");if(t)document.documentElement.dataset.theme=t;}catch(e){}
/* the gate is served IN PLACE of the requested page, so the URL still carries
   its #/v/…/m/… hash — ride it through the login back to the deep link */
const nx=document.getElementById("next");
if(location.hash)nx.value=(nx.value||"/")+location.hash;
const EYE='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYEOFF='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3l18 18"/><path d="M10.6 5.1A11 11 0 0 1 12 5c6.5 0 10 7 10 7a17.8 17.8 0 0 1-3.1 4.1M6.6 6.6A16.9 16.9 0 0 0 2 12s3.5 7 10 7a10.2 10.2 0 0 0 4.4-1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';
const pw=document.getElementById("pw"),eye=document.getElementById("eye");
eye.innerHTML=EYE;
eye.onclick=()=>{const show=pw.type==="password";pw.type=show?"text":"password";
  eye.innerHTML=show?EYEOFF:EYE;eye.title=show?"hide password":"show password";
  eye.setAttribute("aria-label",eye.title);pw.focus();};
document.getElementById("f").addEventListener("submit",()=>{
  const b=document.getElementById("go");b.disabled=true;b.textContent="Signing in…";});
</script>
</body>
</html>
"""

def login_page(error=False, org_value="", next_path="/"):
    errbox = ('<div class="errbox" role="alert">'
              '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
              'stroke="currentColor" stroke-width="2"><path d="M12 3l10 18H2L12 3z"/>'
              '<path d="M12 10v4"/><path d="M12 17.4v.6"/></svg>'
              '<span>Invalid organization or password.</span></div>') if error else ""
    return (LOGIN
            .replace("__ERRCLASS__", " err" if error else "")
            .replace("__ERRBOX__", errbox)
            .replace("__ORG__", html.escape(org_value, quote=True))
            .replace("__NEXT__", html.escape(next_path, quote=True))
            .replace("__AF_ORG__", "" if error else "autofocus")
            .replace("__AF_PW__", "autofocus" if error else ""))

def safe_next(n):
    """only same-origin relative paths ride the post-login redirect"""
    n = (n or "/").strip()
    if (not n.startswith("/") or n.startswith("//") or "\\" in n
            or any(ord(c) < 32 for c in n) or len(n) > 2048):
        return "/"
    return n

def serve(root, port, org, password):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from http.cookies import SimpleCookie, CookieError
    from urllib.parse import urlparse, parse_qs
    import secrets, time
    ROOT_R = os.path.realpath(root)
    SESSIONS = set()   # live session ids — one per sign-in; logout kills only its own
    TYPES = {".json": "application/json", ".md": "text/plain; charset=utf-8",
             ".py": "text/plain; charset=utf-8", ".c": "text/plain; charset=utf-8",
             ".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
             ".html": "text/html; charset=utf-8", ".mp4": "video/mp4",
             ".srt": "text/plain; charset=utf-8"}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def _send(self, code, ctype, body, set_cookie=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        def _redirect(self, loc, set_cookie=None):
            self.send_response(303)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        def _sid(self):
            try:
                jar = SimpleCookie(self.headers.get("Cookie") or "")
            except CookieError:
                jar = SimpleCookie()
            m = jar.get("rv_session")
            return m.value if m else None
        def _authed(self):
            s = self._sid()
            return bool(s and s in SESSIONS)
        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/logout":
                s = self._sid()
                if s:
                    SESSIONS.discard(s)   # server-side invalidation, this session only
                self._redirect("/login", "rv_session=; Path=/; HttpOnly; "
                                         "SameSite=Strict; Max-Age=0")
                return
            if p == "/login":
                if self._authed():
                    self._redirect("/")
                else:
                    self._send(200, "text/html; charset=utf-8", login_page())
                return
            if p in ("/", "/dashboard.html"):
                if not self._authed():
                    # the gate renders IN PLACE — the URL (and its hash) survives
                    self._send(200, "text/html; charset=utf-8",
                               login_page(next_path=p))
                    return
                hits, ts = payload(root)          # fresh scan per request
                self._send(200, "text/html; charset=utf-8", build_page(hits, ts))
                return
            if not self._authed():
                if p == "/__data__":
                    self._send(401, "application/json",
                               '{"error":"sign-in required"}')
                else:
                    self._send(401, "text/plain", "401 — sign in at /\n")
                return
            if p == "/__data__":
                hits, ts = payload(root)
                self._send(200, "application/json",
                           json.dumps({"ts": ts, "hits": hits},
                                      ensure_ascii=False).replace("</", "<\\/"))
                return
            # raw vault files (evidence etc); no dir listings
            f = os.path.realpath(os.path.join(ROOT_R, p.lstrip("/")))
            if f.startswith(ROOT_R + os.sep) and os.path.isfile(f):
                self._send(200, TYPES.get(os.path.splitext(f)[1].lower(),
                                          "application/octet-stream"),
                           open(f, "rb").read())
            else:
                self._send(404, "text/plain", "404\n")
        def do_POST(self):
            if urlparse(self.path).path != "/login":
                self._send(404, "text/plain", "404\n")
                return
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if n > 65536:
                self.close_connection = True
                self._send(413, "text/plain", "413\n")
                return
            body = self.rfile.read(n).decode("utf-8", "replace") if n > 0 else ""
            form = parse_qs(body, keep_blank_values=True)
            org_f = (form.get("org") or [""])[0]
            pw_f = (form.get("password") or [""])[0]
            nxt = safe_next((form.get("next") or ["/"])[0])
            if self._authed():
                self._redirect(nxt)
                return
            # constant-time on both fields; bytes so any unicode input is safe
            ok = (secrets.compare_digest(org_f.encode(), org.encode())
                  & secrets.compare_digest(pw_f.encode(), password.encode()))
            if ok:
                sid = secrets.token_urlsafe(32)
                SESSIONS.add(sid)
                self._redirect(nxt, "rv_session=" + sid + "; Path=/; HttpOnly; "
                                    "SameSite=Strict; Max-Age=604800")
                return
            time.sleep(0.4)   # fixed cost on failure — slows guessing, locks no one out
            self._send(200, "text/html; charset=utf-8",
                       login_page(error=True, org_value=org_f, next_path=nxt))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[round-view] LIVE serve http://0.0.0.0:{port}/dashboard.html "
          f"(root {root}; rescans per request, page polls every 4s; "
          f"login gate: organization '{org}')", file=sys.stderr)
    srv.serve_forever()

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.join(REPO, "data", "round"),
                    help="vault root (default data/round)")
    ap.add_argument("--out", default=None,
                    help="output html (default <root>/dashboard.html)")
    ap.add_argument("--serve", type=int, metavar="PORT", default=None,
                    help="serve the dashboard live on PORT instead of writing "
                         "a file: every request rescans data/round and the "
                         "page polls /__data__ every 4s, so new vault entries "
                         "(verify re-run, report agent landing) appear by "
                         "themselves — donuts animate as they land")
    ap.add_argument("--org", default=os.environ.get("ROUND_VIEW_ORG", "netsec"),
                    metavar="NAME",
                    help="login-gate organization name for --serve "
                         "(default: netsec; env ROUND_VIEW_ORG)")
    ap.add_argument("--password",
                    default=os.environ.get("ROUND_VIEW_PASSWORD", "netsecpassword"),
                    metavar="PW",
                    help="login-gate password for --serve "
                         "(default: netsecpassword; env ROUND_VIEW_PASSWORD)")
    a = ap.parse_args()
    if a.serve:
        if not a.org or not a.password:
            ap.error("--org/--password must not be empty — refusing to serve "
                     "an open login gate")
        serve(a.root, a.serve, a.org, a.password)
        return
    hits, ts = payload(a.root)
    out = a.out or os.path.join(a.root, "dashboard.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    open(tmp, "w", encoding="utf-8").write(build_page(hits, ts))
    os.replace(tmp, out)
    print(f"[round-view] {len(hits)} entries "
          f"(0-DAY={sum(1 for h in hits if h['novelty']=='0-DAY')} "
          f"N-DAY={sum(1 for h in hits if h['novelty']=='N-DAY')} "
          f"CONFIRMED={sum(1 for h in hits if h['truth']=='CONFIRMED')} "
          f"REJECTED={sum(1 for h in hits if h['truth']=='REJECTED')} "
          f"PENDING={sum(1 for h in hits if h['truth']=='PENDING')})", file=sys.stderr)
    print(os.path.relpath(out, REPO) if out.startswith(REPO) else out)

main()
