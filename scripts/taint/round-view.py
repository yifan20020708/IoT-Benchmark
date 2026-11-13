#!/usr/bin/env python3
"""agent-scan :: taint — round-view: one static HTML ledger over data/round

Usage: round-view.py [--out PATH] [--root data/round]

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
  (3) Grouped vendor -> model, cards per hit with class/rc/marker/
      graded-ts; clicking a card opens the full audit (four dimensions +
      deterministic finality + novelty queries) and the rendered
      REPORT.md, straight from the vault files embedded in the page.

Default output: <root>/dashboard.html (a derived artifact — like
index.json it is rebuilt wholesale and never read by other scripts).
Exit 0; last stdout line = the HTML path.
"""
import argparse, datetime, glob, hashlib, html, json, os, sys

TRUTH = {"high": "CONFIRMED", "medium": "CONFIRMED", "low": "REJECTED"}
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

def sub(dct, key):
    v = dct.get(key) if isinstance(dct, dict) else None
    return v if isinstance(v, dict) else {}

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
        "novelty": status, "cve": nov.get("cve") or m.get("cve"),
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
.app{display:grid;grid-template-columns:280px minmax(0,1fr);height:100vh;overflow:hidden}

/* ── rail ─────────────────────────────────────────────── */
.rail{background:var(--surface);border-right:1px solid var(--line);padding:22px 20px;display:flex;flex-direction:column;gap:24px;position:sticky;top:0;height:100vh;overflow:hidden}
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
.cs-list{position:absolute;left:0;right:0;top:calc(100% + 6px);z-index:25;background:var(--surface2);border:1px solid var(--line);border-radius:11px;padding:4px;box-shadow:var(--shadow);animation:pop .16s cubic-bezier(.33,1,.6,1)}
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
.ring{flex:1;display:flex;flex-direction:column;align-items:center;gap:10px;min-width:0}
.ring .rt{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--faint)}
.rd{position:relative;width:96px;height:96px}
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
main{padding:0 30px;min-width:0;height:100vh;display:flex;flex-direction:column;overflow:hidden}
.mhead{display:flex;align-items:baseline;gap:16px;padding:26px 0 10px;flex-wrap:wrap;flex:0 0 auto;background:var(--bg)}
#body{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;padding-bottom:8px}
.mhead h1{font-size:19px;font-weight:680;margin:0;letter-spacing:-.01em}
.mtools{margin-left:auto;display:flex;align-items:center;gap:14px;font:11.5px var(--mono);color:var(--faint)}
.live{display:inline-flex;align-items:center;gap:6px}
.live s{width:7px;height:7px;border-radius:50%;background:var(--ok);text-decoration:none;animation:pulse 2.4s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
#thm{background:var(--surface);border:1px solid var(--line);color:var(--mut);border-radius:8px;padding:4px 10px;font-size:11px;cursor:pointer}
#thm:hover{color:var(--ink)}

.vhead{display:flex;align-items:baseline;gap:12px;margin:30px 0 4px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.vhead h2{margin:0;font-size:13px;font-weight:750;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.vhead .vc{font:11px var(--mono);color:var(--faint)}
.mblock{margin:20px 0 6px}
.mblock .mh{display:flex;align-items:baseline;gap:12px;margin-bottom:14px}
.mblock .mh h3{margin:0;font:13.5px var(--mono);font-weight:650;letter-spacing:.02em}
.mblock .mh .ms{font:11px var(--mono);color:var(--faint)}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}

.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px 17px 14px;cursor:pointer;min-width:0;transition:transform .12s ease,border-color .12s,box-shadow .12s;display:flex;flex-direction:column;gap:10px}
.card:hover{transform:translateY(-2px);border-color:var(--faint);box-shadow:var(--shadow)}
.card .ctop{display:flex;align-items:center;gap:8px}
.card .st{display:inline-flex;align-items:center;gap:7px;font-size:10.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;flex:none}
.dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)} .dot.pend{background:transparent;border:1.5px solid var(--pend)}
.card .nv{margin-left:auto;font-size:10.5px;font-weight:750;letter-spacing:.1em}
.day{color:var(--accent)} .nday{color:var(--sky)}
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
.dim h4 b{font-size:11px;letter-spacing:.04em;text-transform:none;font-weight:700}
.dim p{margin:0;font-size:12.5px;color:var(--mut)}
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
.rpt p{margin:8px 0;max-width:70ch}
.rpt code{font-family:var(--mono);background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:11.8px}
.rpt pre{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px 14px;overflow:auto}
.rpt pre code{background:none;border:none;padding:0;font-size:11.5px}
.rpt ul,.rpt ol{margin:8px 0;padding-left:22px}
.rpt li{margin:3px 0;max-width:72ch}
.rpt table{border-collapse:collapse;margin:10px 0;font-size:12.3px}
.rpt th,.rpt td{border:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top}
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
}
@media (prefers-reduced-motion: reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="app">
  <aside class="rail">
    <div class="brand">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.6"><path d="M12 2l8 4v6c0 5-3.5 8.4-8 10-4.5-1.6-8-5-8-10V6l8-4z"/><path d="M8.5 12.2l2.3 2.3 4.7-4.8" stroke="var(--ok)"/></svg>
      <div><div class="bn">Round Vault</div><div class="bs">agent-scan ledger</div></div>
    </div>
    <div class="search">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.5-4.5"/></svg>
      <input id="q" placeholder="poc · handler · marker · class…" autocomplete="off"><kbd>/</kbd>
    </div>
    <div>
      <div class="fl"><label for="cs-nov">Novelty</label><div class="cs" id="cs-nov"></div></div>
      <div class="fl"><label for="cs-truth">Status</label><div class="cs" id="cs-truth"></div></div>
      <div class="fl"><label for="cs-attr">Attribution</label><div class="cs" id="cs-attr"></div></div>
      <div class="fl"><label for="cs-vend">Vendor</label><div class="cs" id="cs-vend"></div></div>
      <button id="reset">Clear filters</button>
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
    </div>
    <div class="railfoot">
      <b>CONFIRMED</b> = the grader proved it and attribution holds
      (high &amp; medium). <b>REJECTED</b> = low confidence. Ratio rings
      weigh audited entries only.
    </div>
  </aside>

  <main>
    <div class="mhead">
      <h1>Vulnerability Ledger</h1>
      <div class="mtools">
        <span id="cnt"></span>
        <span class="live" id="live" hidden><s></s>live</span>
        <button id="thm">theme</button>
      </div>
    </div>
    <div id="body"></div>
    <footer>scripts/taint/round-view.py · data/round · one poc, one fresh boot, one deterministic verdict — __GEN__</footer>
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
      <button data-t="report">Report</button>
    </div>
    <div class="dheadspace"></div>
  </div>
  <div class="dbody">
    <div class="pane" id="pane-audit"></div>
    <div class="pane" id="pane-poc" hidden></div>
    <div class="pane" id="pane-report" hidden></div>
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
let F = {nov:"", truth:"", attr:"", vend:"", q:""};

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
  SEL.nov = listbox("cs-nov", [{v:"",n:"All"},{v:"0-DAY",n:"0-DAY"},{v:"N-DAY",n:"N-DAY"}], v=>{F.nov=v;render();});
  SEL.truth = listbox("cs-truth", [{v:"",n:"All"},{v:"CONFIRMED",n:"Confirmed"},{v:"REJECTED",n:"Rejected"}], v=>{F.truth=v;render();});
  SEL.attr = listbox("cs-attr", [{v:"",n:"All"},{v:"TOKEN",n:"TOKEN"},{v:"WINDOW",n:"WINDOW"}], v=>{F.attr=v;render();});
  SEL.vend = listbox("cs-vend", [{v:"",n:"All"}], v=>{F.vend=v;render();});
  $("#q").oninput=e=>{F.q=e.target.value.toLowerCase();render();};
  $("#reset").onclick=()=>{F={nov:"",truth:"",attr:"",vend:"",q:""};
    SEL.nov.set("");SEL.truth.set("");SEL.attr.set("");SEL.vend.set("");$("#q").value="";render();};
  document.addEventListener("keydown",e=>{
    if(e.key==="/"&&!/input|textarea|select/i.test(e.target.tagName)){e.preventDefault();$("#q").focus();}
    if(e.key==="Escape")closeDrawer();
  });
}
function fillVendors(){
  const vs=[...new Set(H.map(h=>h.vendor))].sort();
  SEL.vend.rebuild([{v:"",n:"All"}].concat(vs.map(v=>({v,n:v}))));
  SEL.vend.set(F.vend);
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
}

/* ── filtering ────────────────────────────────────────── */
function pass(h){
  if(F.nov && h.novelty!==F.nov) return false;
  if(F.truth && h.truth!==F.truth) return false;
  if(F.attr && h.attr_grade!==F.attr) return false;
  if(F.vend && h.vendor!==F.vend) return false;
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
function card(h,i){
  const dot = h.truth==="CONFIRMED"?"ok":h.truth==="REJECTED"?"bad":"pend";
  const stTxt = h.truth==="CONFIRMED"?"Confirmed":h.truth==="REJECTED"?"Rejected":"—";
  return `<article class="card" tabindex="0" data-i="${i}" aria-label="${esc(h.poc)}">
    <div class="ctop"><span class="st"><span class="dot ${dot}"></span>${esc(stTxt)}</span>
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
function render(){
  const vis = H.map((h,i)=>[h,i]).filter(([h])=>pass(h));
  $("#cnt").textContent = vis.length+" / "+H.length+" in vault";
  stat(vis.map(x=>x[0]));
  if(!vis.length){$("#body").innerHTML=`<div class="empty">no entries match the filters</div>`;return;}
  let out="";
  const vendors=[...new Set(vis.map(([h])=>h.vendor))];
  for(const v of vendors){
    const inV=H.filter(x=>x.vendor===v).length;
    out+=`<div class="vhead"><h2>${esc(v)}</h2><span class="vc">${inV} vaulted · ${vis.filter(x=>x[0].vendor===v).length} shown</span></div>`;
    const models=[...new Set(vis.filter(([h])=>h.vendor===v).map(([h])=>h.model))];
    for(const mo of models){
      const mm=vis.filter(([h])=>h.model===mo&&h.vendor===v);
      const conf=mm.filter(([h])=>h.truth==="CONFIRMED").length;
      out+=`<div class="mblock"><div class="mh"><h3>${esc(mo)}</h3><span class="ms">${mm.length} hit${mm.length===1?"":"s"} · ${conf} confirmed</span></div><div class="mgrid">`;
      out+=mm.map(([h,i])=>card(h,i)).join("");
      out+=`</div></div>`;
    }
  }
  $("#body").innerHTML=out;
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
  switchTab("audit");
  $("#scrim").classList.add("open"); $("#drawer").classList.add("open");
  $(".dbody").scrollTop=0;
}
function closeDrawer(){$("#scrim").classList.remove("open");$("#drawer").classList.remove("open");}
$("#dClose").onclick=closeDrawer; $("#scrim").onclick=closeDrawer;
$("#dTabs").onclick=e=>{if(e.target.dataset.t)switchTab(e.target.dataset.t);};
function switchTab(t){
  $$("#dTabs button").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
  ["audit","poc","report"].forEach(k=>{$("#pane-"+k).hidden = k!==t;});
}

/* ── live polling ─────────────────────────────────────── */
if(location.protocol.startsWith("http")){
  $("#live").hidden=false;
  setInterval(async()=>{
    try{
      const r = await fetch("/__data__", {cache:"no-store"});
      const j = await r.json();
      if(j.ts !== DATA_TS){
        const grew = j.hits.length > H.length;
        H = j.hits; DATA_TS = j.ts;
        fillVendors(); render();
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

initFilters(); fillVendors(); render();
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
                      h["conf"], h["flow"], len(h["report"]), len(h["poc_src"])] for h in hits])
    return hits, hashlib.md5(key.encode()).hexdigest()

def build_page(hits, ts):
    gen = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    data = json.dumps({"ts": ts, "hits": hits}, ensure_ascii=False).replace("</", "<\\/")
    return (TEMPLATE
            .replace("__GEN__", html.escape(gen))
            .replace("__TOTAL__", str(len(hits)))
            .replace("__DATA__", data))

def serve(root, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    ROOT_R = os.path.realpath(root)
    TYPES = {".json": "application/json", ".md": "text/plain; charset=utf-8",
             ".py": "text/plain; charset=utf-8", ".c": "text/plain; charset=utf-8",
             ".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
             ".html": "text/html; charset=utf-8"}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def _send(self, code, ctype, body):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            p = self.path.split("?")[0]
            if p in ("/", "/dashboard.html"):
                hits, ts = payload(root)          # fresh scan per request
                self._send(200, "text/html; charset=utf-8", build_page(hits, ts))
            elif p == "/__data__":
                hits, ts = payload(root)
                self._send(200, "application/json",
                           json.dumps({"ts": ts, "hits": hits},
                                      ensure_ascii=False).replace("</", "<\\/"))
            else:  # raw vault files (evidence etc); no dir listings
                f = os.path.realpath(os.path.join(ROOT_R, p.lstrip("/")))
                if f.startswith(ROOT_R + os.sep) and os.path.isfile(f):
                    self._send(200, TYPES.get(os.path.splitext(f)[1].lower(),
                                              "application/octet-stream"),
                               open(f, "rb").read())
                else:
                    self._send(404, "text/plain", "404\n")
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[round-view] LIVE serve http://0.0.0.0:{port}/dashboard.html "
          f"(root {root}; rescans per request, page polls every 4s)", file=sys.stderr)
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
    a = ap.parse_args()
    if a.serve:
        serve(a.root, a.serve)
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
