#!/usr/bin/env python3
"""
agent-scan :: taint — frontend keyword extraction (deterministic, host-side)

Usage: frontend-keywords.py [--out FILE] [--cap N] <rootfs-dir>

IDENTIFICATION is purely suffix-based — no per-firmware, no per-directory
tuning (vendors scatter web assets under webroot/, www/, htdocs/, opt/web/,
... and new names keep appearing; directory-name discovery does not
generalize). Every file under <rootfs> is classified by extension:

    markup  : .html .htm .xhtml .shtml .shtm .asp .aspx .jsp .jspx .php .tpl
    script  : .js .mjs .vue .ts .jsx
    data    : .json .xml — parsed only when their directory also holds
              markup/script files (system configs in /etc are not frontend;
              the "near web content" test is derived from content, not names)

.css carries no request vocabulary and is not parsed. .asp/.php/.jsp are
vendor page templates — they are markup with embedded code, and the parser
below tolerates the embedded fragments.

PARSING per category:
    markup  : HTML form-field attributes (name=, data-field, data-name,
              data-key, data-param, id= on input-ish elements), URL-ish
              values in action/href/src, plus endpoints/keys/actions
              harvested from the raw text (inline scripts). Script blocks
              that ARE client-side templates (type="text/template" &c, or
              any script body containing form markup) are re-parsed as
              markup — SPA frontends keep their whole form vocabulary there
    script  : endpoint strings, object keys (network-context flagged),
              dispatch-shaped literals (setWanDhcp / getDnsData ...)
    data    : object keys + endpoint-shaped string values

Output (JSON), every entry carries evidence (count + origins + files):
    files_by_ext / files_scanned / vendor_skipped
    param_names   form field names (the by-name lookup vocabulary)
    endpoints     goform/..., /cgi-bin/..., *.cgi, *.asp, /xxx/yy.html ...
    js_net_keys   object keys near network calls (requestUrl/$.post/...)
    js_keys       all identifier-shaped object keys (broad, low signal)
    action_names  set/get/add/...-shaped literals (dispatch-key candidates)

Buckets stay separate — the consuming agent weighs them
(js_net_keys > param_names > js_keys) and the join with backend strings
filters frontend-framework noise naturally. Lists are count-sorted and
capped at --cap entries per bucket. Exit 0 on success, 1 on bad input.

Vendor library filtering (jquery, angular, ...) is generic web knowledge,
valid for any firmware; it removes noise, never signal.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------------------
# file classes by extension (the identification contract — keep generic)
# ---------------------------------------------------------------------------
MARKUP_EXTS = {".html", ".htm", ".xhtml", ".shtml", ".shtm",
               ".asp", ".aspx", ".jsp", ".jspx", ".php", ".tpl"}
SCRIPT_EXTS = {".js", ".mjs", ".vue", ".ts", ".jsx"}
DATA_EXTS = {".json", ".xml"}   # gated on web content in the same directory

# ---------------------------------------------------------------------------
# vendor library noise — generic web knowledge, not firmware-specific tuning
# ---------------------------------------------------------------------------
VENDOR_NAME_SUBSTRINGS = (
    "jquery", "angular", "vue", "react", "bootstrap", "layui", "underscore",
    "lodash", "mootools", "prototype", "dojo", "yui", "ext-all", "swfobject",
    "modernizr", "polyfill", "html5shiv", "wdatepicker", "kindeditor",
    "ueditor", "echarts", "highcharts", "chart",
)
VENDOR_BANNERS = (
    "jQuery JavaScript Library", "AngularJS v", "Vue.js v",
    "Bootstrap v", "Dojo Toolkit",
)

# URL-ish endpoint patterns (markup attribute values, script/data text).
# The lookbehind rejects identifier characters (so "mygoform/x" is not a
# match) but allows "/" and quotes — "/goform/module" must match.
ENDPOINT_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_.-])(?:goform|GoForm)/[A-Za-z0-9_/.-]{1,48}"
    r"|/cgi-bin/[A-Za-z0-9_/.-]{1,48}"
    r"|/userRpm/[A-Za-z0-9_/.-]{1,48}"
    r"|[A-Za-z0-9_-]{1,32}\.(?:cgi|asp)\b"
    r"|/[A-Za-z0-9_-]{1,32}/[A-Za-z0-9_.-]{1,32}\.htm[l]?\b)"
)

# object keys in script/JSON text: "key": | {key: | ,key:
KEY_QUOTED_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{0,31})"\s*:')
KEY_BARE_RE = re.compile(r'[{,]\s*([A-Za-z_$][A-Za-z0-9_$]{0,31})\s*:')

# dispatch-key-shaped string literals: setWanDhcp / getDnsData / addRule ...
ACTION_RE = re.compile(
    r'["\']((?:set|get|add|del|rm|mod|apply|cfg|do|op)[A-Z][A-Za-z0-9]{1,28})["\']'
)

# network-call context: keys matched within +/- this many characters of one
# of these markers count as js_net_keys
NET_CONTEXT_RE = re.compile(
    r"requestUrl|requestData|requestOpt|\$\.post|\$\.ajax|\$\.get\b|axios"
    r"|fetch\(|XMLHttpRequest|goform|\.cgi|\.asp"
)
NET_CONTEXT_WINDOW = 200

# HTML element/attribute harvesting
INPUTISH_TAGS = {"input", "select", "textarea", "button", "option"}
NAME_ATTRS = ("name", "data-field", "data-name", "data-key", "data-param")
URLISH_ATTRS = ("action", "href", "src")

# client-side templates (<script type="text/template">…</script>) hold REAL
# form markup that the HTML parser treats as script CDATA — a generic web
# pattern (Bootstrap/Backbone/EJS), detected by type OR by content
TEMPLATE_TYPE_HINTS = ("template", "text/html", "x-handlebars", "ejs",
                       "mustache", "text/x-")
MARKUP_BLOCK_RE = re.compile(
    r"<\s*(?:input|select|textarea|form|option|button)\b", re.IGNORECASE)


class FormHarvester(HTMLParser):
    """Collects parameter-ish attribute values and URL-ish endpoints.

    Script blocks whose type or content marks them as client-side templates
    are re-parsed as markup (their <input name=...> vocabulary is invisible
    to the outer parse: it is script CDATA there)."""

    def __init__(self, sink):
        super().__init__(convert_charrefs=True)
        self.sink = sink  # sink(bucket, value, origin)
        self._script = None  # [type, [chunks]] while inside <script>

    def _emit(self, bucket, value, origin):
        self.sink(bucket, value, origin)

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._script = [((dict(attrs).get("type") or "")).lower(), []]
            return
        a = dict(attrs)
        if tag in INPUTISH_TAGS:
            for attr in NAME_ATTRS:
                v = (a.get(attr) or "").strip()
                if v and len(v) <= 48:
                    self._emit("param_names", v, f"html-{attr}")
            # ids of input elements — often field names, noisier than name=
            v = (a.get("id") or "").strip()
            if v and len(v) <= 48:
                self._emit("param_names", v, "html-id")
        for attr in URLISH_ATTRS:
            v = (a.get(attr) or "").strip()
            if v:
                for m in ENDPOINT_RE.finditer(v):
                    self._emit("endpoints", m.group(0), f"html-{attr}")
        # any element can carry a data-* field name (vendor form frameworks);
        # data-bs-* is Bootstrap UI state (generic web knowledge), never a
        # request parameter
        for k, v in attrs:
            if k and k.startswith("data-") and not k.startswith("data-bs") \
                    and k not in NAME_ATTRS and v:
                v = v.strip()
                if v and len(v) <= 48 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v):
                    self._emit("param_names", v, f"html-{k}")

    def handle_data(self, data):
        if self._script is not None:
            self._script[1].append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            stype, chunks = self._script
            self._script = None
            text = "".join(chunks)
            if not text:
                return
            templateish = (any(h in stype for h in TEMPLATE_TYPE_HINTS)
                           or MARKUP_BLOCK_RE.search(text))
            if templateish:
                try:
                    tpl = FormHarvester(
                        lambda b, v, o: self._emit(b, v, f"tpl-{o}"))
                    tpl.feed(text)
                except Exception:
                    pass  # malformed template: keep whatever parsed so far


def is_vendor(path: Path, text_head: str) -> bool:
    """True when the file looks like a third-party web library."""
    low = path.name.lower()
    if any(sub in low for sub in VENDOR_NAME_SUBSTRINGS):
        return True
    return any(banner in text_head for banner in VENDOR_BANNERS)


def harvest_text(text: str, sink, origin_prefix: str):
    """Endpoints, object keys and action-shaped literals from raw text
    (script files, inline script inside markup, data files)."""
    for m in ENDPOINT_RE.finditer(text):
        sink("endpoints", m.group(0), f"{origin_prefix}-literal")
    for m in ACTION_RE.finditer(text):
        sink("action_names", m.group(1), f"{origin_prefix}-literal")
    # object keys — with network-context attribution
    net_spans = [m.span() for m in NET_CONTEXT_RE.finditer(text)]
    keys = [(m.start(), m.group(1)) for m in KEY_QUOTED_RE.finditer(text)]
    keys += [(m.start(), m.group(1)) for m in KEY_BARE_RE.finditer(text)]
    for pos, key in keys:
        bucket = "js_keys"
        origin = f"{origin_prefix}-key"
        for s, e in net_spans:
            if s - NET_CONTEXT_WINDOW <= pos <= e + NET_CONTEXT_WINDOW:
                bucket = "js_net_keys"
                origin = f"{origin_prefix}-net-key"
                break
        sink(bucket, key, origin)


def finalize(counter: Counter, origins: defaultdict, files: defaultdict, cap: int):
    """Render one bucket into its JSON-ready, count-sorted, capped form."""
    out = []
    for value, count in counter.most_common(cap):
        out.append({
            "name": value,
            "count": count,
            "origins": sorted(origins[value]),
            "files": sorted(files[value])[:3],
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="harvest frontend keyword sets from an unpacked rootfs "
                    "(suffix-based identification, category parsers)")
    ap.add_argument("rootfs", help="path to the firmware root filesystem")
    ap.add_argument("--out", help="output JSON path (default: stdout)")
    ap.add_argument("--cap", type=int, default=500,
                    help="max entries per bucket (default 500)")
    args = ap.parse_args()

    root = Path(args.rootfs)
    if not root.is_dir():
        print(f"[-] not a directory: {root}", file=sys.stderr)
        return 1

    # ---- pass 1: classify every file by suffix ------------------------------
    all_files = [p for p in root.rglob("*") if p.is_file()]
    markup = [p for p in all_files if p.suffix.lower() in MARKUP_EXTS]
    script = [p for p in all_files if p.suffix.lower() in SCRIPT_EXTS]
    web_dirs = {p.parent for p in markup} | {p.parent for p in script}
    data = [p for p in all_files
            if p.suffix.lower() in DATA_EXTS and p.parent in web_dirs]

    # ---- pass 2: parse by category ------------------------------------------
    buckets = {b: Counter() for b in
               ("param_names", "endpoints", "js_net_keys", "js_keys",
                "action_names")}
    origins = defaultdict(set)
    files = defaultdict(set)
    files_by_ext = Counter()
    scanned = 0
    vendor_skipped = []
    cur_file = None

    def sink(bucket, value, origin):
        buckets[bucket][value] += 1
        origins[value].add(origin)
        files[value].add(cur_file)

    def process(path: Path, origin_prefix: str, also_markup: bool):
        nonlocal cur_file, scanned
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if is_vendor(path, text[:8192]):
            vendor_skipped.append(str(path.relative_to(root)))
            return
        cur_file = str(path.relative_to(root))
        scanned += 1
        files_by_ext[path.suffix.lower()] += 1
        if also_markup:
            try:
                FormHarvester(sink).feed(text)
            except Exception:
                pass  # malformed markup: keep whatever was parsed so far
        harvest_text(text, sink, origin_prefix)

    for p in sorted(markup):
        process(p, "inline", also_markup=True)
    for p in sorted(script):
        process(p, "js", also_markup=False)
    for p in sorted(data):
        process(p, p.suffix.lower().lstrip("."), also_markup=False)

    result = {
        "rootfs": str(root),
        "files_by_ext": dict(sorted(files_by_ext.items())),
        "files_scanned": scanned,
        "vendor_skipped_count": len(vendor_skipped),
        "vendor_skipped": vendor_skipped[:50],
        "param_names": finalize(buckets["param_names"], origins, files, args.cap),
        "endpoints": finalize(buckets["endpoints"], origins, files, args.cap),
        "js_net_keys": finalize(buckets["js_net_keys"], origins, files, args.cap),
        "js_keys": finalize(buckets["js_keys"], origins, files, args.cap),
        "action_names": finalize(buckets["action_names"], origins, files, args.cap),
    }

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print(f"[keywords] {args.out}: scanned={scanned} "
              f"param_names={len(result['param_names'])} "
              f"endpoints={len(result['endpoints'])} "
              f"js_net_keys={len(result['js_net_keys'])} "
              f"js_keys={len(result['js_keys'])} "
              f"action_names={len(result['action_names'])}")
    else:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
