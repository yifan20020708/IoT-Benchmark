#!/usr/bin/env python3
"""frontend-surface — the client-side request-surface extractor
(taint stage, Phase-1 Mapper input).

Usage: frontend-surface.py [--out FILE] [--max-bytes N] <rootfs>

A DUMB EXTRACTOR: it pulls the frontend's vocabulary OUT completely and
decides NOTHING. Which field is auth-relevant, which URL dispatches to
which handler, which cookie is the session — that judgment belongs to
the Mapper agent. The tool's job is only to hand it the raw client-side
half of the cross-reference. Noise is TAGGED (origins, controls,
contexts), never filtered: the Mapper's use is a JOIN against the
server-side vocabulary (accessor key strings, dispatch strings), and a
join loses to gaps, not to noise.

Aggregates:
  endpoints    URL-ish paths: form actions, <a href> navigation, and
               path-shaped string literals in JS (incl. inline scripts);
               query-string keys of those URLs land in `fields`
  fields       request-field candidates from structural sources only:
               form-control name= attributes and URL query keys
  js_keys      EVERY object-literal key in script files/inline scripts,
               each carrying its context path (the parent key chain,
               e.g. formCfg.fields, or a webpack module id) — the corpus's
               real field vocabulary lives here (JS-built request bodies,
               framework form configs), so coverage beats net-call
               adjacency heuristics; member assignments (a.b.c =) are
               folded in the same way (request bodies built by mutation).
               The lex pass is regex-literal aware — quotes inside a
               character class (/["'&<>]/g) used to desync a plain
               string-skipping lexer and swallow kilobytes of minified
               bundles — and bracket matching runs on the code-only text,
               immune to quotes/brackets inside strings, comments and
               regexes. Function bodies ARE walked: a webpack bundle
               wraps all its modules in function values.
  data_attrs   every data-* attribute value in markup, keyed by the
               attribute name — embedded UI frameworks carry their
               form field names in data-key/data-field attributes
  forms        per-form structural records: file, action, method, its
               fields — the shape of a minimal valid request
  cookies      document.cookie usage sites, cookie-name evidence from
               assignments, *Cookie("name") idioms and the read-side
               document.cookie.indexOf("name=") idiom, set-cookie
               mentions
  template_    <script> blocks that carry markup (typed template mimes
blocks       or content-detected); their bodies are re-parsed — client-
               side templates hide form vocabulary from an outer parse

Deliberately NOT extracted (the agent has the raw files and grep):
  html id= attributes (DOM anchors, not request vocabulary), plain
  string literals (the dispatch-value join target — one grep away),
  non-markup/non-script files.

Determinism: sorted walks, sorted aggregates, capped sorted origins,
no timestamps — byte-reproducible output.

Output: <model>/taint-work/frontend-surface.json where <model> is the
nearest task.json ancestor of <rootfs>; without one, --out is required.
Exit 0 = written (an empty surface is a valid answer — no frontend in
this rootfs); the summary line goes to stdout.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

MARKUP_EXTS = {
    ".html", ".htm", ".xhtml", ".shtml", ".vue",
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".jsp", ".jspx", ".tpl", ".tmpl",
}
SCRIPT_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}

# <script type=...> values that make the block an inert client-side
# template (a mechanism fact about browsers, not a vendor judgment)
TEMPLATE_TYPES = {
    "text/template", "text/x-template", "text/html", "text/ng-template",
    "text/x-jquery-tmpl", "text/x-handlebars-template", "text/x-tmpl",
    "text/x-kendo-template", "text/mustache",
}

# a script body that contains these is markup-in-JS (content-detected
# template) — parsed as markup AND js-extracted, both halves kept
STRONG_TAG_RE = re.compile(
    r"<(?:input|form|select|textarea|button|div|table|a|ul|ol|li|span|"
    r"img|label|option|tr|td|nav|section|header|footer|p|h[1-6])[\s/>]",
    re.I)

TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)([^>]*)>", re.S)
ATTR_RE = re.compile(
    r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\">]+))")
SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
FORM_CLOSE_RE = re.compile(r"</form\s*>", re.I)

DOC_COOKIE_RE = re.compile(r"document\s*\.\s*cookie\b", re.I)
COOKIE_ASSIGN_RE = re.compile(r"document\s*\.\s*cookie\s*=\s*([\"'])(.*?)\1")
COOKIE_FN_RE = re.compile(
    r"([A-Za-z_$][\w$]*[Cc]ookie[\w$]*)\s*\(\s*[\"']([\w.\-]+)[\"']")
# read side: document.cookie.indexOf("name=") — the cookie NAME lives in
# the searched literal (trailing "=" stripped)
COOKIE_READ_RE = re.compile(
    r"document\s*\.\s*cookie\s*\.\s*"
    r"(?:indexOf|lastIndexOf|includes|startsWith|search)\s*\(\s*"
    r"[\"']([^\"'\s;]{1,64})[\"']")
SET_COOKIE_RE = re.compile(r"set-cookie", re.I)

# no "!" — webpack loader chains (!!x/loader.js?!./f.scss) are build-time,
# never browser-fetchable; same mechanism-fact class as data:/javascript:
PATH_CHARS_RE = re.compile(r"^[\w\-./%?&=+~:,@#$'()*\[\]]+$")
WORD_RE = re.compile(r"^[A-Za-z_][\w\-.]{0,63}$")
KEY_NAME_RE = re.compile(r"^[A-Za-z_$][\w$\-.]{0,63}$")
NUM_KEY_RE = re.compile(r"^\d{1,6}$")

MAX_ORIGIN = 12
MAX_CONTEXT_DEPTH = 4
CONTROL_TAGS = {"input", "select", "textarea", "button"}


def path_shaped(s):
    """URL-ish and plausibly server-relevant (>=2 segments, no scheme)."""
    if s is None:
        return False
    s = s.split("#", 1)[0]
    if not (2 <= len(s) <= 512):
        return False
    if any(ch.isspace() or ord(ch) > 126 for ch in s):
        return False
    if s.startswith(("//", "http:", "https:", "data:", "javascript:",
                     "mailto:", "tel:", "#")):
        return False
    if "://" in s:
        return False
    if not PATH_CHARS_RE.match(s):
        return False
    segs = [x for x in s.split("/") if x]
    return len(segs) >= 2 and any(re.search(r"[A-Za-z]", x) for x in segs)


def query_keys(s):
    """parameter names of a URL's query string."""
    if "?" not in s:
        return []
    q = s.split("?", 1)[1]
    return [kv.split("=", 1)[0] for kv in q.split("&") if kv]


def parse_attrs(body):
    attrs = {}
    for m in ATTR_RE.finditer(body):
        v = m.group(2)
        if v is None:
            v = m.group(3)
        if v is None:
            v = m.group(4)
        attrs[m.group(1).lower()] = v or ""
    return attrs


# ---- JS lexical core -----------------------------------------------------
# ONE forward pass classifies strings / comments / REGEX LITERALS vs
# division (the classic preceding-token heuristic). Bracket matching then
# runs on the code-only text, immune to quotes and brackets hiding inside
# strings, comments and regexes — a regex like /["'&<>]/g used to open a
# phantom string and silently swallow kilobytes of a minified bundle.

# a `/` after one of these keywords starts a regex literal, not division
JS_KEYWORDS = {"return", "case", "typeof", "instanceof", "in", "of", "new",
               "delete", "void", "throw", "do", "else", "yield", "await"}
ASSIGN_CHAIN_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*=(?![=>])")
_OPENER = {"(": ")", "[": "]", "{": "}"}
_CLOSER = {")": "(", "]": "[", "}": "{"}


def _skip_string(src, i):
    """src[i] is a quote; index just past the closing quote."""
    quote = src[i]
    j = i + 1
    n = len(src)
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == quote:
            return j + 1
        if quote != "`" and src[j] == "\n":
            return j
        j += 1
    return n


def _skip_regex(src, i):
    """src[i] == '/' opening a regex literal; index past it (incl. flags),
    or -1 if it does not terminate before a newline (then it is not a
    regex — treat as division)."""
    j = i + 1
    n = len(src)
    in_class = False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            return j
        elif c == "\n":
            return -1
        j += 1
    return -1


def _tail_token(text):
    """the last significant token of a code fragment, for the
    regex-vs-division decision: 'kw', 'ident', or the last punct char."""
    k = len(text) - 1
    while k >= 0 and text[k].isspace():
        k -= 1
    if k < 0:
        return ""
    if text[k].isalnum() or text[k] in "_$":
        j = k
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        return "kw" if text[j + 1:k + 1] in JS_KEYWORDS else "ident"
    return text[k]


def _regex_allowed(prev):
    if prev in ("ident", ")", "]"):
        return False  # division
    return True  # nothing yet, after a keyword/string/regex or any punct


class _JSLex:
    """One lex pass over a script: code text (strings/comments/regexes
    excised), the src offset of every code char, and the bracket-pair
    map over the code text. Walkers below navigate this in O(n)."""

    def __init__(self, src):
        self.src = src
        self._tokens = []       # (kind, i, j) of str/comment/regex spans
        pieces, poss = [], []
        i, n, last = 0, len(src), 0
        prev = ""               # last significant token (comments excluded)
        while i < n:
            c = src[i]
            if c in "'\"`":
                j = _skip_string(src, i)
                if i > last:
                    prev = _tail_token(src[last:i])
                    self._emit(pieces, poss, src, last, i)
                self._tokens.append(("str", i, j))
                i = last = j
                prev = "str"
            elif c == "/" and src[i + 1:i + 2] == "/":
                k = src.find("\n", i)
                j = n if k < 0 else k + 1
                if i > last:
                    prev = _tail_token(src[last:i])
                    self._emit(pieces, poss, src, last, i)
                self._tokens.append(("comment", i, j))
                i = last = j      # comments keep `prev` unchanged
            elif c == "/" and src[i + 1:i + 2] == "*":
                k = src.find("*/", i + 2)
                j = n if k < 0 else k + 2
                if i > last:
                    prev = _tail_token(src[last:i])
                    self._emit(pieces, poss, src, last, i)
                self._tokens.append(("comment", i, j))
                i = last = j
            elif c == "/":
                if i > last:
                    prev = _tail_token(src[last:i])
                    self._emit(pieces, poss, src, last, i)
                    last = i
                if _regex_allowed(prev):
                    j = _skip_regex(src, i)
                    if j > 0:
                        self._tokens.append(("regex", i, j))
                        i = last = j
                        prev = "regex"
                        continue
                    # unterminated: not a regex after all — division
                prev = "/"
                i += 1
            else:
                i += 1
        if n > last:
            self._emit(pieces, poss, src, last, n)
        self.code = "".join(pieces)
        self.pos = poss
        self.match = self._match_brackets()

    @staticmethod
    def _emit(pieces, poss, src, a, b):
        if b > a:
            pieces.append(src[a:b])
            poss.extend(range(a, b))

    def _match_brackets(self):
        code = self.code
        stack = []
        match = {}
        for i, ch in enumerate(code):
            if ch in _OPENER:
                stack.append(i)
            elif ch in _CLOSER:
                if stack and code[stack[-1]] == _CLOSER[ch]:
                    match[stack.pop()] = i
                elif stack:
                    stack.pop()  # mismatched: both stay unmatched
        return match

    # ---- derived views ---------------------------------------------------
    def strings(self):
        """string-literal contents (exact text, no unescaping)."""
        out = []
        src = self.src
        for kind, i, j in self._tokens:
            if kind != "str" or j - i < 2:
                continue
            if src[j - 1] == src[i]:
                out.append(src[i + 1:j - 1])
            else:               # unterminated line-string
                out.append(src[i + 1:j])
        return out

    def object_keys(self):
        """every object-literal key with its context path — descends into
        every bracket region, function bodies included (a webpack bundle
        wraps all its modules in function values). Yields (key, context)."""
        out = []
        self._walk(0, len(self.code), "", out)
        return out

    def member_writes(self):
        """object member assignments (a.b.c = ..., not ==/=>/+=): the last
        segment is the field, the prefix is its context — request bodies
        built by mutation instead of one literal."""
        out = []
        for m in ASSIGN_CHAIN_RE.finditer(self.code):
            parts = m.group(1).split(".")
            if len(parts) >= 2:
                prefix = ".".join(parts[:-1])[:MAX_CONTEXT_DEPTH * 24]
                out.append((parts[-1], prefix))
        return out

    # ---- raw-text helpers ------------------------------------------------
    def _raw(self, a, b):
        """src text covered by code range [a, b)."""
        if a >= b:
            return ""
        return self.src[self.pos[a]:self.pos[b - 1] + 1]

    def _skip_region(self, i, b):
        """past the bracket pair opened at code index i, or None."""
        close = self.match.get(i)
        if close is None or close >= b:
            return None
        return close

    def _split_top(self, a, b):
        """(start, end) code ranges of comma-separated entries at depth 0."""
        out = []
        code = self.code
        s = a
        i = a
        while i < b:
            c = code[i]
            if c in _OPENER:
                close = self._skip_region(i, b)
                if close is None:
                    return []  # unbalanced inside — not a literal
                i = close + 1
                continue
            if c in _CLOSER:
                return []      # stray closer — caller guards the span
            if c == ",":
                out.append((s, i))
                s = i + 1
            i += 1
        out.append((s, b))
        return out

    def _top_colon(self, s, e):
        """code index of the depth-0 colon of a pair entry, or None.
        Colons inside strings never reach the code text, so quoted keys
        containing ':' cannot confuse this."""
        code = self.code
        i = s
        while i < e:
            c = code[i]
            if c in _OPENER:
                close = self._skip_region(i, e)
                if close is None:
                    return None
                i = close + 1
                continue
            if c == ":":
                return i
            i += 1
        return None

    def _walk(self, a, b, ctx, out):
        code = self.code
        i = a
        while i < b:
            c = code[i]
            if c in _OPENER:
                close = self._skip_region(i, b)
                if close is None:
                    return     # unbalanced/truncated region: give up
                if c == "{":
                    self._obj_pairs(i + 1, close, ctx, out)
                else:          # ( and [ — descend, context unchanged
                    self._walk(i + 1, close, ctx, out)
                i = close + 1
                continue
            i += 1

    def _obj_pairs(self, a, b, ctx, out):
        for s, e in self._split_top(a, b):
            if e <= s:
                continue
            colon = self._top_colon(s, e)
            key = None
            if colon is not None:
                cand = _strip_key_quotes(self._raw(s, colon).strip())
                if cand and (KEY_NAME_RE.match(cand) or NUM_KEY_RE.match(cand)):
                    key = cand
            child = ctx
            wstart = s
            if key is not None:
                out.append((key, ctx))
                child = key if not ctx else ctx + "." + key
                child = ".".join(child.split(".")[:MAX_CONTEXT_DEPTH])
                if colon + 1 < e:
                    wstart = colon + 1
            # walk the pair's value — or, for a non-pair entry (var
            # declarations, function bodies, ternaries), the whole entry:
            # objects nested inside are found by the brace descent, and a
            # function value's inner objects belong to this key's context
            self._walk(wstart, e, child, out)


def _strip_key_quotes(k):
    if len(k) >= 2 and k[0] in "\"'" and k[-1] == k[0]:
        return k[1:-1]
    return k


def js_string_literals(src):
    """String literals (' \" `) with comment and regex awareness."""
    return _JSLex(src).strings()


def js_object_keys(src):
    """Every object-literal key with its context path."""
    return _JSLex(src).object_keys()


class Surface:
    def __init__(self):
        self.scan = Counter()
        self.endpoints = {}          # path -> {n_files, origins, kinds}
        self.fields = {}             # name -> {n_files, origins, controls}
        self.js_keys = {}            # key -> {n_files, origins, occurrences, contexts}
        self.data_attrs = {}         # value -> {n_files, origins, attrs}
        self.forms = []              # per-form structural records
        self.template_blocks = []
        self.cookies = {
            "document_cookie": {"n_files": 0, "origins": []},
            "set_cookie_literal": {"n_files": 0, "origins": []},
            "names": {},
        }
        self._ep_files = {}
        self._fd_files = {}
        self._jsk_files = {}
        self._dat_files = {}
        self._dc_files = set()
        self._sc_files = set()
        self._cookie_files = {}

    # ---- aggregation helpers -------------------------------------------
    def add_endpoint(self, path, origin, kind):
        rec = self.endpoints.setdefault(
            path, {"n_files": 0, "origins": [], "kinds": {}})
        fs = self._ep_files.setdefault(path, set())
        if origin not in fs:
            fs.add(origin)
            rec["n_files"] = len(fs)
        rec["kinds"][kind] = rec["kinds"].get(kind, 0) + 1

    def add_field(self, name, control, origin):
        rec = self.fields.setdefault(
            name, {"n_files": 0, "origins": [], "controls": {}})
        fs = self._fd_files.setdefault(name, set())
        if origin not in fs:
            fs.add(origin)
            rec["n_files"] = len(fs)
        rec["controls"][control] = rec["controls"].get(control, 0) + 1

    def add_js_key(self, key, ctx, origin):
        rec = self.js_keys.setdefault(
            key, {"n_files": 0, "origins": [], "occurrences": 0,
                  "contexts": {}})
        fs = self._jsk_files.setdefault(key, set())
        if origin not in fs:
            fs.add(origin)
            rec["n_files"] = len(fs)
        rec["occurrences"] += 1
        rec["contexts"][ctx] = rec["contexts"].get(ctx, 0) + 1

    def add_data_attr(self, value, attr, origin):
        rec = self.data_attrs.setdefault(
            value, {"n_files": 0, "origins": [], "attrs": {}})
        fs = self._dat_files.setdefault(value, set())
        if origin not in fs:
            fs.add(origin)
            rec["n_files"] = len(fs)
        rec["attrs"][attr] = rec["attrs"].get(attr, 0) + 1

    def add_cookie_name(self, name, origin, evidence):
        rec = self.cookies["names"].setdefault(
            name, {"n_files": 0, "origins": [], "evidence": {}})
        fs = self._cookie_files.setdefault(name, set())
        if origin not in fs:
            fs.add(origin)
            rec["n_files"] = len(fs)
        rec["evidence"][evidence] = rec["evidence"].get(evidence, 0) + 1

    # ---- scanners -------------------------------------------------------
    def scan_js(self, src, origin):
        self.scan["js_blocks"] += 1
        lex = _JSLex(src)     # one pass: strings, comments, regexes
        for lit in lex.strings():
            if path_shaped(lit):
                self.add_endpoint(lit, origin, "script_literal")
                for k in query_keys(lit):
                    if WORD_RE.match(k):
                        self.add_field(k, "query", origin)
        for key, ctx in lex.object_keys():
            self.add_js_key(key, ctx, origin)
        for key, ctx in lex.member_writes():
            self.add_js_key(key, ctx, origin)
        if DOC_COOKIE_RE.search(src):
            self._dc_files.add(origin)
            self.cookies["document_cookie"]["n_files"] = len(self._dc_files)
        for m in COOKIE_ASSIGN_RE.finditer(src):
            # "name=value; expires=..." — the name is before the first
            # ; or =
            name = ((m.group(2) or "").split(";", 1)[0]
                    .split("=", 1)[0].strip())
            if name and len(name) <= 128:
                self.add_cookie_name(name, origin, "document.cookie=")
        for m in COOKIE_FN_RE.finditer(src):
            self.add_cookie_name(m.group(2), origin, "call:" + m.group(1))
        for m in COOKIE_READ_RE.finditer(src):
            self.add_cookie_name(m.group(1).rstrip("="),
                                 origin, "document.cookie.read")

    def scan_markup(self, src, origin, depth):
        self.scan["markup_scans"] += 1
        cur_form = None
        # script bodies are excluded from the tag walk (their tags would
        # double-count as markup controls)
        script_spans = []
        tpl_idx = 0
        for m in SCRIPT_RE.finditer(src):
            body = m.group(2)
            if not body.strip():
                continue  # external script (src=), nothing inline
            attrs = parse_attrs(m.group(1))
            stype = (attrs.get("type") or "").strip().lower()
            script_spans.append((m.start(2), m.end(2)))
            if stype in TEMPLATE_TYPES:
                kind = stype
            elif STRONG_TAG_RE.search(body):
                kind = "content-detected"
            else:
                kind = ""
            if kind:
                tpl_idx += 1
                self.template_blocks.append(
                    {"file": origin, "type": kind, "bytes": len(body)})
                self.scan["template_blocks"] += 1
                if depth < 2:
                    self.scan_markup(body, "%s#tpl%d" % (origin, tpl_idx),
                                     depth + 1)
                if kind != "content-detected":
                    continue  # inert template: no JS in it
                # content-detected: real JS that also embeds markup —
                # keep both halves
            self.scan_js(body, origin)

        def in_script(pos):
            return any(a <= pos < b for a, b in script_spans)

        # TAG_RE never matches closing tags, so </form> positions are
        # tracked separately to end the current form record
        form_closes = [m.start() for m in FORM_CLOSE_RE.finditer(src)]
        close_idx = 0

        for m in TAG_RE.finditer(src):
            while (close_idx < len(form_closes)
                    and form_closes[close_idx] < m.start()):
                if cur_form is not None:
                    self.forms.append(cur_form)
                    cur_form = None
                close_idx += 1
            if in_script(m.start()):
                continue
            name = m.group(1).lower()
            attrs = parse_attrs(m.group(2))
            if name == "form":
                if cur_form is not None:
                    self.forms.append(cur_form)
                cur_form = {
                    "file": origin,
                    "action": attrs.get("action", ""),
                    "method": (attrs.get("method") or "").lower(),
                    "fields": [],
                }
                action = attrs.get("action")
                if action and path_shaped(action):
                    self.add_endpoint(action, origin, "form_action")
                    for k in query_keys(action):
                        if WORD_RE.match(k):
                            self.add_field(k, "query", origin)
            elif name == "a":
                href = attrs.get("href")
                if href and path_shaped(href):
                    self.add_endpoint(href, origin, "link")
                    for k in query_keys(href):
                        if WORD_RE.match(k):
                            self.add_field(k, "query", origin)
            elif name in CONTROL_TAGS:
                nm = (attrs.get("name") or "").strip()
                if nm and WORD_RE.match(nm):
                    control = name
                    if name == "input":
                        control = "input:" + (attrs.get("type") or "?").lower()
                    self.add_field(nm, control, origin)
                    if cur_form is not None:
                        cur_form["fields"].append(
                            {"name": nm, "control": control})
            # every data-* attribute value — embedded UI frameworks
            # carry their field names there (data-key/data-field/...)
            for k, v in attrs.items():
                if k.startswith("data-") and v and WORD_RE.match(v):
                    self.add_data_attr(v, k, origin)
        if cur_form is not None:
            self.forms.append(cur_form)

    def scan_file(self, path, rel, ext, max_bytes):
        try:
            if os.path.getsize(path) > max_bytes:
                self.scan["too_large"] += 1
                return
            with open(path, "rb") as f:
                head = f.read(8192)
                if b"\x00" in head:
                    self.scan["skipped_binary"] += 1
                    return
                data = head + f.read()
        except OSError:
            self.scan["read_errors"] += 1
            return
        text = data.decode("utf-8", "replace")
        self.scan["bytes"] += len(data)
        try:
            if ext in MARKUP_EXTS:
                self.scan["markup_files"] += 1
                self.scan_markup(text, rel, 0)
            else:
                self.scan["script_files"] += 1
                self.scan_js(text, rel)
        except RecursionError:
            # pathologically nested input: one file must not kill the
            # model run — reported, honest, skipped
            self.scan["scan_errors"] += 1
        if SET_COOKIE_RE.search(text):
            self._sc_files.add(rel)
            self.cookies["set_cookie_literal"]["n_files"] = len(self._sc_files)

    # ---- finalize -------------------------------------------------------
    def finalize(self):
        for key, fs in self._ep_files.items():
            self.endpoints[key]["origins"] = sorted(fs)[:MAX_ORIGIN]
        for key, fs in self._fd_files.items():
            self.fields[key]["origins"] = sorted(fs)[:MAX_ORIGIN]
        for key, fs in self._jsk_files.items():
            self.js_keys[key]["origins"] = sorted(fs)[:MAX_ORIGIN]
        for key, fs in self._dat_files.items():
            self.data_attrs[key]["origins"] = sorted(fs)[:MAX_ORIGIN]
        for key, fs in self._cookie_files.items():
            self.cookies["names"][key]["origins"] = sorted(fs)[:MAX_ORIGIN]
        self.cookies["document_cookie"]["origins"] = sorted(
            self._dc_files)[:MAX_ORIGIN]
        self.cookies["set_cookie_literal"]["origins"] = sorted(
            self._sc_files)[:MAX_ORIGIN]
        return {
            "tool": "frontend-surface",
            "endpoints": {k: self.endpoints[k]
                          for k in sorted(self.endpoints)},
            "fields": {k: self.fields[k] for k in sorted(self.fields)},
            "js_keys": {k: self.js_keys[k] for k in sorted(self.js_keys)},
            "data_attrs": {k: self.data_attrs[k]
                           for k in sorted(self.data_attrs)},
            "cookies": {
                "document_cookie": self.cookies["document_cookie"],
                "set_cookie_literal": self.cookies["set_cookie_literal"],
                "names": {k: self.cookies["names"][k]
                          for k in sorted(self.cookies["names"])},
            },
            "forms": self.forms,
            "template_blocks": self.template_blocks,
            "scan": dict(sorted(self.scan.items())),
        }


def main():
    ap = argparse.ArgumentParser(
        description="client-side request-surface extractor (dumb, judgment-free)")
    ap.add_argument("--out", help="output JSON path (default: "
                    "<model>/taint-work/frontend-surface.json)")
    ap.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024,
                    help="skip files larger than this (default 8MB)")
    ap.add_argument("rootfs", help="the model's rootfs directory")
    args = ap.parse_args()

    rootfs = os.path.realpath(args.rootfs)
    if not os.path.isdir(rootfs):
        print("[-] not a directory: %s" % args.rootfs, file=sys.stderr)
        return 1

    model = ""
    d = os.path.dirname(rootfs)
    while d != "/":
        if os.path.isfile(os.path.join(d, "task.json")):
            model = d
            break
        d = os.path.dirname(d)
    out = args.out
    if not out:
        if not model:
            print("[-] no task.json ancestor found -- --out is required",
                  file=sys.stderr)
            return 1
        out = os.path.join(model, "taint-work", "frontend-surface.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)

    surf = Surface()
    for dirpath, dirnames, filenames in os.walk(rootfs):
        dirnames.sort()
        for fn in sorted(filenames):
            ext = os.path.splitext(fn)[1].lower()
            if ext not in MARKUP_EXTS and ext not in SCRIPT_EXTS:
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, rootfs).replace(os.sep, "/")
            surf.scan_file(p, rel, ext, args.max_bytes)

    doc = surf.finalize()
    doc = {"tool": doc["tool"], "rootfs": rootfs, **doc}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write("\n")

    print("frontend-surface: markup=%d script=%d endpoints=%d fields=%d "
          "js_keys=%d data_attrs=%d forms=%d template_blocks=%d "
          "cookie_names=%d -> %s"
          % (doc["scan"].get("markup_files", 0),
             doc["scan"].get("script_files", 0), len(doc["endpoints"]),
             len(doc["fields"]), len(doc["js_keys"]),
             len(doc["data_attrs"]), len(doc["forms"]),
             len(doc["template_blocks"]), len(doc["cookies"]["names"]), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
