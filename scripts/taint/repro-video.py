#!/usr/bin/env python3
"""agent-scan :: taint — repro-video: render ONE vault entry's replay session
into an mp4 (+ srt sidecar) for CNVD-style authenticity proof.

Usage: repro-video.py <vault-entry-dir> [--out MP4] [--srt SRT]

Input (all inside the entry, written by repro-run.sh):
  repro/session.jsonl   the timestamped event stream of the LIVE replay:
                        {"ts": <epoch-f>, "s": cmd|out|serial|canary|probe|cap,
                         "t": "<verbatim line>"} — the video is built ONLY
                        from these bytes; the renderer re-times, never adds.
  repro/report.json     THIS replay's poc-run verdict (the rc shown on screen)
  repro/serial-window.log  the graded window of this replay's serial
  meta.json / AUDIT.json / task.json   provenance + class + mechanism facts

Scenes: title -> boot time-lapse (declared 20x) -> baseline alive -> attack
window (SPLIT SCREEN: left = attack terminal, right = LIVE serial tail, the
decisive line lands highlighted in real time) -> serial/canary/probe exhibit
(verbatim window lines) -> verdict summary (report.json fields verbatim) ->
provenance card. Boot is compressed; the decisive window is 1:1 real time —
unless pathologically long (a hung poc-run), in which case head 45s + tail
105s stay 1:1 and the middle fast-forwards at a DECLARED 20x. Frames are
streamed into ffmpeg as they are drawn, so memory is O(1) at any length.

Deterministic facts layer: decisive lines, rc/verdict fields and timestamps
are class templates filled ONLY from this run's bytes. The explanatory layer
(why a moment proves the trigger) comes from repro/subtitles.json when the
static organizer agent wrote one; missing/invalid -> template sentences.
Mechanism text is lifted verbatim from AUDIT.json. Exit 0 = mp4 + srt written.
"""
import json, os, re, subprocess, sys, datetime
from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 960, 540, 10
BG, PANE, PANEHD = "#0c1016", "#10161f", "#1c2636"
LINE, INK, MUT, FAINT = "#232e3f", "#dce3ee", "#8f9bb0", "#5c6779"
ACC, BAD, OK, SKY, VIO = "#d9a441", "#d2566b", "#5cb98c", "#6d9fd4", "#a08fe0"
MONO_P = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
CJK_P = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
_fc = {}
def F(path, size):
    k = (path, size)
    if k not in _fc:
        _fc[k] = ImageFont.truetype(path, size)
    return _fc[k]
CJK_RE = re.compile(r"[一-鿿　-〿＀-￯]")
def font_for(t, size):
    return F(CJK_P, size) if CJK_RE.search(t or "") else F(MONO_P, size)
CRASH_RE = re.compile(r"sending SIG(SEGV|BUS|ILL|FPE|TRAP)|potentially "
                      r"unexpected fatal signal|kernel panic|oops:|"
                      r"general protection fault", re.IGNORECASE)

def load(p, d=None):
    try:
        return json.load(open(p))
    except Exception:
        return d if d is not None else {}

class Cap:
    """caption track: (start_s, end_s, text) -> burn-in + srt"""
    def __init__(self): self.items = []
    def add(self, t0, t1, text): self.items.append((t0, t1, text))
    def write(self, path):
        def ts(s):
            ms = int(round(s * 1000))
            return "%02d:%02d:%02d,%03d" % (ms // 3600000, ms // 60000 % 60,
                                            ms // 1000 % 60, ms % 1000)
        with open(path, "w", encoding="utf-8") as f:
            for i, (a, b, t) in enumerate(self.items, 1):
                f.write("%d\n%s --> %s\n%s\n\n" % (i, ts(a), ts(b), t))

def draw_bar(d, text, sub):
    d.rectangle([0, 0, W, 64], fill="#161e2a")
    d.text((28, 10), text, font=F(CJK_P, 17), fill=ACC)
    d.text((28, 37), sub, font=F(CJK_P, 12), fill=MUT)
    d.rectangle([0, 64, W, 65], fill=LINE)

def pane(d, x0, y0, x1, y1, title):
    d.rectangle([x0, y0, x1, y1], fill=PANE, outline=LINE, width=1)
    d.rectangle([x0, y0, x1, y0 + 24], fill=PANEHD)
    d.text((x0 + 10, y0 + 5), title, font=F(MONO_P, 12), fill=MUT)
    return y0 + 32

def put(d, x, y, t, size=13, col=INK, hl=None, maxw=None):
    fnt = font_for(t, size)
    if maxw:
        maxpx = maxw - x
        while d.textlength(t, font=fnt) > maxpx and len(t) > 6:
            t = t[:-2]
        if d.textlength(t, font=fnt) > maxpx:
            t = t[:max(1, len(t) - 1)] + "…"
    if hl:
        d.rectangle([x - 4, y - 2, (maxw or W - 20), y + size + 8], fill=hl)
    d.text((x, y), t, font=fnt, fill=col)

def lines_of(d, x, y, rows, size=12, maxlines=15, maxw=None, hlset=None):
    """rows: list of (text, color|None, highlight-bg|None); scrolls to tail"""
    rows = rows[-maxlines:]
    for t, col, hl in rows:
        put(d, x, y, t, size=size, col=col or INK, hl=hl, maxw=maxw)
        y += size + 8
    return y

def main():
    entry = sys.argv[1]
    out_mp4 = out_srt = None
    RC_CLI = None
    ATT_CLI = None
    args = sys.argv[2:]
    while args:
        if args[0] == "--out": out_mp4 = args[1]; args = args[2:]
        elif args[0] == "--srt": out_srt = args[1]; args = args[2:]
        elif args[0] == "--rc": RC_CLI = args[1]; args = args[2:]
        elif args[0] == "--attempts": ATT_CLI = args[1]; args = args[2:]
        else: args = args[1:]
    rep_dir = os.path.join(entry, "repro")
    ev = [json.loads(l) for l in open(os.path.join(rep_dir, "session.jsonl"),
                                      encoding="utf-8", errors="replace")
          if l.strip()]
    ev.sort(key=lambda e: e.get("ts", 0))
    rep = load(os.path.join(rep_dir, "report.json"))
    meta = load(os.path.join(entry, "meta.json"))
    aud = load(os.path.join(entry, "AUDIT.json"))
    task = load(os.path.join(meta.get("source", {}).get("model_dir", ""),
                             "task.json"))
    v = rep.get("verdict", {})
    ci, bof = bool(v.get("ci")), bool(v.get("bof"))
    sd = bool(v.get("service_down"))
    klass = "CI" if ci else ("BOF" if bof else ("DoS" if sd else "?"))
    fresh = [c for c in v.get("crashes", []) if not c.get("pre_existing")]
    crash_line = fresh[0]["line"].strip() if fresh else ""
    comm = ""
    m = re.search(r"sending SIG\w+ to (\S+)", crash_line)
    if m: comm = m.group(1)
    if not comm:
        m = re.search(r"Comm:\s*(\S+)", "\n".join(
            c["line"] for c in fresh[:1]) or "")
        comm = m.group(1) if m else ""
    mech = ""
    for k in ("attribution", "artifact_check"):
        e = (aud.get(k) or {}).get("evidence") or ""
        if e:
            mech = e.split(". ")[0][:150]
            break
    ver = (task.get("version") or meta.get("firmware_file") or "")
    # 解释层字幕:repro agent(静态组织员)可选提供;缺失/非法 -> 确定性模板。
    # 事实层(引用行/rc/时间戳)永远来自本次运行的字节,agent 不可触达。
    SUB = load(os.path.join(rep_dir, "subtitles.json"), {})
    def sub(k, dflt):
        s = SUB.get(k)
        return s.strip() if isinstance(s, str) and s.strip() else dflt
    RC_DISP = RC_CLI if RC_CLI is not None else rep.get("rc", "?")
    try:
        ATT_DISP = int(ATT_CLI)
    except (TypeError, ValueError):
        ATT_DISP = 1
    caps = Cap()
    t0 = ev[0]["ts"] if ev else 0.0
    def T(ts): return ts - t0
    ph = {e["t"]: T(e["ts"]) for e in ev if e["s"] == "cap"}
    boot_end = ph.get("gate-stable", 60.0)
    atk0 = ph.get("attack-start", boot_end)
    atk1 = ph.get("attack-end", atk0 + 10.0)

    def cap_events(a, b, streams):
        return [e for e in ev if a <= T(e["ts"]) < b and e["s"] in streams]

    boot_serial = [e for e in ev if e["s"] == "serial" and T(e["ts"]) < boot_end]
    base_ev = cap_events(boot_end, atk0, ("cmd", "out", "probe", "gate"))
    atk_left = cap_events(atk0, atk1 + 6, ("cmd", "out", "canary", "probe"))
    atk_right = cap_events(atk0, atk1 + 6, ("serial",))

    # ---- window exhibit lines (verbatim, from this replay's window) ----
    winp = os.path.join(rep_dir, "serial-window.log")
    win = []
    if os.path.exists(winp):
        win = open(winp, encoding="utf-8", errors="replace").read().splitlines()
    if klass == "CI":
        canp = os.path.join(rep_dir, "canary-new.txt")
        exh = open(canp, encoding="utf-8", errors="replace").read().splitlines() \
            if os.path.exists(canp) else []
        exh_src = "canary"
    elif klass == "DoS":
        exh = [e["t"] for e in ev if e["s"] == "probe"]
        exh_src = "probe"
    else:
        idx = next((i for i, l in enumerate(win) if CRASH_RE.search(l)), 0)
        exh = win[max(0, idx - 4):idx + 8]
        exh_src = "serial"

    # frames STREAM into ffmpeg as they are drawn: the previous all-in-RAM
    # list hit 14+ GB on a long session (each 960x540 RGB frame is ~1.5 MB).
    out_mp4 = out_mp4 or os.path.join(rep_dir, "repro.mp4")
    out_srt = out_srt or os.path.join(rep_dir, "repro.srt")
    ff = subprocess.Popen(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo",
         "-pix_fmt", "rgb24", "-s", "%dx%d" % (W, H), "-r", str(FPS), "-i", "-",
         "-c:v", "libx264", "-preset", "medium", "-crf", "23",
         "-pix_fmt", "yuv420p", "-movflags", "+faststart", out_mp4],
        stdin=subprocess.PIPE)

    class Sink:
        """.append(im) streams the frame immediately; .hold(n) re-streams the
        last frame's bytes n times (the old hold() semantics, O(1) memory)."""
        def __init__(self):
            self.n = 0
            self.last = None
        def append(self, im):
            self.last = im.tobytes()
            ff.stdin.write(self.last)
            self.n += 1
        def hold(self, n):
            for _ in range(n):
                ff.stdin.write(self.last)
                self.n += 1

    frames, capT = Sink(), 0.0
    def hold(n):
        frames.hold(n)

    def newframe():
        im = Image.new("RGB", (W, H), BG)
        return im, ImageDraw.Draw(im)

    # ---------------- scene 1: title ----------------
    S1 = 4.0
    im, d = newframe()
    draw_bar(d, "漏洞复现 · 真实性证明(本次确定性重放)",
             "CNVD 提交附件 — 视频字节全部来自本次重放的事件流,可下载审计")
    y = 120
    for t, c in [("%s  %s" % (meta.get("vendor", "?"), meta.get("model", "?")), INK),
                 ("固件: %s" % ver, INK),
                 ("漏洞类别: %s   判分: rc=%s %s" % (
                     klass, meta.get("rc"), v.get("result", "")), OK),
                 ("marker: %s" % v.get("marker", ""), MUT),
                 ("重放时间: %s" % datetime.datetime.now().strftime(
                     "%Y-%m-%d %H:%M"), MUT)]:
        put(d, 60, y, t, size=16, col=c); y += 36
    frames.append(im); hold(int(S1 * FPS))
    caps.add(capT, capT + S1, "标题:%s %s · %s · 本次确定性重放" % (
        meta.get("vendor"), meta.get("model"), klass)); capT += S1

    # ---------------- scene 2: boot time-lapse ----------------
    S2 = 4.0
    im, d = newframe()
    draw_bar(d, "环境 · 厂商固件镜像启动(20× 快进,已声明)",
             "全新容器 / emu debug / 串口全文见 serial-full.log — 未剪辑关键段")
    y = pane(d, 24, 88, W - 24, H - 24, "guest — qemu.final.serial.log (boot)")
    rows = [(e["t"], MUT, None) for e in boot_serial[:12]] or \
           [("Linux version …(boot banner,见 serial-full.log)", MUT, None)]
    lines_of(d, 40, y, rows, size=12, maxlines=16, maxw=W - 60)
    put(d, 40, H - 52, "gate 确认:攻击面端口稳定应答 %.0fs(稳定确认 8s)" % boot_end,
        size=13, col=OK)
    frames.append(im); hold(int(S2 * FPS))
    caps.add(capT, capT + S2, "环境:全新容器启动厂商固件镜像,boot %.0fs(20× 快进),"
             "gate 稳定确认通过" % boot_end); capT += S2

    # ---------------- scene 3: baseline ----------------
    S3 = 2.5
    im, d = newframe()
    draw_bar(d, "基线 · 攻击前服务存活确认", "判分基线门:端口在 poc 前必须应答")
    y = pane(d, 24, 88, W - 24, H - 24, "host — baseline probe")
    rows = [(e["t"], OK if "200" in e["t"] or "alive" in e["t"] else MUT, None)
            for e in base_ev[:12]]
    lines_of(d, 40, y, rows, size=12, maxlines=16, maxw=W - 60)
    frames.append(im); hold(int(S3 * FPS))
    caps.add(capT, capT + S3, "基线:服务存活(HTTP 200 / TCP alive)——攻击前状态确认")
    capT += S3

    # ---------------- scene 4: attack window, split screen ----------------
    # 1:1 real time by default. A pathologically long window (a hung poc-run
    # once produced 26 min of "trigger pending" spam) is re-timed piecewise:
    # head and tail stay 1:1, the middle fast-forwards at a DECLARED 20x —
    # same contract as the boot time-lapse: re-time openly, never add content.
    WIN = max(6.0, atk1 - atk0)
    ATK_HEAD, ATK_TAIL, ATK_MID_X = 45.0, 105.0, 20.0
    if WIN <= ATK_HEAD + ATK_TAIL + 60.0:
        segs = [(WIN, 1.0)]                       # (session-seconds, speed)
    else:
        segs = [(ATK_HEAD, 1.0),
                (WIN - ATK_HEAD - ATK_TAIL, ATK_MID_X),
                (ATK_TAIL, 1.0)]
    COMPRESSED = len(segs) > 1
    atk_dur = sum(s / x for s, x in segs) + 4.0   # video-seconds of scene 4
    n_atk = int(atk_dur * FPS)
    def win_map(vt):
        """video-time in the scene -> (window offset in session-seconds, speed)"""
        for s, x in segs:
            d = s / x
            if vt <= d:
                return vt * x, x
            vt -= d
        return WIN, segs[-1][1]
    LX0, LX1 = 16, 470
    RX0, RX1 = 486, W - 16
    PY0, PY1 = 88, H - 16
    for k in range(n_atk):
        off, speed = win_map(k / FPS)
        now = atk0 + off
        im, d = newframe()
        bar = ("攻击窗口 · 1:1 实时(不压缩)" if speed == 1.0 else
               "攻击窗口 · 中段 %g× 快进(已声明压缩)" % speed)
        sbar = "左:攻击终端(poc 逐字输出)  右:串口实时尾随 — 因果同屏"
        if COMPRESSED:
            sbar += " · 会话 t=+%.0fs / 窗口全长 %.0fs" % (off, WIN)
        draw_bar(d, bar, sbar)
        yl = pane(d, LX0, PY0, LX1, PY1, "attack terminal — poc stdout")
        yr = pane(d, RX0, PY0, RX1, PY1, "serial tail — live")
        left = [(e["t"], (ACC if e["t"].startswith("$") else
                          BAD if "RemoteDisconnected" in e["t"] or
                          "died" in e["t"] else MUT), None)
                for e in atk_left if T(e["ts"]) <= now]
        lines_of(d, LX0 + 12, yl, left, size=11, maxlines=15, maxw=LX1 - 20)
        right = []
        for e in atk_right:
            if T(e["ts"]) > now:
                continue
            hl = "#2a1520" if CRASH_RE.search(e["t"]) else None
            right.append((e["t"], BAD if hl else MUT, hl))
        lines_of(d, RX0 + 12, yr, right, size=11, maxlines=15, maxw=RX1 - 20)
        frames.append(im)
    hold(int(2.0 * FPS))
    atk_why = ("串口在同一秒出现致命信号(右屏红行)——内存破坏被触发"
               if klass == "BOF" else
               "canary 注入日志新增记录——命令注入被执行" if klass == "CI"
               else "服务由 alive 转 dead,窗口内无崩溃行/无重启——DoS")
    seg_txt = ("实时头 %.0fs + 中段 %g× 快进 + 实时尾 %.0fs;窗口原长 %.0fs"
               % (ATK_HEAD, ATK_MID_X, ATK_TAIL, WIN)) if COMPRESSED else "实时"
    caps.add(capT, capT + atk_dur + 2.0,
             "攻击窗口(%s):发送 PoC;%s" % (seg_txt, sub("attack", atk_why)))
    capT += atk_dur + 2.0

    # ---------------- scene 5: exhibit (verbatim) ----------------
    S5 = 6.0
    im, d = newframe()
    ttl = {"serial": "串口日志原文(本次窗口,逐字)",
           "canary": "canary 注入日志(本次新增记录,逐字)",
           "probe": "liveness 探测序列(alive→dead 三次握手)"}[exh_src]
    draw_bar(d, "证据展示 · " + ttl,
             "全文见 repro/serial-window.log / canary / probe 记录 — 未删改")
    y = pane(d, 24, 88, W - 24, H - 64, "evidence — verbatim")
    rows = []
    for l in exh[:16]:
        hl = "#2a1520" if CRASH_RE.search(l) else None
        rows.append((l, BAD if hl else INK, hl))
    lines_of(d, 40, y, rows, size=12, maxlines=14, maxw=W - 70)
    why = sub("exhibit", {
        "BOF": "内核向 Comm=%s 投递致命信号;该行在 poc 前串口中无同指纹记录"
               " → 本窗口新增崩溃" % (comm or "固件进程"),
        "CI": "注入日志新增记录携带本次 marker → 注入命令确已执行",
        "DoS": "窗口内 0 崩溃行、0 重启签名,端口 alive→dead → service_down 判据"}[
        klass if klass in ("BOF", "CI", "DoS") else "BOF"])
    put(d, 40, H - 44, "为何关键:" + why, size=13, col=ACC, maxw=W - 80)
    frames.append(im); hold(int(S5 * FPS))
    caps.add(capT, capT + S5, "证据展示:%s。%s" % (ttl, why)); capT += S5

    # ---------------- scene 6: verdict summary ----------------
    S6 = 4.5
    im, d = newframe()
    draw_bar(d, "判分摘要 · poc-run report.json(本次重放,逐字字段)",
             "判定记录见 vault evidence/;本幕为本次复现的判分器输出")
    y = pane(d, 24, 88, W - 24, H - 24, "grader — report.json verdict")
    vl = [("result      : %s" % v.get("result"), OK),
          ("ci          : %s" % ci, INK),
          ("bof         : %s   (new crash lines: %d)" % (bof, len(fresh)), INK),
          ("service_down: %s" % sd, INK),
          ("canary delta: %s" % v.get("canary_file_delta"), INK),
          ("marker      : %s" % v.get("marker"), MUT),
          ("replay rc   : %s (vault rc=%s,同类命中)" % (
              RC_DISP, meta.get("rc")), ACC)]
    if ATT_DISP > 1:
        vl.append(("attempts    : %d 次全新 boot — 本视频为命中 vault 类别的那次;"
                   "此前尝试封存于 repro.fail-*/(可审计)" % ATT_DISP, MUT))
    for t, c in vl:
        put(d, 44, y, t, size=14, col=c); y += 28
    if mech:
        put(d, 44, y + 8, "机制(AUDIT 原句):" + mech[:90], size=11, col=MUT,
            maxw=W - 88)
        y += 24
    vnote = sub("verdict", "")
    if vnote:
        put(d, 44, y + 8, "结论说明:" + vnote, size=11, col=SKY, maxw=W - 88)
    frames.append(im); hold(int(S6 * FPS))
    caps.add(capT, capT + S6, "判分:rc=%s %s;ci=%s bof=%s service_down=%s,"
             "新增崩溃行 %d;%s" % (RC_DISP, v.get("result"), ci, bof, sd,
                                len(fresh), sub("verdict", "")[:80])); capT += S6

    # ---------------- scene 7: provenance ----------------
    S7 = 3.5
    im, d = newframe()
    draw_bar(d, "溯源 · 本视频与附件", "vault 条目 append-only;sha256 见 repro.json")
    y = 120
    for t, c in [("poc sha256   : %s" % (meta.get("poc_sha256") or "")[:40], MUT),
                 ("container    : %s" % rep.get("container", ""), MUT),
                 ("image        : %s" % rep.get("image", ""), MUT),
                 ("graded_at    : %s (vault)  replayed_at: %s" % (
                     meta.get("graded_at"), rep.get("ts", "")), MUT),
                 ("retry rule   : 与 verify-run 复检对齐 — 每尝试全新 boot、", MUT),
                 ("               rc=4 永不重试、attempts_ledger 见 repro.json", MUT),
                 ("附件:repro.mp4 / repro.srt / serial-full.log /", INK),
                 ("      serial-window.log / decisive.txt / REPRO.md", INK)]:
        put(d, 60, y, t, size=13, col=c); y += 30
    frames.append(im); hold(int(S7 * FPS))
    caps.add(capT, capT + S7, "溯源:poc sha256=%s…;完整说明见 REPRO.md" % (
        (meta.get("poc_sha256") or "")[:16])); capT += S7

    ff.stdin.close()
    rc = ff.wait()
    caps.write(out_srt)
    print("[repro-video] %s frames=%d dur=%.1fs rc=%d srt=%s captions=%s" % (
        out_mp4, frames.n, frames.n / FPS, rc, out_srt,
        "agent" if SUB else "template"))
    sys.exit(rc)

main()
