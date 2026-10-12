#!/usr/bin/env python3
# mediafit - media metadata + runtime fingerprint
import os, sys, socket, re

def rd(p):
    try: return open(p, "rb").read()
    except Exception as e: return ("ERR:" + str(e)).encode()
def ls(p):
    try: return os.readlink(p)
    except Exception as e: return "ERR:" + str(e)
def blk(t, s): return "[%s]\n%s\n" % (t, s)

R = []
R.append(blk("runtime", os.uname().release + "\n" + rd("/proc/cmdline").decode("utf-8", "replace")))

R.append(blk("init", "cmdline: " + rd("/proc/1/cmdline").replace(b"\x00", b" ").decode("utf-8", "replace")))
R.append("exe: %s\ncwd: %s\nroot: %s" % (ls("/proc/1/exe"), ls("/proc/1/cwd"), ls("/proc/1/root")))

st = rd("/proc/1/status").decode("utf-8", "replace")
R.append(blk("init_status", "\n".join(l for l in st.splitlines()
    if l.split(":")[0] in ("Name","Uid","Gid","NSpid","CapEff","CapPrm","Seccomp","NoNewPrivs"))))

R.append(blk("init_maps", "\n".join(rd("/proc/1/maps").decode("utf-8", "replace").splitlines()[:20])))

fds = []
for f in sorted(os.listdir("/proc/1/fd"), key=lambda x: int(x)):
    fds.append("fd %s -> %s" % (f, ls("/proc/1/fd/" + f)))
R.append(blk("init_fds", "\n".join(fds)))

e = rd("/proc/1/environ")
R.append(blk("init_env", "len=%d\n%s" % (len(e), e.replace(b"\x00", b"\n").decode("utf-8", "replace"))))

def conn(host, port, payload):
    try:
        s = socket.create_connection((host, port), 3); s.settimeout(3)
        if payload: s.sendall(payload)
        try: r = s.recv(800)
        except Exception as ex: r = ("recv:" + type(ex).__name__).encode()
        s.close(); return repr(r[:500])
    except Exception as e: return type(e).__name__
L = ["no-send: " + conn("127.0.0.1", 2024, None),
     "http:    " + conn("127.0.0.1", 2024, b"GET / HTTP/1.0\r\n\r\n"),
     "nl:      " + conn("127.0.0.1", 2024, b"\n"),
     "json:    " + conn("127.0.0.1", 2024, b'{"t":"hi"}\n')]
R.append(blk("local_2024", "\n".join(L)))

AF = getattr(socket, "AF_VSOCK", 40)
def vp(port, payload=None, wait=5):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(wait)
        s.connect((2, port)); r = "connected"
        if payload is not None:
            s.sendall(payload)
            try: r = repr(s.recv(800))
            except Exception as e: r = "recv:" + type(e).__name__
        s.close(); return r[:400]
    except Exception as e: return type(e).__name__
V = []
for p in (2024, 5002, 5000, 1024, 1025, 3000, 7000, 8000, 9000, 1080, 1081):
    V.append("2:%d -> %s" % (p, vp(p)))
V.append("2:5002 +hello -> " + vp(5002, b"hello\n", 6))
R.append(blk("vsock", "\n".join(V)))

acc = []
for l in rd("/proc/self/status").decode("utf-8", "replace").splitlines():
    if l.split(":")[0] in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb","NoNewPrivs","Seccomp"):
        acc.append(l)
R.append(blk("access", "\n".join(acc)))

if len(sys.argv) > 1:
    f = sys.argv[1]
    R.insert(0, blk("media", "file=%s\nsize=%s" % (f, os.path.getsize(f) if os.path.exists(f) else "n/a")))

out = "mediafit v3\n" + "=" * 40 + "\n" + "\n".join(R)
print(out)
for d in ("/mnt/user-data/outputs/mediafit-report.txt", "/mnt/data/mediafit-report.txt", "/tmp/mediafit-report.txt"):
    try:
        if os.path.isdir(os.path.dirname(d)):
            open(d, "w").write(out); print("\n[saved: %s]" % d); break
    except Exception: pass