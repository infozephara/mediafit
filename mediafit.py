import os, socket

print("### processes (all /proc/*/comm)")
for p in sorted(os.listdir("/proc")):
    if p.isdigit():
        try:
            c = open("/proc/%s/comm" % p).read().strip()
            cmd = open("/proc/%s/cmdline" % p).read().replace("\x00", " ").strip()
            print("%5s %-18s %s" % (p, c, cmd[:110]))
        except Exception: pass

print("### vsock precise (cid:port -> errno)")
AF = getattr(socket, "AF_VSOCK", 40)
for cid in (0, 1, 2, 3, 4, 0xFFFFFFFF):
    for port in (2024, 2025, 5002, 1024):
        try:
            s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(2)
            s.connect((cid, port)); print("  OK  %s:%d" % (cid, port)); s.close()
        except Exception as e:
            print("  ERR %s:%d %s errno=%s" % (cid, port, type(e).__name__, getattr(e, "errno", None)))

print("### TCP 2025: no-send then read")
try:
    s = socket.create_connection(("127.0.0.1", 2025), 3); s.settimeout(4)
    try: print("  greeting:", repr(s.recv(500)))
    except Exception as e: print("  greeting:", type(e).__name__)
    s.close()
except Exception as e: print("  ", type(e).__name__)

print("### /proc/net/tcp full")
print(open("/proc/net/tcp").read())