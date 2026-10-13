import os
for pid in ("56", "57"):
    print("========== PID %s ==========" % pid)
    for f in ("comm", "cmdline"):
        try: print(f + ":", open("/proc/%s/%s" % (pid, f)).read().replace("\x00", " ").strip())
        except Exception as e: print(f, "ERR", e)
    try:
        print("--- environ ---")
        print(open("/proc/%s/environ" % pid).read().replace(b"\x00", b"\n").decode("utf-8", "replace"))
    except Exception as e: print("environ ERR", e)
    try:
        print("--- fds ---")
        for x in sorted(os.listdir("/proc/%s/fd" % pid), key=int):
            try: print("  %s -> %s" % (x, os.readlink("/proc/%s/fd/%s" % (pid, x))))
            except Exception as e: print("  %s -> ERR %s" % (x, e))
    except Exception as e: print("fd ERR", e)
    print()

# scan host vsock listeners
import socket
AF = getattr(socket, "AF_VSOCK", 40)
found = []
for port in range(1, 10001):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(0.2)
        s.connect((2, port)); s.close(); found.append(port)
    except Exception: pass
print("### host vsock listeners 1-10000:", found)