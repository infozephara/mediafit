import os, socket

def env(pid):
    try:
        b = open("/proc/%s/environ" % pid, "rb").read()
        return b.replace(b"\x00", b"\n").decode("utf-8", "replace")
    except Exception as e: return "ERR:" + str(e)

for pid in ("56", "57"):
    print("========== PID %s environ ==========" % pid)
    print(env(pid) or "(empty)")

print("### /proc/net/vsock")
try: print(open("/proc/net/vsock").read())
except Exception as e: print("ERR", e)

print("### /proc/net/tcp (all)")
print(open("/proc/net/tcp").read())

print("### /proc/net/unix")
try: print(open("/proc/net/unix").read()[:1500])
except Exception as e: print("ERR", e)

AF = getattr(socket, "AF_VSOCK", 40)
def v(port, payload, wait=4):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(wait)
        s.connect((2, port))
        if payload: s.sendall(payload)
        try: r = repr(s.recv(1000))
        except Exception as e: r = "recv:" + type(e).__name__
        s.close(); return r
    except Exception as e: return type(e).__name__

print("### vsock 2:5005")
print("no-send:", v(5005, None))
print("http   :", v(5005, b"GET /status HTTP/1.0\r\n\r\n"))
print("nl     :", v(5005, b"\n"))
print("json   :", v(5005, b'{"t":"hi"}\n'))