import socket, os
AF = getattr(socket, "AF_VSOCK", 40)

def v(port, raw, wait=4):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(wait)
        s.connect((2, port)); s.sendall(raw)
        try: r = s.recv(1500)
        except Exception as e: r = ("recv:" + type(e).__name__).encode()
        s.close(); return r
    except Exception as e: return type(e).__name__

tests = [
 b"POST /status HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
 b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
 b"POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
 b"POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
 b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
 b"HEAD /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
 b"OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
 b"POST /v1/ingest HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
]
for t in tests:
    print("%-40s -> %s" % (t.split(b"\r\n")[0].decode(), repr(v(5005, t))[:300]))

print("### unix socket")
p = "/run/sandbox-telemetry/ingest.sock"
print("exists:", os.path.exists(p))
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
    s.connect(p); s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    print("unix resp:", repr(s.recv(800))); s.close()
except Exception as e: print("unix:", type(e).__name__, e)