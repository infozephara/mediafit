import socket, base64, os
def req(port, raw, wait=4):
    try:
        s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(wait)
        s.sendall(raw)
        try: d = s.recv(2000)
        except Exception as e: d = ("recv:" + type(e).__name__).encode()
        s.close(); return repr(d[:900])
    except Exception as e: return type(e).__name__

print("### port 2025 (HTTP control API)")
print("GET /status :", req(2025, b"GET /status HTTP/1.0\r\n\r\n"))
print("GET /       :", req(2025, b"GET / HTTP/1.0\r\n\r\n"))
print("GET /status HTTP/1.1:", req(2025, b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))

print("### port 2024 (WebSocket handshake)")
k = base64.b64encode(os.urandom(16)).decode()
ws = ("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
      "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % k).encode()
print("WS 2024:", req(2024, ws))

print("### other ports")
for p in (2025, 2026, 2027, 3000, 3001, 8080, 8000, 5000):
    print("127.0.0.1:%d -> %s" % (p, req(p, b"GET / HTTP/1.0\r\n\r\n", 2)))

print("### vsock host")
AF = getattr(socket, "AF_VSOCK", 40)
def v(port, raw):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(3)
        s.connect((2, port)); s.sendall(raw)
        try: r = repr(s.recv(900))
        except Exception as e: r = "recv:" + type(e).__name__
        s.close(); return r
    except Exception as e: return type(e).__name__
for p in (2025, 2026, 5002):
    print("vsock 2:%d -> %s" % (p, v(p, b"GET /status HTTP/1.0\r\n\r\n")))