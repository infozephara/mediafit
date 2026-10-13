import socket, subprocess, base64, os

def run(c):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip()
    except Exception as e: return "ERR:" + str(e)

print("### our netns")
print(run("ls -l /proc/self/ns/net"))
print("### listeners in OUR netns (/proc/net/tcp)")
print(run("cat /proc/net/tcp | awk '{print $2, $4}'"))
print("### pid1 net ns files")
for n in ("net", "mnt", "pid", "user"):
    print("  /proc/1/ns/%s -> %s" % (n, run("readlink /proc/1/ns/%s" % n)))

def req(host, port, raw, half=True, wait=4):
    try:
        s = socket.create_connection((host, port), 3); s.settimeout(wait)
        s.sendall(raw)
        if half:
            try: s.shutdown(socket.SHUT_WR)
            except Exception: pass
        try: d = s.recv(2000)
        except Exception as e: d = ("recv:" + type(e).__name__).encode()
        s.close(); return repr(d[:900])
    except Exception as e: return type(e).__name__

print("### 2025 half-close variants")
print("HTTP/1.1:", req("127.0.0.1", 2025, b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
print("HTTP/1.0:", req("127.0.0.1", 2025, b"GET /status HTTP/1.0\r\n\r\n"))
print("POST    :", req("127.0.0.1", 2025, b"POST /fs_sync HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))

print("### vsock 2:2024 with WebSocket handshake")
AF = getattr(socket, "AF_VSOCK", 40)
k = base64.b64encode(os.urandom(16)).decode()
ws = ("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
      "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % k).encode()
for port, payload in ((2024, ws), (2024, b"GET /status HTTP/1.0\r\n\r\n"), (2025, b"GET /status HTTP/1.0\r\n\r\n")):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(3)
        s.connect((2, port)); s.sendall(payload)
        try: r = repr(s.recv(900))
        except Exception as e: r = "recv:" + type(e).__name__
        s.close()
    except Exception as e: r = type(e).__name__
    print("vsock 2:%d -> %s" % (port, r))

print("### strace pid1")
print("strace:", run("command -v strace"))
print(run("timeout 3 strace -f -p 1 -e trace=network,read,write 2>&1 | head -25"))