import socket, base64, os, subprocess

def req(host, port, raw, wait=4):
    try:
        s = socket.create_connection((host, port), 3); s.settimeout(wait)
        s.sendall(raw)
        try: d = s.recv(2000)
        except Exception as e: d = ("recv:" + type(e).__name__).encode()
        s.close(); return repr(d[:900])
    except Exception as e: return type(e).__name__

# اكتشف عنواننا
ip = None
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.0.0.1", 1))
    ip = s.getsockname()[0]; s.close()
except Exception: pass
print("our ip:", ip)
print("fib_trie:")
print(subprocess.run("grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' /proc/net/fib_trie | sort -u", shell=True, capture_output=True, text=True).stdout)

hosts = [h for h in (ip, "192.168.2.1", "0.0.0.0") if h]

print("### HTTP /status via iface")
for h in hosts:
    for p in (2024, 2025):
        print("%s:%d -> %s" % (h, p, req(h, p, b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))

print("### WebSocket via iface")
k = base64.b64encode(os.urandom(16)).decode()
for h in hosts:
    ws = ("GET / HTTP/1.1\r\nHost: %s:2024\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (h, k)).encode()
    print("%s:2024 WS -> %s" % (h, req(h, 2024, ws)))
    