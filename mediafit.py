import socket
AF = getattr(socket, "AF_VSOCK", 40)

def post(path, ctype, body=b"", extra=""):
    raw = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n%sConnection: close\r\n\r\n"
           % (path, ctype, len(body), extra)).encode() + body
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(4)
        s.connect((2, 5005)); s.sendall(raw)
        r = s.recv(800); s.close()
        return r.split(b"\r\n")[0].decode() + " | body=" + repr(r.split(b"\r\n\r\n", 1)[-1][:120])
    except Exception as e: return type(e).__name__

print("### content-type probe on /v1/metrics")
for ct in ("application/x-protobuf", "application/protobuf", "application/octet-stream",
           "application/json", "text/plain", "application/grpc"):
    print("%-30s -> %s" % (ct, post("/v1/metrics", ct)))

print("### empty protobuf body")
print("x-protobuf empty:", post("/v1/metrics", "application/x-protobuf"))

print("### other OTLP paths")
for p in ("/v1/logs", "/v1/traces"):
    print("%-14s -> %s" % (p, post(p, "application/x-protobuf")))

print("### GET on /v1/metrics")
try:
    s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(4)
    s.connect((2, 5005)); s.sendall(b"GET /v1/metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    print(s.recv(400)); s.close()
except Exception as e: print(type(e).__name__)