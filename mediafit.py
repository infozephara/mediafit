import socket, struct

def varint(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, d): return varint((f << 3) | 2) + varint(len(d)) + d
def vi(f, n): return varint((f << 3) | 0) + varint(n)
def fx64(f, v): return varint((f << 3) | 1) + struct.pack("<d", float(v))

av   = ld(1, b"probe")
kv   = ld(1, b"service.name") + ld(2, av)
res  = ld(1, kv)
ndp  = vi(3, 1_000_000_000) + fx64(4, 1.0)
gau  = ld(1, ndp)
met  = ld(1, b"probe.metric") + ld(2, b"probe") + ld(3, b"1") + ld(5, gau)
sm   = ld(2, met)
rm   = ld(1, res) + ld(2, sm)
req  = ld(1, rm)

AF = getattr(socket, "AF_VSOCK", 40)
def post(path, body, ctype="application/x-protobuf"):
    raw = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
           % (path, ctype, len(body))).encode() + body
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(5)
        s.connect((2, 5005)); s.sendall(raw)
        r = s.recv(800); s.close()
        return r.split(b"\r\n")[0].decode(), repr(r.split(b"\r\n\r\n", 1)[-1][:200])
    except Exception as e: return type(e).__name__, ""

print("payload bytes:", len(req))
print("POST /v1/metrics ->", post("/v1/metrics", req))