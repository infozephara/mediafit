import socket, struct, os

def varint(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, d): return varint((f << 3) | 2) + varint(len(d)) + d   # length-delimited
def vi(f, n): return varint((f << 3) | 0) + varint(n)             # varint
def fx64(f, v): return varint((f << 3) | 1) + struct.pack("<d", float(v))  # fixed64

# --- حمولة OTLP صحيحة (الأزمنة fixed64 كما يفرض البروتوكول) ---
av  = ld(1, b"probe")
kv  = ld(1, b"service.name") + ld(2, av)
res = ld(1, kv)
ndp = fx64(2, 1_000_000_000) + fx64(3, 2_000_000_000) + fx64(4, 1.0) + vi(8, 0)
gau = ld(1, ndp)
met = ld(1, b"probe.metric") + ld(2, b"probe") + ld(3, b"1") + ld(5, gau)
sm  = ld(2, met)
rm  = ld(1, res) + ld(2, sm)
full = ld(1, rm)

variants = {
    "full":     full,
    "empty_rm": ld(1, b""),
    "empty_sm": ld(1, ld(2, b"")),
}

AF = getattr(socket, "AF_VSOCK", 40)
def post(body):
    raw = ("POST /v1/metrics HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode() + body
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(5)
        s.connect((2, 5005)); s.sendall(raw)
        r = s.recv(800); s.close()
        return r.split(b"\r\n")[0].decode()
    except Exception as e: return type(e).__name__

lines = []
for name, body in variants.items():
    st = post(body)
    lines.append("%-10s (%3d bytes) -> %s" % (name, len(body), st))
    print(lines[-1])

out = "otlp probe\n" + "\n".join(lines)
for d in ("/mnt/user-data/outputs/otlp-report.txt", "/tmp/otlp-report.txt"):
    try:
        if os.path.isdir(os.path.dirname(d)):
            open(d, "w").write(out); print("[saved: %s]" % d); break
    except Exception: pass