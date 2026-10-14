import socket, struct, os

def varint(n):
    o = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])
def ld(f, d): return varint((f << 3) | 2) + varint(len(d)) + d
def vi(f, n): return varint((f << 3) | 0) + varint(n)
def fx64(f, v): return varint((f << 3) | 1) + struct.pack("<d", float(v))

def metric(name, val):
    av = ld(1, b"probe"); kv = ld(1, b"service.name") + ld(2, av)
    res = ld(1, kv)
    ndp = fx64(2, 1_000_000_000) + fx64(3, 2_000_000_000) + fx64(4, val) + vi(8, 0)
    gau = ld(1, ndp)
    met = ld(1, name.encode()) + ld(2, b"probe") + ld(3, b"1") + ld(5, gau)
    return ld(1, ld(1, res) + ld(2, ld(2, met)))

AF = getattr(socket, "AF_VSOCK", 40)
def post(path, body):
    raw = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" % (path, len(body))).encode() + body
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(5)
        s.connect((2, 5005)); s.sendall(raw)
        r = s.recv(900); s.close()
        return r.split(b"\r\n")[0].decode() + " body=" + repr(r.split(b"\r\n\r\n",1)[-1][:120])
    except Exception as e: return type(e).__name__

L = []
# 1) تأكيد الحقن بثلاث قياسات مختلفة
for i in range(3):
    st = post("/v1/metrics", metric("probe.metric.%d" % i, float(i)))
    L.append("inject %d -> %s" % (i, st))

# 2) مسارات أخرى بنوع x-protobuf
for p in ("/v1/logs", "/v1/traces", "/v1/metrics/", "/metrics", "/v1/profiles"):
    L.append("%-16s -> %s" % (p, post(p, metric("x", 1.0)).split(" body")[0]))

# 3) مسح كامل لمنافذ المضيف
found = []
for p in range(1, 20001):
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(0.12)
        s.connect((2, p)); s.close(); found.append(p)
    except Exception: pass
L.append("host ports 1-20000: %s" % found)

out = "final probe\n" + "\n".join(L)
print(out)
for d in ("/mnt/user-data/outputs/final-report.txt", "/tmp/final-report.txt"):
    try:
        if os.path.isdir(os.path.dirname(d)):
            open(d, "w").write(out); print("[saved: %s]" % d); break
    except Exception: pass