import socket
AF = getattr(socket, "AF_VSOCK", 40)
paths = ["/v1/telemetry","/telemetry","/events","/v1/events","/logs","/v1/logs",
 "/metrics","/v1/metrics","/otlp","/v1/traces","/traces","/ingest","/v1/ingest",
 "/api/ingest","/sandbox/telemetry","/sbx/telemetry","/telemetry/v1","/v1","/api",
 "/health","/healthz","/ready","/collect","/v1/collect","/report","/v1/report",
 "/stats","/v1/stats","/heartbeat","/v1/heartbeat","/ping","/v1/messages",
 "/sandbox/v1/telemetry","/v1/sandbox/telemetry","/telemetry/ingest","/ingest/v1"]
def post(path, body=b"{}"):
    raw = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" % (path, len(body))).encode() + body
    try:
        s = socket.socket(AF, socket.SOCK_STREAM); s.settimeout(3)
        s.connect((2, 5005)); s.sendall(raw)
        r = s.recv(500); s.close()
        return r.split(b"\r\n")[0].decode()
    except Exception as e: return type(e).__name__
for p in paths:
    st = post(p)
    print("%-30s %s" % (p, st))
    