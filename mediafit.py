import socket, ssl
def https(path, method="GET", headers=None, body=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection(("api.anthropic.com", 443), 6)
        s = ctx.wrap_socket(s, server_hostname="api.anthropic.com")
        req = "%s %s HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n" % (method, path)
        for k, v in (headers or {}).items(): req += "%s: %s\r\n" % (k, v)
        if body is not None: req += "Content-Length: %d\r\n" % len(body)
        req += "\r\n"
        s.sendall(req.encode() + (body or b""))
        d = b""
        while True:
            try:
                c = s.recv(4096)
                if not c: break
                d += c
            except Exception: break
        s.close(); return d
    except Exception as e: return ("ERR:" + str(e)).encode()

h = {"anthropic-version": "2023-06-01"}
for p in ("/v1/models", "/v1/files", "/v1/messages", "/"):
    r = https(p, headers=h)
    print("GET %-14s -> %s" % (p, r[:250].decode("utf-8", "replace").replace("\r\n", " | ")))

print("### with empty x-api-key")
print(https("/v1/models", headers=dict(h, **{"x-api-key": ""}))[:200].decode("utf-8","replace"))