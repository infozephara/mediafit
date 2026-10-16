import re
d = open("/opt/rclone/rclone-filestore", "rb").read()

def ctx(lit, n=8):
    out = []
    for m in list(re.finditer(re.escape(lit), d))[:n]:
        i = m.start(); j = i
        while j > 0 and 0x20 <= d[j-1] < 0x7f: j -= 1
        k = i + len(lit)
        while k < len(d) and 0x20 <= d[k] < 0x7f: k += 1
        s = d[j:k].decode("utf-8", "replace")
        if len(s) < 220: out.append(s)
    return out

for lit in (b"/v1/fs", b"Bearer", b"Authorization", b"x-api-key", b"Filestore",
            b"filestore.v1alpha", b"application/", b"/v1/", b"filesystem_id", b"allowed_roots"):
    print("### " + lit.decode())
    for s in dict.fromkeys(ctx(lit, 6)):
        print("   " + s)