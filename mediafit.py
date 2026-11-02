#!/usr/bin/env python3
# egress5.py - raw TLS ClientHello SNI prober (NUL-capable) - silent, file-only
import os, socket, ssl, struct, sys, time, traceback

GW = "160.79.104.10"; PORT = 443; TIMEOUT = 8; CAP = 4000
OUT = "mediafit-report.txt"

_f = open(OUT, "w", encoding="utf-8")
def emit(s=""):
    _f.write(str(s) + "\n")
    _f.flush()

def u16(n): return struct.pack(">H", n)
def u24(n): return struct.pack(">I", n)[1:]
def ext(t, d): return u16(t) + u16(len(d)) + d

def build_ch(sni):
    sni_ext = ext(0x0000, u16(len(sni) + 3) + b"\x00" + u16(len(sni)) + sni)
    groups  = ext(0x000a, u16(4) + b"\x00\x1d\x00\x17")
    sigs    = ext(0x000d, u16(6) + b"\x04\x03\x08\x04\x04\x01")
    vers    = ext(0x002b, b"\x02\x03\x04\x03\x03")
    pfx     = ext(0x000b, b"\x01\x00")
    exts    = sni_ext + groups + sigs + vers + pfx
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + u16(14) + b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x30\x00\x9c\x00\x2f"
            + b"\x01\x00" + u16(len(exts)) + exts)
    hs = b"\x01" + u24(len(body)) + body
    return b"\x16\x03\x01" + u16(len(hs)) + hs

def read_all(s, first):
    buf = bytearray(first)
    while len(buf) < CAP:
        try: d = s.recv(65536)
        except socket.timeout: break
        except Exception: break
        if not d: break
        buf += d
    return bytes(buf)

def tls_get(s, first, sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception: pass
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=None)
    inb.write(first)
    for _ in range(64):
        try:
            obj.do_handshake(); break
        except ssl.SSLWantReadError:
            try: outb.read()
            except Exception: pass
            d = s.recv(65536)
            if not d: raise RuntimeError("eof_in_handshake")
            inb.write(d)
        except ssl.SSLWantWriteError:
            try: s.sendall(outb.read())
            except Exception: pass
    host = sni.split(b"\x00")[0] or b"x"
    obj.write(b"GET / HTTP/1.1\r\nHost: " + host +
              b"\r\nUser-Agent: egress5\r\nConnection: close\r\n\r\n")
    buf = b""
    for _ in range(200):
        try: d = outb.read()
        except Exception: d = b""
        if d:
            try: s.sendall(d)
            except Exception: break
        try:
            c = obj.read(65536)
            if c:
                buf += c
                if len(buf) > CAP: break
        except ssl.SSLWantReadError:
            try: raw = s.recv(65536)
            except socket.timeout: break
            except Exception: break
            if not raw: break
            inb.write(raw)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError): break
        except Exception: break
    return buf

def run(name, sni):
    t0 = time.time()
    emit("--- %s  sni=%r" % (name, sni))
    try:
        s = socket.create_connection((GW, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
    except Exception as e:
        emit("%-22s => CONNECT_FAIL %s" % (name, e)); emit(); return (name, "CONNECT_FAIL", "")
    try:
        s.sendall(build_ch(sni))
        first = s.recv(64)
    except Exception as e:
        emit("%-22s => SEND_FAIL %s" % (name, e)); emit(); return (name, "SEND_FAIL", "")
    if not first:
        emit("%-22s => EMPTY" % name); emit(); return (name, "EMPTY", "")
    mode = "TLS" if first[:1] == b"\x16" else "PLAIN"
    try:
        raw = tls_get(s, first, sni) if mode == "TLS" else read_all(s, first)
    except Exception as e:
        raw = b""
        emit("%-22s => %s ERR %r" % (name, mode, e))
    try: s.close()
    except Exception: pass

    head = raw.split(b"\r\n", 1)
    status = head[0].decode("latin1", "replace") if raw else "-"
    body = head[1].decode("latin1", "replace") if len(head) > 1 else ""
    emit("%-22s => mode=%s status=%s" % (name, mode, status))
    emit("   FIRST=%s" % raw[:16].hex())
    emit("   RAWHEX=%s" % raw[:220].hex())
    emit("   BODY=%s" % body[:400].replace("\r", "\\r").replace("\n", "\\n"))
    emit("   t=%.2fs" % (time.time() - t0))
    emit()
    return (name, status, body)

CASES = [
    ("CTL github",            b"github.com"),
    ("CTL example",           b"example.com"),
    ("CTL claude",            b"claude.ai"),
    ("SFX xgithub",           b"xgithub.com"),
    ("SFX github.evil",       b"github.com.evil.com"),
    ("SFX sub.github",        b"sub.github.com"),
    ("SFX github.dot",        b"github.com."),
    ("SFX pypi.dot",          b"pypi.org."),
    ("NUL allowed+denied",    b"github.com\x00example.com"),
    ("NUL denied+allowed",    b"example.com\x00github.com"),
    ("NUL claude+allowed",    b"claude.ai\x00github.com"),
    ("NUL allowed+claude",    b"github.com\x00claude.ai"),
    ("NUL allowed+trail",     b"github.com\x00"),
    ("NUL lead",              b"\x00github.com"),
    ("NUL double",            b"github.com\x00\x00example.com"),
    ("NUL space",             b"github.com\x00 "),
    ("NUL inside allowed",    b"git\x00hub.com"),
]

def main():
    emit("=== EGRESS5 raw-clienthello ===")
    emit("GW=%s:%d cases=%d time=%s" % (GW, PORT, len(CASES), time.strftime("%Y-%m-%d %H:%M:%S")))
    emit()
    res = []
    for name, sni in CASES:
        res.append(run(name, sni))
        time.sleep(0.15)
    emit("=== SUMMARY ===")
    ok200 = [n for n, st, _ in res if "200" in st]
    deny  = [n for n, st, _ in res if "403" in st]
    other = [(n, st) for n, st, _ in res if "200" not in st and "403" not in st]
    emit("ALLOWED(200)=%d %s" % (len(ok200), ok200))
    emit("DENIED(403)=%d %s" % (len(deny), deny))
    emit("OTHER=%s" % other)
    emit("VERDICT_BUILDER_OK=%s" % ("CTL github" in ok200 and "CTL example" in deny))
    emit()
    emit("OUT_FILE=%s" % os.path.abspath(OUT))

try:
    main()
except Exception:
    emit("=== UNCAUGHT ===")
    emit(traceback.format_exc())
finally:
    _f.close()