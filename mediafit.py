#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""egress4.py -- NUL SNI differential using bytes server_hostname (no IDNA)."""
import os, ssl, socket

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IP = "160.79.104.10"
CTX = ssl._create_unverified_context()
CTX.check_hostname = False
R = []
def rec(s): R.append(str(s)); print("[e]", s, flush=True)

def hit(sni: bytes, tmo=7):
    """TLS with raw-bytes SNI, then GET /. Returns (status, cn, body_marker)."""
    try:
        raw = socket.create_connection((IP, 443), timeout=tmo)
    except Exception as e:
        return "CONN_ERR:%s" % e, "-", "-"
    try:
        with CTX.wrap_socket(raw, server_hostname=sni) as ss:
            c = ss.getpeercert() or {}
            cn = dict(x[0] for x in c.get("subject", ())).get("commonName", "-")
            ss.sendall(b"GET / HTTP/1.1\r\nHost: " + sni.split(b"\x00")[0] +
                       b"\r\nUser-Agent: mf\r\nConnection: close\r\n\r\n")
            data = b""
            for _ in range(4):
                try: d = ss.recv(2048)
                except socket.timeout: break
                if not d: break
                data += d
                if len(data) > 4000: break
            st = data.split(b"\r\n")[0].decode("latin1", "replace") if data else "EMPTY"
            low = data.lower()
            mark = ("EXAMPLE_DOMAIN" if b"example domain" in low else
                    "GITHUB" if b"github" in low else
                    "CLAUDE" if b"claude" in low else
                    "ANTHROPIC" if b"anthropic" in low else "?")
            return st, cn, mark
    except Exception as e:
        return "TLS_ERR:%s" % e, "-", "-"
    finally:
        try: raw.close()
        except Exception: pass

rec("=== CONTROLS ===")
for c in (b"github.com", b"example.com", b"claude.ai"):
    st, cn, mk = hit(c)
    rec("CTL %-12s => %s cn=%s body=%s" % (c.decode(), st, cn, mk))

rec("=== NUL VARIANTS ===")
cases = [
    (b"example.com\x00github.com", "denied+allowed"),
    (b"github.com\x00example.com", "allowed+denied"),
    (b"claude.ai\x00github.com", "claude.ai+allowed"),
    (b"example.com\x00pypi.org", "denied+pypi"),
    (b"example.com\x00registry.npmjs.org", "denied+npm"),
    (b"example.com\x00github.com\x00pypi.org", "double"),
    (b"example.com\x00", "trailing_nul"),
    (b"\x00github.com", "leading_nul"),
]
for sni, label in cases:
    st, cn, mk = hit(sni)
    rec("NUL %-26s => %s cn=%s body=%s" % (label, st, cn, mk))

rec("=== TRAILING DOT / CASE ===")
for sni, label in ((b"example.com.", "dot"), (b"GITHUB.COM", "upper"),
                   (b"github.com.", "dot_allowed")):
    st, cn, mk = hit(sni)
    rec("ALT %-12s => %s cn=%s body=%s" % (label, st, cn, mk))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)