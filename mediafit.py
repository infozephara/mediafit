#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""egress3.py -- NUL-byte SNI differential against the egress gateway + allowlist map."""
import os, socket, struct, ssl, re

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IP = "160.79.104.10"
R = []
def rec(s): R.append(str(s)); print("[e]", s, flush=True)

def client_hello(name: bytes) -> bytes:
    ext_data = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    ext = b"\x00\x00" + struct.pack("!H", len(ext_data)) + ext_data
    body = (b"\x03\x03" + os.urandom(32) + b"\x00"
            + struct.pack("!H", 10) + b"\x13\x01\x13\x02\xc0\x2f\xc0\x2b\x00\x9c"
            + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

def raw_probe(name: bytes, tmo=6):
    """returns (verdict, names_seen_in_certificate)"""
    try:
        s = socket.create_connection((IP, 443), timeout=tmo)
    except Exception as e:
        return "CONN_ERR:%s" % e, []
    try:
        s.sendall(client_hello(name))
        buf = b""
        for _ in range(6):
            try: d = s.recv(4096)
            except socket.timeout: break
            if not d: break
            buf += d
            if len(buf) > 6000: break
        if not buf: return "NO_RESPONSE", []
        if buf[0] == 0x15: return "ALERT(deny)", []
        if buf[0] == 0x16 and len(buf) > 5 and buf[5] == 0x02:
            names = sorted(set(re.findall(rb"[a-z0-9][a-z0-9\-\.]{3,40}\.(?:com|org|ai|net|io|dev)", buf)))
            return "SERVER_HELLO(accept)", [n.decode() for n in names][:6]
        return "OTHER:%02x" % buf[0], []
    except Exception as e:
        return "ERR:%s" % e, []
    finally:
        try: s.close()
        except Exception: pass

rec("=== CONTROL (plain SNI, no NUL) ===")
for ctl in (b"github.com", b"example.com"):
    v, n = raw_probe(ctl)
    rec("CTL %s => %s names=%s" % (ctl.decode(), v, n))

rec("=== NUL DIFFERENTIAL ===")
cases = [
    (b"example.com\x00github.com",  "denied\\x00allowed"),
    (b"github.com\x00example.com",  "allowed\\x00denied"),
    (b"example.com\x00.anthropic.com", "denied\\x00allowed_suffix"),
    (b"nonexistent-zz9.example\x00github.com", "bogus\\x00allowed"),
    (b"example.com\x00", "denied\\x00empty"),
]
for name, label in cases:
    v, n = raw_probe(name)
    rec("NUL %s => %s names=%s" % (label, v, n))

rec("=== ALLOWLIST MAP (normal TLS) ===")
ctx = ssl.create_default_context()
def reach(host):
    try:
        raw = socket.create_connection((IP, 443), timeout=6)
        with ctx.wrap_socket(raw, server_hostname=host) as ss:
            ss.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
            return ss.recv(80).decode("latin1", "replace").split("\r\n")[0]
    except Exception as e:
        return "ERR:%s" % e
for h in ("api.anthropic.com", "anthropic.com", "claude.ai", "www.anthropic.com",
          "github.com", "pypi.org", "registry.npmjs.org", "google.com",
          "example.com", "raw.githubusercontent.com"):
    rec("MAP %s => %s" % (h, reach(h)))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)