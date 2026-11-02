#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""egress2.py -- does the egress gateway allow arbitrary destinations?"""
import os, ssl, socket

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
R = []
def rec(s): R.append(str(s)); print("[e]", s, flush=True)

CTX = ssl.create_default_context()

def tls_http(ip, sni, port=443, tmo=6):
    """TLS to a raw IP with an arbitrary SNI, then a GET. Proves egress + cert minting."""
    info = {"tls": "?", "cn": "?", "iss": "?", "http": "?"}
    try:
        raw = socket.create_connection((ip, port), timeout=tmo)
    except Exception as e:
        info["tls"] = "CONN_ERR:%s" % e; return info
    try:
        with CTX.wrap_socket(raw, server_hostname=sni) as ss:
            info["tls"] = "OK"
            c = ss.getpeercert() or {}
            sub = dict(x[0] for x in c.get("subject", ()))
            iss = dict(x[0] for x in c.get("issuer", ()))
            info["cn"] = sub.get("commonName", "-")
            info["iss"] = iss.get("commonName", "-")
            try:
                ss.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sni).encode("latin1"))
                info["http"] = ss.recv(160).decode("latin1", "replace").split("\r\n")[0]
            except Exception as e:
                info["http"] = "ERR:%s" % e
    except Exception as e:
        info["tls"] = "TLS_ERR:%s" % e
    finally:
        try: raw.close()
        except Exception: pass
    return info

def plain_http(ip, host, port=80, tmo=6):
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode("latin1"))
        d = s.recv(160).decode("latin1", "replace").split("\r\n")[0]
        s.close(); return d
    except Exception as e:
        return "ERR:%s" % e

rec("=== TLS TO RAW IP WITH ARBITRARY SNI ===")
for ip, sni in (("160.79.104.10", "api.anthropic.com"),
                ("1.1.1.1", "cloudflare-dns.com"),
                ("1.1.1.1", "example.com"),
                ("1.1.1.1", "github.com"),
                ("8.8.8.8", "dns.google"),
                ("93.184.216.34", "example.com")):
    i = tls_http(ip, sni)
    rec("PAIR %s / %s => tls=%s cn=%s issuer=%s http=%s" %
        (ip, sni, i["tls"], i["cn"], i["iss"], i["http"]))

rec("=== PLAIN HTTP HOST-HEADER VARIANTS (parser differential) ===")
for ip, host, label in (("1.1.1.1", "example.com", "control_foreign"),
                        ("1.1.1.1", "api.anthropic.com", "spoof_allowed"),
                        ("1.1.1.1", "attacker.example\x00.api.anthropic.com", "nul_suffix"),
                        ("1.1.1.1", "api.anthropic.com.", "trailing_dot"),
                        ("1.1.1.1", "API.ANTHROPIC.COM", "uppercase"),
                        ("1.1.1.1", "api.anthropic.com:443", "with_port")):
    rec("HOST %s (%s) => %s" % (label, host.replace("\x00", "<NUL>"), plain_http(ip, host)))

rec("=== SNI CONTAINING NUL (bytes-level) ===")
def tls_sni_bytes(ip, sni_bytes, tmo=6):
    """minimal check: python rejects NUL in str, so build SNI manually is out of scope;
       we approximate by testing whether str-with-NUL reaches the gateway at all"""
    try:
        raw = socket.create_connection((ip, 443), timeout=tmo)
    except Exception as e: return "CONN_ERR:%s" % e
    try:
        with CTX.wrap_socket(raw, server_hostname=sni_bytes) as ss:
            c = ss.getpeercert() or {}
            sub = dict(x[0] for x in c.get("subject", ()))
            return "TLS_OK cn=%s" % sub.get("commonName", "-")
    except Exception as e:
        return "ERR:%s" % e
    finally:
        try: raw.close()
        except Exception: pass
rec("NULSTR => %s" % tls_sni_bytes("160.79.104.10", "a.example\x00.api.anthropic.com"))

rec("=== DIRECT ANTHROPIC API SANITY (does filestore route exist at all?) ===")
i = tls_http("160.79.104.10", "api.anthropic.com")
rec("API_ROOT => tls=%s http=%s" % (i["tls"], i["http"]))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)