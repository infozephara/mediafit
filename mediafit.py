#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""egressmap.py -- map the egress gateway: proxy port, policy, MITM, bypasses."""
import os, ssl, socket, subprocess, http.client as hc

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
R = []
def rec(s): R.append(str(s)); print("[g]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read().strip()
    except Exception: return d
def sh(c, t=8):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or "")).strip()
    except Exception as e: return "ERR:%s" % e

rec("=== NETFILTER (the policy itself) ===")
for c in ("iptables -t nat -S", "iptables -S", "nft list ruleset"):
    out = sh(c)
    if out and not out.startswith("ERR"): rec("%s => %s" % (c, out[:900].replace("\n", " | ")))

rec("=== LISTENERS ===")
for f in ("/proc/net/tcp", "/proc/net/tcp6"):
    for line in rdo(f).splitlines()[1:]:
        p = line.split()
        if len(p) > 3 and p[3] == "0A":
            ip, port = p[1].split(":")
            rec("LISTEN %s port=%d" % (f, int(port, 16)))

rec("=== RESOLV/HOSTS ===")
rec("RESOLV=%s" % rdo("/etc/resolv.conf", "-").replace("\n", " | ")[:300])
rec("HOSTS=%s" % rdo("/etc/hosts", "-").replace("\n", " | ")[:300])

rec("=== CA IDENTITIES ===")
for c in ("/etc/ssl/certs/swp-ca-production.pem", "/etc/ssl/certs/egress-gateway-ca-production.pem"):
    rec("%s => %s" % (os.path.basename(c), sh("openssl x509 -in %s -noout -subject -issuer" % c)[:200]))

rec("=== MITM CHECK (who signs example.com?) ===")
def peer_issuer(host, sni=None, tmo=6):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=tmo) as s:
            with ctx.wrap_socket(s, server_hostname=sni or host) as ss:
                der = ss.getpeercert()
                return "subject=%s issuer=%s" % (dict(x[0] for x in der.get("subject", ())),
                                                 dict(x[0] for x in der.get("issuer", ())))
    except Exception as e: return "ERR:%s" % e
rec("example.com => %s" % peer_issuer("example.com"))
rec("api.anthropic.com => %s" % peer_issuer("api.anthropic.com"))

rec("=== EGRESS REACHABILITY ===")
def tcp(host, port, tmo=4):
    try:
        s = socket.create_connection((host, port), timeout=tmo); s.close(); return "OPEN"
    except Exception as e: return "ERR:%s" % e
for h, p in (("1.1.1.1", 443), ("8.8.8.8", 53), ("example.com", 443),
             ("example.com", 80), ("1.1.1.1", 80), ("9.9.9.9", 853)):
    rec("TCP %s:%d => %s" % (h, p, tcp(h, p)))
try:
    rec("DNS random => %s" % socket.gethostbyname("q7z3x1k9.example.com"))
except Exception as e: rec("DNS random => ERR:%s" % e)

rec("=== SNI / IP-LITERAL BYPASS VARIANTS ===")
for label, sni in (("nul_suffix", "attacker.example\x00.api.anthropic.com"),
                   ("zone_id", "api.anthropic.com%eth0"),
                   ("upper", "API.ANTHROPIC.COM"),
                   ("dot_suffix", "api.anthropic.com.")):
    rec("SNI %s => %s" % (label, peer_issuer("api.anthropic.com", sni)))

rec("=== IP-LITERAL FORMS (canonicalization) ===")
for form in ("127.1", "0x7f000001", "0177.0.0.1", "2130706433"):
    try: rec("IP %s => %s" % (form, socket.inet_aton(form).hex() if "." in form else "n/a"))
    except Exception as e: rec("IP %s => ERR:%s" % (form, e))
for form in ("127.1", "0x7f000001", "2130706433"):
    rec("CONN %s:2024 => %s" % (form, tcp(form, 2024)))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)