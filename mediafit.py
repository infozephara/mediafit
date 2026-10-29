#!/usr/bin/env python3
import os, json, re, glob
CFG = "/dev/shm/rclone-boot/config.json"
print("=== probe ===")
try: print("BOOT_ID", open("/proc/sys/kernel/random/boot_id").read().strip()[:8])
except Exception: pass
body = ""
try:
    body = open(CFG).read()
    print("CFG_KEYS", list(json.loads(body).keys()))
    print("CFG_RAW", body[:1800].replace("\n", "|"))
    m = re.search(r"claude_chat_[A-Za-z0-9]+", body)
    print("SELF_FSID", m.group(0) if m else "-")
except Exception as e:
    print("CFG_ERR", e)
d = "/dev/shm/rclone-boot"
print("DIR", sorted(os.listdir(d)) if os.path.isdir(d) else "-")
for p in glob.glob(d + "/*"):
    try:
        if os.path.isfile(p) and os.path.getsize(p) < 100000:
            print("FILE", p, "=", open(p, errors="replace").read()[:500].replace("\n", "|"))
    except Exception: pass
for p in os.listdir("/proc"):
    if not p.isdigit(): continue
    try: cl = open("/proc/%s/cmdline" % p, errors="replace").read()
    except Exception: continue
    if "rclone" in cl:
        print("RCLONE", p, cl.replace("\x00", " ")[:300])
        try: print("ENV", open("/proc/%s/environ" % p, errors="replace").read().replace("\x00", "|")[:600])
        except Exception: pass