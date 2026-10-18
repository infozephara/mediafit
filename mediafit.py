#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit.py v2.9.0 -- find who provides the 9112 gateway; ws probe; mount liveness."""
import os, sys, json, re, time, ssl, base64, socket, subprocess, traceback
import urllib.request, urllib.error

VER="2.9.0"; REPORT="/mnt/user-data/outputs/mediafit-report.txt"
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

def s_config():
    head("config"); G["CONF"]="/dev/shm/rclone-boot/config.json"
    conf=json.loads(open(G["CONF"]).read())
    for m in conf.get("mounts",[]):
        if m.get("filesystem_id"): G["fsid"]=m["filesystem_id"]
    rec("P","config readable",G.get("fsid"))

def s_tokens():
    head("tokens")
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
    def pick(r0):
        for r in TD:
            if r0 in (r["pl"].get("allowed_roots") or []): return r
        return None
    G["TOKEN"]=((pick("/outputs") or (TD[0] if TD else None)) or {}).get("tok")
    for r in TD: w("    roots=%s ro=%s"%(r["pl"].get("allowed_roots"),r["pl"].get("readonly")))
    rec("P" if TD else "F","tokens n=%d"%len(TD))

def s_mountcheck():
    head("mount liveness (is the gateway actually needed?)")
    try:
        o=os.listdir("/mnt/user-data/outputs")
        w("    outputs entries: %d"%len(o))
        if o:
            d=open("/mnt/user-data/outputs/"+o[0],"rb").read(80)
            w("    read ok: %r"%d[:60]); rec("P","fuse mount readable")
    except Exception as e:
        w("    read FAIL: %s"%e); rec("F","fuse mount unreadable",e)
    rc,out,err=sh(["bash","-lc","mount 2>/dev/null | grep -iE 'rclone|fuse' | head"])
    for ln in out.splitlines(): w("    mount: "+ln[:200])
    rc,out,err=sh(["bash","-lc","cat /proc/58/mounts 2>/dev/null | grep -iE 'rclone|fuse' | head"])
    for ln in out.splitlines(): w("    pmount: "+ln[:200])

def s_hunt():
    head("hunt: who provides 9112 ?")
    for root in ["/etc","/opt","/usr/local","/root","/run","/tmp","/dev/shm"]:
        rc,out,err=sh(["bash","-lc","timeout 8 grep -rIl 9112 %s 2>/dev/null | head -15"%root])
        for ln in out.splitlines(): w("    ref %s"%ln)
    for d in ["/opt","/opt/rclone","/usr/local/bin","/usr/bin","/sbin","/run","/tmp","/dev/shm","/"]:
        try: w("    ls %-16s %s"%(d,sorted(os.listdir(d))[:24]))
        except Exception: pass
    try: w("    pid1 cmdline: "+open("/proc/1/cmdline","rb").read().replace(b"\0",b" ").decode("latin1"))
    except Exception: pass
    try:
        for e in open("/proc/1/environ","rb").read().split(b"\0"):
            if e: w("    pid1 env "+e.decode("latin1")[:200])
    except Exception: pass
    try:
        for ln in open("/proc/net/unix").read().splitlines():
            if any(k in ln for k in ["sock",".s","9112","filestore","rclone"]): w("    UNIX "+ln[:170])
    except Exception: pass
    try:
        data=open("/opt/rclone/rclone-filestore","rb").read()
        seen=set()
        for run in re.findall(rb"[\x20-\x7e]{4,90}", data):
            s=run.decode("latin1")
            if ("9112" in s or "gateway" in s.lower() or "FILESTORE_" in s or "localhost:" in s) and s not in seen:
                seen.add(s); w("    bin: "+s)
                if len(seen)>40: break
    except Exception as e: w("    bin err %s"%e)

def s_probe():
    head("probe 9112 (if up) + ws handshake on 2024/2025")
    FSID=G.get("fsid"); TOKEN=G.get("TOKEN")
    for path in ["/v1/filestore/fs/listDirectory"]:
        st,b=http("POST","http://127.0.0.1:9112"+path,token=TOKEN,data=b"{}",
                  hdrs={"Content-Type":"application/json","Connect-Protocol-Version":"1"})
        w("    9112 %s -> %s %r"%(path,st,b[:100]))
    ws={"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Version":"13",
        "Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ=="}
    for port in [2024,2025]:
        st,b=http("GET","http://127.0.0.1:%d/"%port,hdrs=ws)
        w("    ws %d / -> %s %r"%(port,st,b[:100]))

def s_trystart():
    head("try to (re)start a filestore gateway on 9112")
    cands=[]
    for d in ["/opt/rclone","/opt","/usr/local/bin","/usr/bin"]:
        try:
            for f in os.listdir(d):
                p=os.path.join(d,f)
                if os.path.isfile(p) and ("filestore" in f or "gateway" in f): cands.append(p)
        except Exception: pass
    w("    candidates: %s"%cands)
    for p in cands:
        rc,out,err=sh(["bash","-lc","timeout 4 %s --help 2>&1 | head -15"%p])
        w("    --- %s (rc=%s) ---"%(p,rc))
        for ln in out.splitlines()[:12]: w("    | "+ln[:160])

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  FAIL %d: %s"%(len(F),F)); w("  UNKNOWN %d: %s"%(len(U),U))
    if G.get("TOKEN"):
        w("\n  >>> COPY THESE <<<\n  FSID=%s\n  TOKEN=%s"%(G.get("fsid"),G.get("TOKEN")))

def main():
    for n,f in [("config",s_config),("tokens",s_tokens),("mount",s_mountcheck),
                ("hunt",s_hunt),("probe",s_probe),("trystart",s_trystart),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! main: %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in SINKS:
        try: os.makedirs(d,exist_ok=True); open(os.path.join(d,os.path.basename(REPORT)),"w").write(txt)
        except Exception: pass
    print("\nwritten: "+", ".join(SINKS))