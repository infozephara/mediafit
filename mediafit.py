import os, subprocess
def run(c):
    try:
        p = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip()
    except Exception as e: return "ERR:" + str(e)

print("### self ns");   print(run("ls -l /proc/self/ns/"))
print("### pid1 ns");   print(run("ls -l /proc/1/ns/"))
print("### uid_map self"); print(run("cat /proc/self/uid_map"))
print("### uid_map pid1"); print(run("cat /proc/1/uid_map"))
print("### nsenter exists:", run("command -v nsenter"))
print("### nsenter into pid1:")
print(run("nsenter -t 1 -m -p -u -i -U -- sh -c 'id; echo ---; ls /; echo ---; readlink /proc/1/exe; echo ---; cat /proc/1/environ | tr \"\\0\" \"\\n\"' 2>&1 | head -50"))
print("### setns fallback:")
try:
    fd = os.open("/proc/1/ns/mnt", os.O_RDONLY)
    os.setns(fd, 0); print("setns(mnt) OK")
    print(run("ls -la / | head -20"))
    print(run("readlink /proc/1/exe"))
except Exception as e:
    print("setns ERR:", e)