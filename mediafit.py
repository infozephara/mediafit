import re
d = open("/opt/rclone/rclone-filestore", "rb").read()

print("### package.service identifiers")
for m in sorted(set(re.findall(rb"anthropic\.filestore\.v1alpha\.[A-Za-z_]{2,}", d))):
    print("  ", m.decode())

print("### *Filestore* tokens")
for m in sorted(set(re.findall(rb"[A-Za-z_./]*Filestore[A-Za-z_./]*", d)))[:40]:
    print("  ", m.decode())

print("### path-like literals")
seen = set()
for m in re.finditer(rb"/[A-Za-z0-9_./{}:%-]{4,70}", d):
    s = m.group().decode()
    if any(k in s for k in ("fs", "v1", "Filestore", "file", "connect", "directory")) and s not in seen:
        seen.add(s); print("  ", s)
    if len(seen) > 60: break

print("### procedure names (RPC methods)")
for m in sorted(set(re.findall(rb"\b(Read|List|Create|Move|Copy|Remove|Import|Get|Reassign|Write)[A-Za-z]{3,30}\b", d)))[:50]:
    print("  ", m.decode())