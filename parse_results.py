import re
import sys

names = [l.strip().split("/")[-1][:-3] for l in open(sys.argv[1])]
content = open(sys.argv[2], errors="replace").read()
content = re.sub(r"\x1b\[[0-9;]*m", "", content)

blocks = []
for m in re.finditer(
    r"Ran (\d+) tests? in [\d.]+s\s*\n\s*\n(OK(?: \([^)]*\))?|FAILED \([^)]*\))",
    content,
):
    blocks.append((m.start(), m.group(1), m.group(2)))

print(f"found {len(blocks)} result blocks for {len(names)} modules")
for i, (pos, ran, res) in enumerate(blocks):
    label = names[i] if i < len(names) else "?"
    print(f"{label}: ran={ran} {res}")
