#!/usr/bin/env python3
"""Regenerate baselines.csv from the baseline sets embedded in main.cpp.

Single source of truth = main.cpp. Parses the three std::unordered_set<string>
functions that the unknown/noteworthy filter uses to exclude noise:
    baselineSystem()     -> kind "system"
    baselineCommonApps() -> kind "app"
    pseudoKernelNames()  -> kind "pseudo"
Emits Process,Kind sorted by (Kind, Process), CRLF.

Usage (from repo root):
    python tools/gen_baselines.py               # main.cpp -> baselines.csv
    python tools/gen_baselines.py <src> <dst>   # explicit paths
"""
import re
import sys

src_path = sys.argv[1] if len(sys.argv) > 1 else "main.cpp"
dst_path = sys.argv[2] if len(sys.argv) > 2 else "baselines.csv"

src = open(src_path, encoding="utf-8").read()


def body_of(func):
    i = src.index(func)
    j = src.index("return", i)
    return src[i:j]


sets = [
    ("baselineSystem()", "system"),
    ("baselineCommonApps()", "app"),
    ("pseudoKernelNames()", "pseudo"),
]

rows = []
seen = set()
for func, kind in sets:
    for name in re.findall(r'"([^"]+)"', body_of(func)):
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append((key, kind))

if not rows:
    sys.exit("no baseline entries parsed from %s" % src_path)

for p, k in rows:
    if "," in p or '"' in p:
        sys.exit("field breaks CSV: %r" % (p,))

rows.sort(key=lambda r: (r[1], r[0]))

out = ["Process,Kind"] + ["%s,%s" % r for r in rows]
with open(dst_path, "w", newline="", encoding="utf-8") as fh:
    fh.write("\r\n".join(out) + "\r\n")

print("%s: %d entries (system=%d app=%d pseudo=%d)" % (
    dst_path, len(rows),
    sum(1 for _, k in rows if k == "system"),
    sum(1 for _, k in rows if k == "app"),
    sum(1 for _, k in rows if k == "pseudo"),
))
