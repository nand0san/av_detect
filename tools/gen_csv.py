#!/usr/bin/env python3
"""Regenerate processes.csv from the catalog embedded in main.cpp.

Single source of truth = main.cpp. Parses the catalog entries of the form
    {"image.exe", { {"ProductName","Type","TAG"} }},
and emits Process,ProductName,Tag,Type sorted by (Tag, Process), CRLF.

Usage (from repo root):
    python tools/gen_csv.py                 # main.cpp -> processes.csv
    python tools/gen_csv.py <src> <dst>     # explicit paths
"""
import re
import sys

src_path = sys.argv[1] if len(sys.argv) > 1 else "main.cpp"
dst_path = sys.argv[2] if len(sys.argv) > 2 else "processes.csv"

src = open(src_path, encoding="utf-8").read()

# Narrow to the catalog function to avoid picking up baselines.
body = src[src.index("catalog"):]

entry = re.compile(
    r'\{\s*"([A-Za-z0-9_.\-]+\.exe)"\s*,\s*\{\s*(\{.*?\})\s*\}\s*\}\s*,',
    re.DOTALL,
)
triple = re.compile(r'\{\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\}')

rows = []
for m in entry.finditer(body):
    exe = m.group(1)
    for name, typ, tag in triple.findall(m.group(2)):
        rows.append((exe, name, tag, typ))

if not rows:
    sys.exit("no catalog entries parsed from %s" % src_path)

# Flat CSV: reject any field that would break the schema.
for r in rows:
    for f in r:
        if "," in f or '"' in f:
            sys.exit("field contains comma or quote, would break CSV: %r" % (r,))

rows.sort(key=lambda r: (r[2], r[0], r[1]))

out = ["Process,ProductName,Tag,Type"] + [",".join(r) for r in rows]
with open(dst_path, "w", newline="", encoding="utf-8") as fh:
    fh.write("\r\n".join(out) + "\r\n")

print("%s: %d entries" % (dst_path, len(rows)))
