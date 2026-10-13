# tools

Dev scripts that keep the published CSVs in sync with the catalog in `main.cpp`.

`main.cpp` is the single source of truth. The CSVs are generated, never edited
by hand, so the PowerShell workflows (which read the CSVs) and the compiled exe
(which reads the embedded catalog) always agree.

## Scripts

| Script             | Reads      | Writes          | From                                                     |
| ------------------ | ---------- | --------------- | -------------------------------------------------------- |
| `gen_csv.py`       | `main.cpp` | `processes.csv` | the detection catalog                                    |
| `gen_baselines.py` | `main.cpp` | `baselines.csv` | `baselineSystem` + `baselineCommonApps` + pseudo names   |

## Usage

Run from the repo root (defaults assume `main.cpp` in the current directory):

```bash
python tools/gen_csv.py
python tools/gen_baselines.py
```

Regenerate both whenever you change the catalog or the baseline sets in
`main.cpp`, then commit the updated CSVs alongside the source change.

Requires Python 3 only (standard library). Output uses CRLF line endings.
