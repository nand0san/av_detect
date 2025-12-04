
# Security Software Detector (`av_detect`)

Detects whether security software (AV, EDR/XDR, firewall, VPN/ZTNA, DLP, telemetry, etc.) is running on a Windows endpoint by enumerating live processes and matching them against a curated catalog of known agent executables.

- **Version:** `v2.1.0`
- **Scope:** Image-name–based detection; **no admin required**; low-noise (does **not** request `SeDebugPrivilege`).
- **Use cases:** DFIR triage, Red Team reconnaissance, IT asset survey.

---

## What’s new in `v2.1.0`

- **Deterministic, parser-friendly output**
  - Leading **unknown** block (excludes Windows baseline and mainstream apps).
  - Separator line `---` for parsers.
  - Detections **sorted alphabetically** and prefixed with `[TAG]`.
- **Compact `cmd=`** (no outer quotes, normalized spaces, smart truncation).
- **Non-intrusive fallbacks**
  - `svc=`/`bin=` from SCM when `cmd=` is not available.
  - `img=` (full image path) when neither `cmd=` nor SCM data is available.
- **Expanded 2024–2025 catalog:** Falcon, SentinelOne, Cortex XDR, Elastic, Trend, McAfee/Trellix, Sophos, ESET, Zscaler, Fortinet, Tanium, Rapid7, Qualys, etc.
- **New tags:** `[CLOUD]`, `[CREDS]`, `[RDP]`, `[ZTNA]` in addition to `[AV]`, `[EDR]`, `[VPN]`, `[TEL]`, `[VIRT]`, `[FW]`, `[HIPS]`, `[VULN]`, `[NDR]`, `[AUDIO]`, `[OEM]`, `[DRM]`, `[USB]`, `[TB]`, `[NAS]`, `[INT]`, `[OTHER]`.

---

## Requirements

- **OS:** Windows 10/11 (x64 recommended).
- **Compiler:** C++17+ (MSVC, MinGW-w64 g++, clang-cl).
- **Headers:** Win32 SDK (`tlhelp32.h`, `winsvc.h`) provided by MSVC/MinGW-w64.

---

## Build

### MSVC (Developer Command Prompt)

```bat
cl /std:c++17 /O2 /W3 /EHsc av_detect.cpp /link /SUBSYSTEM:CONSOLE
````

### MinGW-w64 g++

```bash
g++ -std=c++17 -O2 -Wall -o av_detect.exe av_detect.cpp
```

### CMake (optional)

```cmake
cmake_minimum_required(VERSION 3.16)
project(av_detect CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(av_detect av_detect.cpp)
```

```bash
cmake -S . -B build
cmake --build build --config Release
```

> Note: 64-bit builds simplify future extensions (paths/PEB on WOW64).

---

## Usage

```powershell
.\av_detect.exe
```

**Sample output:**

```
AV_detect Version: v2.1.0

[unknown] Non-system unknown processes (24):
- ai.exe | cmd=C:\Program Files\Microsoft Office\root\...
- ...
---
[AV] Kaspersky UI - exe=avpui.exe
[CLOUD] Nextcloud Desktop - exe=nextcloud.exe
[EDR] Kaspersky AV / KES - exe=avp.exe
[RDP] Microsoft Remote Desktop Client - exe=mstsc.exe
[VPN] WireGuard - exe=wireguard.exe
...

Found security software process (AV, anti-malware, EDR, XDR, etc.) running.
```

* **Exit code:** always `0`; findings are reported via `stdout`.

---

## Output format (stable)

* **Unknown lines:**
  `- <exeLower>[ | cmd=<normalized> | svc=<name>(+N)[ | bin=<path>] | img=<fullpath>]`
* **Separator:** `---`
* **Detections:**
  `\[<TAG>\] <Product Name> - exe=<ImageName>`
* **Truncation:** lines are right-truncated with `...` to honor `kLineMax`.

### Tags

`[AV], [EDR], [VPN], [ZTNA], [RDP], [CLOUD], [CREDS], [TEL], [VIRT], [FW], [HIPS], [VULN], [NDR], [AUDIO], [OEM], [DRM], [USB], [TB], [NAS], [INT], [OTHER]`

---

## How it works

* Enumerates processes via `CreateToolhelp32Snapshot`.
* Case-insensitive exact match on image name (`.exe`) against the internal catalog.
* **De-dup by image:** a single process can map to **multiple** products (all are listed).
* **Unknown** = not in the catalog and not part of **Windows baseline** or **mainstream apps**.

### Baselines

* `baselineSystem()`: only **native Windows** binaries (core, svchost, shell, UWP brokers, WMI, printing, WSL infra, etc.).
* `baselineCommonApps()`: **mainstream** non-suspicious apps (popular browsers, Microsoft Office, IM, Terminal/winget).

---

## Limitations

* Name-based heuristics: renamed/protected processes may evade detection.
* Does **not** inspect kernel drivers/services nor licensing/product state.
* **Low-noise** profile: no `SeDebugPrivilege`, no process memory access.

---

## CSV & PowerShell

### CSV schema

Publish `processes.csv` with columns:

| Process (exe)   | ProductName               | Tag     | Type                     |
| --------------- | ------------------------- | ------- | ------------------------ |
| `avp.exe`       | `Kaspersky AV / KES`      | `EDR`   | `AV / EDR`               |
| `nextcloud.exe` | `Nextcloud Desktop`       | `CLOUD` | `Cloud Sync / Nextcloud` |
| `keepass.exe`   | `KeePass Password Safe 2` | `CREDS` | `Credential Manager`     |
| …               | …                         | …       | …                        |

> `Tag` = short label without brackets; `Type` = longer descriptive category.

### PowerShell (online; corp-friendly)

**Option A — `Invoke-WebRequest` with system proxy & TLS:**

```powershell
$Url = 'https://raw.githubusercontent.com/<org>/<repo>/main/processes.csv'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Csv = (Invoke-WebRequest -Uri $Url -UseBasicParsing -ProxyUseDefaultCredentials -TimeoutSec 10).Content | ConvertFrom-Csv
$Procs = Get-Process
$Csv | ForEach-Object {
  $name = ($_.'Process' -replace '\.exe$','')
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name }
  if($r){ [pscustomobject]@{ Process="$($r[0].ProcessName).exe"; ProductName=$_.ProductName; Tag=$_.Tag; Type=$_.Type } }
} | Sort-Object Tag,Process,ProductName -Unique | Format-Table
```

**Option B — .NET `WebClient` honoring system proxy (often bypasses strict policies):**

```powershell
$Url = 'https://raw.githubusercontent.com/<org>/<repo>/main/processes.csv'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object Net.WebClient
$wc.Proxy = [Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
$Csv = $wc.DownloadString($Url) | ConvertFrom-Csv
$Procs = Get-Process
$Csv | ForEach-Object {
  $name = ($_.'Process' -replace '\.exe$','')
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name }
  if($r){ [pscustomobject]@{ Process="$($r[0].ProcessName).exe"; ProductName=$_.ProductName; Tag=$_.Tag; Type=$_.Type } }
} | Sort-Object Tag,Process,ProductName -Unique | Format-Table
```

**Option C — BITS (when `Invoke-*` is blocked, but BITS allowed):**

```powershell
$Url  = 'https://raw.githubusercontent.com/<org>/<repo>/main/processes.csv'
$Dest = Join-Path $env:TEMP 'processes.csv'
Start-BitsTransfer -Source $Url -Destination $Dest
$Csv  = Import-Csv $Dest
Remove-Item $Dest -Force
$Procs = Get-Process
$Csv | ForEach-Object {
  $name = ($_.'Process' -replace '\.exe$','')
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name }
  if($r){ [pscustomobject]@{ Process="$($r[0].ProcessName).exe"; ProductName=$_.ProductName; Tag=$_.Tag; Type=$_.Type } }
} | Sort-Object Tag,Process,ProductName -Unique | Format-Table
```

> Practical notes:
>
> * No elevation required. Works behind NTLM/Kerberos proxies via `-ProxyUseDefaultCredentials` (A) or system proxy (B).
> * Forcing `Tls12` reduces failures with TLS-inspection middleboxes.
> * Avoid disabling cert validation or execution policy changes; not needed here.

### PowerShell (offline)

```powershell
$Csv   = Import-Csv .\processes.csv
$Procs = Get-Process
$Csv | ForEach-Object {
  $name = ($_.'Process' -replace '\.exe$','')
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name }
  if($r){ [pscustomobject]@{ Process="$($r[0].ProcessName).exe"; ProductName=$_.ProductName; Tag=$_.Tag; Type=$_.Type } }
} | Sort-Object Tag,Process,ProductName -Unique | Format-Table
```

> **Single-line (Option B) for restricted consoles:**

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u='https://raw.githubusercontent.com/<org>/<repo>/main/processes.csv';$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;($w.DownloadString($u)|ConvertFrom-Csv)|%{$n=($_.Process -replace '\.exe$','');$p=Get-Process|?{$_.ProcessName -ieq $n};if($p){[pscustomobject]@{Process="$($p[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

---

## Selected vendors in catalog

* Microsoft Defender (AV/MDE), Sysmon, Security Health
* CrowdStrike Falcon, SentinelOne, Cortex XDR, Elastic Defend/Agent
* Trend Micro Apex/OfficeScan, McAfee/Trellix, Sophos, ESET, Bitdefender, Avast/Avira/Panda/Webroot, Symantec/Norton
* Zscaler, Fortinet, GlobalProtect, AnyConnect, OpenVPN, WireGuard
* Tanium, Rapid7 Insight Agent, Qualys Cloud Agent
* VMware Tools/Services, WSL stack
* Cloud sync (OneDrive, Google Drive, Dropbox, Nextcloud, iCloud family)
* Credential managers (KeePass, KeePassXC, Bitwarden, 1Password)
* Common OEM/DRM/GPU/USB/TB/NAS auxiliaries on corporate endpoints

---

## Changelog

* **v2.1.0**

  * Deterministic output (unknown → `---` → `[TAG]`-sorted detections).
  * Compact `cmd=` and stable `kLineMax` truncation.
  * Non-privileged fallbacks `svc=`/`bin=`/`img=`.
  * New tags plus expanded **2024–2025** catalog.
* **v2.0.x**

  * Unified AV/EDR/VPN/Telemetry catalog, UTF-8 output, basic de-dup.

---

## Contributing

* Open a PR with: **Process** name(s), **ProductName**, `Tag`, `Type`, and short rationale (vendor doc or telemetry).
* Update both `av_detect.cpp` (internal catalog) and `processes.csv` with the same **schema**.

---

## License

MIT.

