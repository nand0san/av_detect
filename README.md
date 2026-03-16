
# AVDETECT - SECURITY SOFTWARE DETECTOR

Detects whether security software (AV, EDR/XDR, firewall, VPN/ZTNA, DLP, telemetry, etc.) is running on a Windows endpoint by enumerating live processes and matching them against a curated catalog of known agent executables.

- **Version:** `v2.3.0`
- **Scope:** Image-name-based detection; **no admin required**; low-noise (does **not** request `SeDebugPrivilege`).
- **Use cases:** DFIR triage, Red Team reconnaissance, asset inventory, SOC enrichment.



## WHAT'S NEW IN V2.3.0

- **Expanded catalog** (266 entries, +75 over v2.2.0)
  - Cisco Secure Client, Pulse Secure / Ivanti, Citrix Workspace ICA, Zscaler ZDP
  - McAfee/Trellix DLP, Endpoint Encryption, Agent components
  - SentinelOne UI + Helper, TeamViewer client/helpers, IBM Tivoli RC
  - Microsoft SCCM, Intune, Vintegris ModuloM
  - Lenovo Dock Manager, ePrivacy Display, Intel GPU Command Center, Synaptics
  - nxlog log forwarder
- **Reduced AV false positives** (12/76 -> 3/76 on VirusTotal)
  - Removed static linking (eliminates DWARF sections and overlay)
  - Added PE version info resource (VERSIONINFO)
  - Stripped debug symbols in Release builds
- **Bug fixes**
  - Fixed duplicate detection for vpnagent.exe
  - Fixed buffer bounds validation in command-line extraction
  - Fixed CMake linker flags applied after target
  - Single process snapshot for both stdout and `--full` (consistent output)
  - RAII guards for all HANDLE / SC_HANDLE resources
- **Version managed from CMakeLists.txt** (single source of truth)



## REQUIREMENTS

- **OS:** Windows 10/11 (x64 recommended)
- **Compiler:** MSVC, MinGW-w64 g++, clang-cl (C++17+)
- **Headers:** Provided by standard Win32 SDK (`tlhelp32.h`, `winsvc.h`)



## BUILD

### MSVC (DEVELOPER COMMAND PROMPT)

```bat
cl /std:c++17 /O2 /W3 /EHsc av_detect.cpp /link /SUBSYSTEM:CONSOLE
````

### MINGW-W64 (G++)

```bash
g++ -std=c++17 -O2 -Wall -o av_detect.exe av_detect.cpp
```

### CMAKE (OPTIONAL)

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

## USAGE

### STANDARD (STDOUT)

```powershell
.\av_detect.exe
```

### FULL REPORT TO FILE (NO TRUNCATION)

```powershell
.\av_detect.exe --full C:\Temp\av_detect_full.txt
```

**Notes**

- Stdout stays **compact** and parser-friendly.
- The file written by `--full` contains the **same output** but with **no field truncation**.

## EXAMPLE OUTPUT

```
AV_detect Version: v2.3.0

[unknown] Non-system unknown processes (N):
- someproc.exe | cmd=C:\Path\To\someproc.exe --arg1 --arg2 ...
- othersvc.exe | svc=ServiceName(+2) | bin=C:\Program Files\Vendor\svc.exe -k group
- another.exe | img=C:\Windows\System32\another.exe


[AV] Kaspersky UI - avpui.exe
[CLOUD] Nextcloud Desktop - nextcloud.exe
[EDR] CrowdStrike Falcon Sensor - csfalconservice.exe
[RDP] Microsoft Remote Desktop Client - mstsc.exe
[VPN] WireGuard - wireguard.exe
...
```

Exit code is always **0**. Output is exclusively on **stdout** (plus optional file when using `--full`).

## OUTPUT FORMAT (STABLE)

- **Unknown processes:**

  ```
  - <exeLower>[ | cmd=<normalized> | svc=<name>(+N)[ | bin=<path>] | img=<fullpath>]
  ```

  Metadata priority is:

  1. `cmd=` (best triage signal)
  2. `svc=` / `bin=` from SCM (when cmdline is protected)
  3. `img=` full image path (fallback)

- **Separator:**
  `---`

- **Detections:**

  ```
  [<TAG>] <ProductName> - <ImageName>
  ```

  (The `<ImageName>` is the observed process image name as returned by Toolhelp.)

## TAGS

```
[AV], [EDR], [VPN], [ZTNA], [RDP], [CLOUD], [CREDS], [DLP], [TEL],
[VIRT], [FW], [HIPS], [VULN], [NDR], [ENC], [AUDIO], [OEM], [DRM],
[GPU], [USB], [TB], [NAS], [INT], [MON], [RMM], [OTHER], [APPC],
[UEM], [PAM], [TRUST]
```

## HOW IT WORKS

- Enumerates processes using `CreateToolhelp32Snapshot`.
- Performs case-insensitive exact match on `.exe` names.
- A single process may match **multiple products** -> all are listed.
- **Unknown** includes everything not in the catalog and not part of the Windows or common-apps baseline.

### BASELINES

- `baselineSystem()` -> core Windows OS binaries
- `baselineCommonApps()` -> mainstream, non-suspicious software (Office, browsers, chat clients, terminal apps, etc.)

Baselines are **noise suppression only** (not allow-lists).

## LIMITATIONS

- Name-based detection: renamed/protected processes may evade classification.
- Does **not** inspect kernel drivers or licensing state.
- Low-noise by design: no memory inspection, no `SeDebugPrivilege`.

## CSV + POWERSHELL

### CSV SCHEMA (PROCESSES.CSV)

| Process (exe)   | ProductName               | Tag     | Type                     |
| --------------- | ------------------------- | ------- | ------------------------ |
| `avp.exe`       | `Kaspersky AV / KES`      | `AV`    | `AV / EDR`               |
| `nextcloud.exe` | `Nextcloud Desktop`       | `CLOUD` | `Cloud Sync / Nextcloud` |
| `keepass.exe`   | `KeePass Password Safe 2` | `CREDS` | `Credential Manager`     |

## POWERSHELL DETECTION (ONLINE)

These one-liners use the canonical CSV:

```
https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv
```

### OPTION A - INVOKE-WEBREQUEST (SIMPLE, TLS 1.2)

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$procs=Get-Process;(Invoke-WebRequest -Uri $url -UseBasicParsing).Content|ConvertFrom-Csv|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

### OPTION B - .NET WEBCLIENT (HONORS SYSTEM PROXY)

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$wc=New-Object Net.WebClient;$wc.Proxy=[Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$procs=Get-Process;($wc.DownloadString($url)|ConvertFrom-Csv)|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

### OPTION C - BITS (WHEN INVOKE-WEBREQUEST IS BLOCKED)

```powershell
$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$dest=Join-Path $env:TEMP 'processes.csv';Start-BitsTransfer -Source $url -Destination $dest;$procs=Get-Process;Import-Csv $dest|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table;Remove-Item $dest -Force
```

### COMPACT SINGLE-LINE (RESTRICTED SHELLS)

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;($w.DownloadString($u)|ConvertFrom-Csv)|ForEach-Object{$n=($_.Process -replace '\.exe$','');$p=Get-Process|Where-Object{$_.ProcessName -ieq $n};if($p){[pscustomobject]@{Process="$($p[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

## POWERSHELL DETECTION (OFFLINE)

For offline environments, download `processes.csv` manually and run:

```powershell
$procs=Get-Process;Import-Csv .\processes.csv -Header Process,ProductName,Tag,Type|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

The forced header ensures stable parsing even if the CSV was exported without a header row.

## VENDOR COVERAGE (SUBSET)

- Microsoft Defender, MDE, Sysmon
- CrowdStrike Falcon, SentinelOne, Cortex XDR, Elastic Agent
- Trend Micro, McAfee/Trellix, Sophos, ESET, Bitdefender, Avast/Avira/Panda/Webroot
- Zscaler, Fortinet, GlobalProtect, AnyConnect, OpenVPN, WireGuard
- Tanium, Rapid7 Insight Agent, Qualys Cloud Agent
- VMware Tools, WSL stack
- Credential managers (KeePass, Bitwarden, 1Password, etc.)
- Cloud sync (OneDrive, Dropbox, Google Drive, Nextcloud, iCloud)
- Pulse Secure / Ivanti, Cisco Secure Client (AnyConnect rebrand)
- Citrix Workspace / ICA Client, Vintegris ModuloM
- Microsoft SCCM, Intune, ManageEngine UEM
- IBM Tivoli Remote Control, nxlog
- OEM/DRM/GPU/USB/TB/NAS auxiliary services

## CHANGELOG

### V2.3.0

- Catalog expanded to 266 entries (+75): Cisco Secure Client, Pulse Secure, Citrix ICA, Zscaler ZDP, McAfee/Trellix DLP, SCCM, Intune, IBM Tivoli, Vintegris, nxlog, OEM extras
- PE version info resource added (reduces AV false positives)
- Removed static linking; stripped DWARF debug sections (VT score: 12/76 -> 3/76)
- Fixed vpnagent.exe duplicate detection, buffer bounds check, CMake linker order
- Single process snapshot for stdout + `--full` (consistent output)
- RAII resource guards (HandleGuard / ScHandleGuard)
- Version centralized in CMakeLists.txt

### V2.2.0

- Added `--full <path>`: write a non-truncated full report to file while keeping stdout compact.
- Output remains deterministic (`unknown -> --- -> TAG-sorted detections`)
- Best-effort metadata: `cmd=` then `svc=`/`bin=` then `img=`

### V2.1.0

- Deterministic output (`unknown -> --- -> TAG-sorted detections`)
- Compact `cmd=` with truncation
- Fallback `svc=` / `bin=` / `img=`
- Expanded 2024-2025 catalog
- New detection tags

## CONTRIBUTING

- Open a PR including **Process**, **ProductName**, **Tag**, **Type**, and the rationale (vendor documentation or telemetry).
- Update **both** `av_detect.cpp` and `processes.csv`.

## LICENSE

MIT.
