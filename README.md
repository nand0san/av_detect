# `av_detect` — Security Software Detector

Detects whether security software (AV, EDR/XDR, firewall, VPN/ZTNA, DLP, telemetry, etc.) is running on a Windows endpoint by enumerating live processes and matching them against a curated catalog of known agent executables.

* **Version:** `v2.1.0`
* **Scope:** Image-name–based detection; **no admin required**; low-noise (does **not** request `SeDebugPrivilege`).
* **Use cases:** DFIR triage, Red Team reconnaissance, asset inventory, SOC enrichment.



## What's new in `v2.1.0`

* **Deterministic, parser-friendly output**

  * Leading **unknown** block (non-baseline, non-mainstream processes).
  * Stable separator line `---`.
  * Security software detections sorted alphabetically and prefixed with `[TAG]`.

* **Compact process metadata**

  * `cmd=` normalized command line (no outer quotes, spacing normalized, smart truncation).
  * `svc=` and `bin=` fallback metadata from SCM.
  * `img=` for full image path when others are unavailable.

* **Expanded 2024–2025 detection catalog**

  * CrowdStrike, SentinelOne, Cortex XDR, Elastic Agent, Trend, McAfee/Trellix, Sophos, ESET, Zscaler, Fortinet, Tanium, Rapid7, Qualys, etc.

* **New categories**

  * `[CLOUD]`, `[CREDS]`, `[RDP]`, `[ZTNA]`, plus existing `[AV]`, `[EDR]`, `[VPN]`, `[TEL]`, `[VIRT]`, `[FW]`, `[HIPS]`, `[VULN]`, `[NDR]`, `[AUDIO]`, `[OEM]`, `[DRM]`, `[USB]`, `[TB]`, `[NAS]`, `[INT]`, `[OTHER]`.



## Requirements

* **OS:** Windows 10/11 (x64 recommended)
* **Compiler:** MSVC, MinGW-w64 g++, clang-cl (C++17+)
* **Headers:** Provided by standard Win32 SDK (`tlhelp32.h`, `winsvc.h`)



## Build

### MSVC (Developer Command Prompt)

```bat
cl /std:c++17 /O2 /W3 /EHsc av_detect.cpp /link /SUBSYSTEM:CONSOLE
```

### MinGW-w64 (g++)

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



## Usage

```powershell
.\av_detect.exe
```

**Example output:**

```
AV_detect Version: v2.1.0

[unknown] Non-system unknown processes (24):
- ai.exe | cmd=C:\Program Files\Microsoft Office\root\...
- ...

[AV] Kaspersky UI - exe=avpui.exe
[CLOUD] Nextcloud Desktop - exe=nextcloud.exe
[EDR] Kaspersky AV / KES - exe=avp.exe
[RDP] Microsoft Remote Desktop Client - exe=mstsc.exe
[VPN] WireGuard - exe=wireguard.exe
...
```

Exit code is always **0**. Output is exclusively on **stdout**.



## Output format (stable)

* **Unknown processes:**

  ```
  - <exeLower>[ | cmd=<normalized> | svc=<name>(+N)[ | bin=<path>] | img=<fullpath>]
  ```

* **Separator:**
  `---`

* **Detections:**

  ```
  [<TAG>] <ProductName> - exe=<ImageName>
  ```

### Tags

```
[AV], [EDR], [VPN], [ZTNA], [RDP], [CLOUD], [CREDS], [TEL], [VIRT],
[FW], [HIPS], [VULN], [NDR], [AUDIO], [OEM], [DRM], [USB], [TB],
[NAS], [INT], [OTHER]
```



## How it works

* Enumerates processes using `CreateToolhelp32Snapshot`.
* Performs case-insensitive exact match on `.exe` names.
* A single process may match **multiple products** → all listed.
* **Unknown** includes everything not in the catalog and not part of the Windows or common-apps baseline.

### Baselines

* `baselineSystem()` → core Windows OS binaries
* `baselineCommonApps()` → mainstream, non-suspicious software (Office, browsers, chat clients, terminal apps, etc.)



## Limitations

* Name-based detection: renamed/protected processes may evade classification.
* Does **not** inspect kernel drivers or licensing state.
* Low-noise by design: no handle access, no memory inspection, no `SeDebugPrivilege`.



## CSV + PowerShell

### CSV schema (`processes.csv`)

| Process (exe)   | ProductName               | Tag     | Type                     |
| --------------- | ------------------------- | ------- | ------------------------ |
| `avp.exe`       | `Kaspersky AV / KES`      | `EDR`   | `AV / EDR`               |
| `nextcloud.exe` | `Nextcloud Desktop`       | `CLOUD` | `Cloud Sync / Nextcloud` |
| `keepass.exe`   | `KeePass Password Safe 2` | `CREDS` | `Credential Manager`     |



## PowerShell detection (online)

These one-liners use the canonical CSV:

```
https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv
```

### **Option A — Invoke-WebRequest (simple, TLS 1.2)**

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$procs=Get-Process;(Invoke-WebRequest -Uri $url -UseBasicParsing).Content|ConvertFrom-Csv|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

### **Option B — .NET WebClient (honors system proxy)**

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$wc=New-Object Net.WebClient;$wc.Proxy=[Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$procs=Get-Process;($wc.DownloadString($url)|ConvertFrom-Csv)|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

### **Option C — BITS (when Invoke-WebRequest is blocked)**

```powershell
$url='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$dest=Join-Path $env:TEMP 'processes.csv';Start-BitsTransfer -Source $url -Destination $dest;$procs=Get-Process;Import-Csv $dest|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table;Remove-Item $dest -Force
```

### **Compact single-line (restricted shells)**

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u='https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv';$w=New-Object Net.WebClient;$w.Proxy=[Net.WebRequest]::GetSystemWebProxy();$w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;($w.DownloadString($u)|ConvertFrom-Csv)|ForEach-Object{$n=($_.Process -replace '\.exe$','');$p=Get-Process|Where-Object{$_.ProcessName -ieq $n};if($p){[pscustomobject]@{Process="$($p[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```



## PowerShell detection (offline)

For offline environments, download `processes.csv` manually and run:

```powershell
$procs=Get-Process;Import-Csv .\processes.csv -Header Process,ProductName,Tag,Type|ForEach-Object{$name=($_.Process -replace '\.exe$','');$r=$procs|Where-Object{$_.ProcessName -ieq $name};if($r){[pscustomobject]@{Process="$($r[0].ProcessName).exe";ProductName=$_.ProductName;Tag=$_.Tag;Type=$_.Type}}}|Sort-Object Tag,Process,ProductName -Unique|Format-Table
```

The forced header ensures stable parsing even if the CSV was exported without a header row.



## Vendor coverage (subset)

* Microsoft Defender, MDE, Sysmon
* CrowdStrike Falcon, SentinelOne, Cortex XDR, Elastic Agent
* Trend Micro, McAfee/Trellix, Sophos, ESET, Bitdefender, Avast/Avira/Panda/Webroot
* Zscaler, Fortinet, GlobalProtect, AnyConnect, OpenVPN, WireGuard
* Tanium, Rapid7 Insight Agent, Qualys Cloud Agent
* VMware Tools, WSL stack
* Credential managers (KeePass, Bitwarden, 1Password, etc.)
* Cloud sync (OneDrive, Dropbox, Google Drive, Nextcloud, iCloud)
* OEM/DRM/GPU/USB/TB/NAS auxiliary services



## Changelog

### v2.1.0

* Deterministic output (`unknown → --- → TAG-sorted detections`)
* Compact `cmd=` with truncation
* Fallback `svc=` / `bin=` / `img=`
* Expanded 2024–2025 catalog
* New detection tags

### v2.0.x

* Unified AV/EDR/VPN/Telemetry catalog
* UTF-8 output, basic de-duplication



## Contributing

* Open a PR including **Process**, **ProductName**, **Tag**, **Type**, and the rationale (vendor documentation or telemetry).
* Update **both** `av_detect.cpp` and `processes.csv`.



## License

MIT.


