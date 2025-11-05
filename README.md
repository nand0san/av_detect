
# Security Software Detector (av_detect)

Detects if security software (AV, EDR, XDR, firewall, VPN, DLP, telemetry, etc.) is running on a Windows endpoint by enumerating live processes and matching them against a curated catalog of well-known agent executables.

* **Version:** `v2.00`
* **Scope:** Process-name based heuristic, no admin required.
* **Use cases:** DFIR triage, Red Team reconnaissance, IT asset survey.

## What’s new in v2.00

* **Broader coverage (2024–2025 enterprise stack):** Elastic Defend/Agent, CrowdStrike Falcon service, SentinelOne extended set, Cortex XDR (modern services), Zscaler Client Connector, Fortinet FortiClient/FortiTray, Tanium, Rapid7 Insight Agent, Qualys Cloud Agent, Trend Micro Apex/OfficeScan core engines, etc.
* **Multi-mapping per process:** one process name can map to multiple products/vendors (e.g., shared services).
* **De-duplication:** each process printed once, listing all known product mappings.
* **UTF-8 console output** for consistent rendering.



## Requirements

* **OS:** Windows.
* **Compiler:** C++17 or later (MSVC, MinGW-w64 g++, clang-cl).
* **SDK/Headers:** On MSVC use the Windows SDK (bundled with the VS toolchain). MinGW-w64 already provides Win32 headers (`tlhelp32.h`) needed for `CreateToolhelp32Snapshot`.



## Build / Compilation

### MSVC (Developer Command Prompt)

```bat
cl /std:c++17 /O2 /W3 /EHsc av_detect.cpp /link /SUBSYSTEM:CONSOLE
```

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

> Tip (Blue Team): if you need fewer AV heuristics from SmartScreen/Defender on internal use, sign the binary with a code-signing cert (`signtool sign /fd SHA256 /a av_detect.exe`).
> Note: On 64-bit Windows, prefer building a 64-bit binary to simplify potential future module/path inspection (WOW64 nuances).



## Usage

```bash
.\av_detect.exe
```

**Example output:**

```
AV_detect Version: v2.00
Security Software detected: CrowdStrike Falcon Sensor (EDR / XDR) - Process: csfalconservice.exe
Security Software detected: Microsoft Defender for Endpoint (MDE / ATP) (EDR) - Process: mssense.exe
Security Software detected: Zscaler Client Connector (Zscaler ZTNA / Secure Web Gateway) (Proxy / CASB / ZTNA) - Process: zsatray.exe

Found security software process (AV, anti-malware, EDR, XDR, etc.) running.
```

Exit code is always `0`; the tool reports findings via stdout.



## How it Works

* Uses `CreateToolhelp32Snapshot` to enumerate running processes.
* Case-insensitive exact name match against an internal dictionary.
* A single process name may map to **several** products/vendors; all are printed.
* Each process is reported **once** to avoid noisy duplicates.

**Limitations**

* Process-name heuristics only: renamed binaries or protected/hidden processes may evade detection.
* Does **not** enumerate Windows services/drivers or query product states/licensing.
* No admin rights are required.



## Detected Software (non-exhaustive but curated)

> Process names are shown as detected (case-insensitive). This list reflects the built-in catalog in `av_detect v2.00`.

* **Absolute Persistence** (`acnamagent.exe`, `acnamlogonagent.exe`) – Asset Management
* **Adobe** (`agmservice.exe`, `agsservice.exe`) – Telemetry
* **Agnitum Outpost Firewall** (`outpost.exe`) – Firewall
* **Avast** (`aswidsagent.exe`, `avastsvc.exe`, `avastui.exe`) – AV
* **Avira** (`avgnt.exe`, `avguard.exe`) – AV
* **AxCrypt** (`axcrypt.exe`) – Encryption
* **Bitdefender** (`bdntwrk.exe`, `updatesrv.exe`, `vsserv.exe`, `bdagent.exe`) – AV
* **Check Point** (`cpd.exe`, `fw.exe`) – Security / Firewall
* **Cisco AnyConnect** (`vpnagent.exe`, `vpnui.exe`) – VPN
* **Cisco Umbrella Roaming** (`aciseagent.exe`, `acumbrellaagent.exe`) – Security DNS
* **Configuration Manager Remote Control** (`cmrcservice.exe`) – Remote Control
* **CrowdStrike Falcon** (`csfalconservice.exe`, `csfalconcontainer.exe`, `csfalcondaterepair.exe`, `cbcomms.exe`) – EDR / XDR
* **Cybereason** (`cybereason.exe`) – EDR
* **Cytomic Orion** (`cytomicendpoint.exe`) – Security
* **Darktrace** (`darktracetsa.exe`) – EDR
* **DriveSentry** (`dsmonitor.exe`, `dwengine.exe`) – Security
* **ESET NOD32 / Endpoint** (`egui.exe`, `ekrn.exe`) – AV
* **Elastic Defend / Endpoint** (`elastic-endpoint.exe`, `endpoint-security.exe`) – EDR / Telemetry
* **Elastic Agent (Fleet)** (`elastic-agent.exe`) – EDR / Telemetry / UEM
* **Elastic Winlogbeat** (`winlogbeat.exe`) – Security Telemetry
* **FireEye HX / Trellix HX** (`firesvc.exe`, `firetray.exe`, `xagt.exe`) – Security / EDR
* **FortiEDR** (`fortiedr.exe`) – EDR
* **Fortinet FortiClient / FortiTray** (`fortitray.exe`, `fortivpn.exe`) – VPN / Endpoint Security
* **Host Intrusion Prevention System** (`hips.exe`) – HIPS
* **Kaspersky** (`avp.exe`, `avpui.exe`, `klwtblfs.exe`) – AV
* **Kaspersky Secure Connection** (`ksde.exe`, `ksdeui.exe`) – VPN
* **Kerio Personal Firewall** (`kpf4ss.exe`) – Firewall
* **Malwarebytes** (`mbae64.sys`, `mbamservice.exe`, `mbamswissarmy.sys`, `mbamtray.exe`) – AV
* **McAfee / Trellix** (`macmnsvc.exe`, `masvc.exe`, `mfemms.exe`, `mfeann.exe`, `mcshield.exe`, `shstat.exe`,
  `mfefire.exe`, `mfemactl.exe`, `edpa.exe`, `dlpsensor.exe`, `mfeepehost.exe`, `mdecryptservice.exe`) – AV / EDR / DLP / Firewall / Encryption
* **Microsoft Defender AV** (`msmpeng.exe`, `msascuil.exe`, `windefend.exe`) – AV
* **Microsoft Defender for Endpoint (MDE/ATP)** (`mssense.exe`, `senseir.exe`, `sensendr.exe`, `sensetvm.exe`, `mpdefendercoreservice.exe`) – EDR / TVM
* **Microsoft Monitoring / OMS** (`monitoringhost.exe`, `healthservice.exe`) – Monitoring
* **Microsoft Security Essentials** (`msseces.exe`, `nissrv.exe`) – AV
* **Microsoft Sysmon** (`sysmon.exe`, `sysmon64.exe`) – Security Telemetry
* **Norton / Symantec** (`ccsvchst.exe`, `rtvscan.exe`, `nortonsecurity.exe`, `ns.exe`, `nsservice.exe`) – AV
* **OpenVPN** (`openvpnserv.exe`) – VPN
* **Palo Alto Networks Cortex XDR (Cyvera/Traps)** (`cyserver.exe`, `cyveraservice.exe`, `cyveraconsole.exe`,
  `cyvragentsvc.exe`, `cyvrfsflt.exe`, `traps.exe`, `trapsagent.exe`, `trapsd.exe`) – EDR / XDR
* **Palo Alto Networks GlobalProtect** (`concentr.exe`, `pangps.exe`) – VPN
* **Panda Security** (`panda_url_filtering.exe`, `pavfnsvr.exe`, `pavsrv.exe`, `psanhost.exe`) – AV
* **Rapid7 Insight Agent** (`ir_agent.exe`) – EDR / Vulnerability / IR
* **Qualys Cloud Agent** (`qualysagent.exe`, `qualysagentui.exe`) – Vulnerability / Compliance
* **Sandboxie** (`sbiesvc.exe`) – Security
* **Security Health** (`securityhealthservice.exe`, `securityhealthsystray.exe`) – Windows Security Health
* **SentinelOne** (`sentinelagent.exe`, `sentinelctl.exe`, `sentinelservicehost.exe`,
  `sentinelstaticengine.exe`, `sentinelstaticenginescanner.exe`, `sentinelmemoryscanner.exe`) – EDR / XDR
* **SentinelOne Singularity XDR** (`cpx.exe`) – XDR
* **SolarWinds NPM** (`npmdagent.exe`) – Network Monitoring
* **Sophos** (`savservice.exe`, `sophosav.exe`, `sophossps.exe`, `sophosui.exe`, `sophosclean.exe`, `sophoshealth.exe`) – AV / EDR
* **Tanium Client** (`taniumclient.exe`, `tanclient.exe`) – IR / EDR / Asset Mgmt
* **Trend Micro Apex One / OfficeScan** (`tmlisten.exe`, `ntrtscan.exe`, `tmproxy.exe`, `tmntsrv.exe`,
  `coreserviceshell.exe`, `clientcommunicationservice.exe`, `clientlogservice.exe`,
  `clientsolutionframework.exe`, `endpointbasecamp.exe`, `personalfirewallservice.exe`,
  `realtimescanservice.exe`, `samplingservice.exe`, `telemetryagentservice.exe`,
  `telemetryservice.exe`, `wscservice.exe`, `dataprotectionservice.exe`, `uiwinmgr.exe`,
  `browserexploitdetection.exe`, `appcontrolagent.exe`, `vulnerabilityprotectionagent.exe`) – AV / EDR / App Control / Exploit Detection / DLP / Firewall / Telemetry / Vuln
* **TrueCrypt** (`truecrypt.exe`) – Encryption
* **VMware Tools** (`vgauthservice.exe`, `vm3dservice.exe`, `vmtoolsd.exe`) – Virtualization
* **Webroot** (`wrsa.exe`) – AV / EDR
* **Windows System Guard** (`sgrmbroker.exe`) – System Integrity
* **WireGuard** (`wireguard.exe`) – VPN
* **Zscaler Client Connector** (`zsatray.exe`, `zsatraymanager.exe`) – Proxy / CASB / ZTNA
* **mDNSResponder (Bonjour)** (`mdnsresponder.exe`) – Network Service

> The catalog is evolving; contributions are welcome.



## Alternative usage with pure PowerShell (no exe)

You can query the maintained CSV directly from GitHub and match against the running process list.

> **Red Team note:** EDRs can flag this as `tasklist`/process enumeration activity. Prefer the compiled binary when stealth is required.

```powershell
$Url="https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv";
$Csv = Invoke-WebRequest -Uri $Url -UseBasicParsing | ConvertFrom-Csv;
$Procs = Get-Process;
$Hits = foreach($p in $Csv){
  $name = ($p.Process -replace '\.exe$','');                        # normalize
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name };         # exact case-insensitive
  if($r){
    $rp = $r | Select-Object -First 1;                              # avoid array if multiple instances
    [pscustomobject]@{ Process = $rp.ProcessName; Name = $p.Name; Type = $p.Type }
  }
}
$Hits | Sort-Object Process,Name,Type -Unique | Format-Table
```

## PowerShell offline (with downloaded CSV)

```powershell
$Csv = Import-Csv .\processes.csv
$Procs = Get-Process
$Hits = foreach($p in $Csv){
  $name = ($p.Process -replace '\.exe$','')
  $r = $Procs | Where-Object { $_.ProcessName -ieq $name }
  if($r){ $rp = $r | Select-Object -First 1; [pscustomobject]@{ Process=$rp.ProcessName; Name=$p.Name; Type=$p.Type } }
}
$Hits | Sort-Object Process,Name,Type -Unique | Format-Table
```



## Contributing

* Propose new entries with **process name(s)**, **product name**, and **category**.
* Prefer vendor docs or stable artifacts seen in enterprise deployments.
* Open a PR with:

    * update to the internal dictionary in `av_detect.cpp`,
    * (optional) update to `processes.csv`,
    * a short rationale (links, screenshots, or telemetry snippets).



## License

MIT (unless the repository specifies otherwise).

