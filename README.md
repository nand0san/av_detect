# Security Software Detector
This program detects if any security software (AV, EDR, XDR, firewall, etc.) is running on the system. The program searches the list of running processes and compares their names with a predefined list of known security software processes.

# Requirements
A C++17 or later compatible compiler.
Windows as the operating system.

# Compilation
Open a terminal or command prompt.
Navigate to the directory where the main.cpp file is located.
Compile the program using CLion, also a C++17 or later compatible compiler. For example, to compile with g++, execute the following command:
```
g++ -std=c++17 -o av_detect main.cpp
```
This will create an executable file named av_detect.exe in the same directory.

## Detected Apps

The program detects the following security software processes:

- Absolute Persistence (`acnamagent.exe`) - Asset Management
- Absolute Persistence (`acnamlogonagent.exe`) - Asset Management
- Adobe (`AGMService.exe`) - Telemetry
- Adobe (`AGSService.exe`) - Telemetry
- Agnitum Outpost Firewall - Firewall
- Avast (`aswidsagent.exe`, `avastsvc.exe`, `avastui.exe`) - AV
- Avira (`avgnt.exe`, `avguard.exe`) - AV
- AxCrypt (`axcrypt.exe`) - Encryption
- Bitdefender (`bdntwrk.exe`, `updatesrv.exe`) - AV
- Bitdefender Total Security (`bdagent.exe`, `vsserv.exe`) - AV
- Check Point Daemon (`cpd.exe`) - Security
- Check Point Firewall (`fw.exe`) - Firewall
- Cisco AnyConnect (`vpnagent.exe`, `vpnui.exe`) - VPN
- Cisco AnyConnect Secure Mobility Client (`vpnagent.exe`) - VPN
- Cisco Umbrella Roaming Security (`aciseagent.exe`, `acumbrellaagent.exe`) - Security DNS
- CmRcService (`CmRcService.exe`) - Remote Control
- CrowdStrike Falcon (`csfalconcontainer.exe`, `csfalcondaterepair.exe`, `csfalconservice.exe`) - EDR
- CrowdStrike Falcon Insight XDR (`cbcomms.exe`) - XDR
- Cybereason EDR (`cybereason.exe`) - EDR
- Cytomic Orion (`cytomicendpoint.exe`) - Security
- Darktrace (`DarktraceTSA.exe`) - EDR
- DriveSentry (`dsmonitor.exe`, `dwengine.exe`) - Security
- ESET NOD32 AV (`egui.exe`, `ekrn.exe`) - AV
- Elastic Winlogbeat (`winlogbeat.exe`) - Security
- FireEye Endpoint Agent (`firesvc.exe`, `firetray.exe`) - Security
- FireEye HX (`xagt.exe`) - Security
- FortiEDR (`fortiedr.exe`) - EDR
- Host Intrusion Prevention System (`hips.exe`) - HIPS
- Kaspersky (`avp.exe`, `avpui.exe`, `klwtblfs.exe`, `klwtpwrs.srv`) - AV
- Kaspersky Secure Connection (`ksde.exe`, `ksdeui.exe`) - VPN
- Kerio Personal Firewall (`kpf4ss.exe`) - Firewall
- Malwarebytes (`mbae64.sys`, `mbamservice.exe`, `mbamswissarmy.sys`, `mbamtray.exe`) - AV
- McAfee (`mfeann.exe`, `mfemms.exe`, `masvc.exe`, `macmnsvc.exe`) - AV
- McAfee DLP Sensor (`dlpsensor.exe`) - DLP
- McAfee Endpoint Encryption (`eegoservice.exe`, `mdecryptservice.exe`, `mfeepehost.exe`) - Encryption
- McAfee Endpoint Security (`edpa.exe`, `shstat.exe`, `mcshield.exe`, `mfefire.exe`, `mfemactl.exe`, `mfemms.exe`) - AV
- McAfee Endpoint Security Firewall (`mfemactl.exe`) - Firewall
- McAfee Host Intrusion Prevention (`mfefire.exe`) - HIPS
- McAfee VirusScan (`mcshield.exe`, `shstat.exe`) - AV
- Microsoft .NET Framework (`SMSvcHost.exe`) - Application
- Microsoft Defender ATP (`mssense.exe`) - Security
- Microsoft Monitoring Agent (`MonitoringHost.exe`) - Monitoring
- Microsoft OMS (`HealthService.exe`) - Monitoring
- Microsoft Security Essentials (`msseces.exe`, `nissrv.exe`) - AV
- Microsoft Sysmon (`sysmon.exe`, `sysmon64.exe`) - Security
- Norton Antivirus (`ccSvcHst.exe`, `nortonsecurity.exe`, `ns.exe`, `nsservice.exe`) - AV
- OpenVPN (`openvpnserv.exe`) - VPN
- Palo Alto Networks (Cyvera) (`CyveraConsole.exe`, `CyveraService.exe`) - EDR
- Palo Alto Networks Cortex XDR (`CyvrAgentSvc.exe`, `CyvrFsFlt.exe`, `trapsagent.exe`, `trapsd.exe`) - XDR
- Palo Alto Networks GlobalProtect (`concentr.exe`, `pangps.exe`) - VPN
- Panda Security (`panda_url_filtering.exe`, `pavfnsvr.exe`, `pavsrv.exe`, `psanhost.exe`) - AV
- Sandboxie (`sbiesvc.exe`) - Security
- SecurityHealthService (`SecurityHealthService.exe`) - Windows Security Health Service
- SentinelOne (`Sentinel.exe`, `SentinelAgent.exe`, `SentinelCtl.exe`) - EDR
- SentinelOne Singularity XDR (`cpx.exe`) - XDR
- SolarWinds NPM (`NPMDAgent.exe`) - Network Monitoring
- Sophos (`savservice.exe`, `sophosav.exe`, `sophossps.exe`, `sophosui.exe`, `SophosClean.exe`, `SophosHealth.exe`) - AV
- Symantec DLP Agent (`dlpagent.exe`) - DLP
- Symantec Endpoint Protection (`ccsvchst.exe`, `rtvscan.exe`) - AV
- Tanium EDR (`tanclient.exe`) - EDR
- Trend Micro (`AppControlAgent.exe`, `BrowserExploitDetection.exe`, `ClientCommunicationService.exe`, `ClientLogService.exe`, `ClientSolutionFramework.exe`, `DataProtectionService.exe`, `EndpointBasecamp.exe`, `PersonalFirewallService.exe`, `RealTimeScanService.exe`, `SamplingService.exe`, `SecurityAgentMonitor.exe`, `TelemetryAgentService.exe`, `coreServiceShell.exe`, `uiWinMgr.exe`, `tmntsrv.exe`, `tmproxy.exe`) - AV, EDR, Application Control, Exploit Detection, Data Protection, Firewall, Security Service, Vulnerability Protection, Telemetry
- TrueCrypt (`truecrypt.exe`) - Encryption
- VMware (`VGAuthService.exe`, `vm3dservice.exe`, `vmtoolsd.exe`) - Virtualization
- VMware Carbon Black EDR (`carbonsensor.exe`) - EDR
- Webroot Anywhere (`wrsa.exe`) - AV
- Windows Defender (`msascuil.exe`, `msmpeng.exe`, `windefend.exe`) - AV
- WireGuard (`wireguard.exe`) - VPN
- mDNSResponder (Bonjour Service) - Network Service


# Usage
Execute the compiled program in a terminal or command prompt. The program will show if any security software is detected running on the system.

```
./av_detect.exe
```
The program will display "Security software is running." if any security software is detected, and "No security software detected." otherwise.

![img.png](img.png)

# Alternative usage using only PowerShell, without using the executable

You can use a PowerShell command to directly interact with the CSV hosted on GitHub, without the need to download the project or compile it.

The original command uses the `[PSCustomObject]` notation to create a custom object directly and add it to `$FoundProcesses`. 
However, this notation caused errors in restrictive environments, so an alternative approach with `Select-Object` was used.

> Red Teamers, be carefull. EDRs can identify the powershell command as tasklist activity. To avoid this compile or use compiled version.
 
```
$Url="https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv"; $ProcessesCSV = Invoke-WebRequest -Uri $Url -UseBasicParsing | ConvertFrom-Csv; $RunningProcesses = Get-Process; $FoundProcesses = @(); foreach ($process in $ProcessesCSV) { $runningProcess = $RunningProcesses | Where-Object { $_.ProcessName -like $process.Process.Replace('.exe','') }; if ($runningProcess) { $ProcessInfo = "" | Select-Object Process, Name, Type; $ProcessInfo.Process = $runningProcess.ProcessName; $ProcessInfo.Name = $process.Name; $ProcessInfo.Type = $process.Type; $FoundProcesses += $ProcessInfo; } }; $FoundProcesses | Format-Table; Write-Output "`nIf you want to contribute to the project, please open issue in https://github.com/nand0san/av_detect with a txt file like 'Get-Process > my_processes.txt' and will check if any new process can be added to the tool. Thank you!"
```
Output example:
```
$Url="https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv"; $ProcessesCSV = Invoke-WebRequest -Uri 
$Url -UseBasicParsing | ConvertFrom-Csv; $RunningProcesses = Get-Process; $FoundProcesses = @(); foreach ($process in 
$ProcessesCSV) { $runningProcess = $RunningProcesses | Where-Object { $_.ProcessName -like $process.Process
.Replace('.exe','') }; if ($runningProcess) { $ProcessInfo = "" | Select-Object Process, Name, Type; 
$ProcessInfo.Process = $runningProcess.ProcessName; $ProcessInfo.Name = $process.Name; $ProcessInfo.Type = 
$process.Type; $FoundProcesses += $ProcessInfo; } }; $FoundProcesses | Format-Table

Process                Name                        Type
-------                ----                        ----
avp                    Kaspersky                   AV

```

# How it Works
The program uses the CreateToolhelp32Snapshot function from the Windows API to obtain a list of all running processes on the system. It then compares the name of each process with a predefined list of known security software processes. If it finds a match, the program considers that security software is running on the system.

The list of security software processes is located in the main.cpp file in the securitySoftwareProcesses dictionary. You can add, remove, or modify entries in this dictionary as needed.
