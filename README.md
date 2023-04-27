# Security Software Detector
This program detects if any security software (AV, EDR, XDR, firewall, etc.) is running on the system. The program searches the list of running processes and compares their names with a predefined list of known security software processes.

# Requirements
A C++11 or later compatible compiler.
Windows as the operating system.

# Compilation
Open a terminal or command prompt.
Navigate to the directory where the main.cpp file is located.
Compile the program using CLion, also a C++11 or later compatible compiler. For example, to compile with g++, execute the following command:
```
g++ -std=c++11 -o av_detect main.cpp
```
This will create an executable file named av_detect.exe in the same directory.

# Detected Apps
- Agnitum Outpost Firewall - Firewall
- Avast - AV
- Avira - AV
- AxCrypt - Encryption
- Bitdefender Total Security - AV
- Check Point Daemon - Security
- Check Point Firewall - Firewall
- CrowdStrike Falcon Insight XDR - XDR
- Cybereason EDR - EDR
- Cytomic Orion - Security
- DriveSentry - Security
- ESET NOD32 AV - AV
- FireEye Endpoint Agent - Security
- FireEye HX - Security
- FortiEDR - EDR
- Host Intrusion Prevention System - HIPS
- Kaspersky - AV
- Kerio Personal Firewall - Firewall
- Malwarebytes - AV
- McAfee DLP Sensor - DLP
- McAfee Endpoint Security - AV
- McAfee Host Intrusion Prevention - HIPS
- McAfee VirusScan - AV
- Microsoft Security Essentials - AV
- Microsoft Sysmon - Security
- Palo Alto Networks Cortex XDR - XDR
- Panda Security - AV
- SentinelOne Singularity XDR - XDR
- Sophos Endpoint Security - AV
- Symantec DLP Agent - DLP
- Symantec Endpoint Protection - AV
- Tanium EDR - EDR
- Trend Micro OfficeScan - AV
- TrueCrypt - Encryption
- VMware Carbon Black EDR - EDR
- Webroot Anywhere - AV
- Windows Defender - AV

# Usage
Execute the compiled program in a terminal or command prompt. The program will show if any security software is detected running on the system.

```
./av_detect.exe
```
The program will display "Security software is running." if any security software is detected, and "No security software detected." otherwise.

![img.png](img.png)

# Alternative usage using only PowerShell, without using the executable

You can use a PowerShell command to directly interact with the CSV hosted on GitHub, without the need to download the project or compile it.

```
$Url="https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv"; $ProcessesCSV = Invoke-WebRequest -Uri $Url | ConvertFrom-Csv; $RunningProcesses = Get-Process; $FoundProcesses = @(); foreach ($process in $ProcessesCSV) { $runningProcess = $RunningProcesses | Where-Object { $_.ProcessName -like $process.Process.Replace('.exe','') }; if ($runningProcess) { $FoundProcesses += [PSCustomObject]@{'Process' = $runningProcess.ProcessName; 'Name' = $process.Name; 'Type' = $process.Type; } } }; $FoundProcesses | Format-Table
```

![img_pwrshll.png](img_pwrshll.png)

### Decteting proxy version
Not tested on corporate systems yet.
```
$Url="https://raw.githubusercontent.com/nand0san/av_detect/main/processes.csv"; $WebRequestSession=New-Object Microsoft.PowerShell.Commands.WebRequestSession; if ($env:HTTP_PROXY -or $env:http_proxy) { $Proxy=$env:HTTP_PROXY -or $env:http_proxy; $WebRequestSession.Proxy=[System.Net.WebRequest]::GetSystemWebProxy(); $WebRequestSession.Proxy.Credentials=[System.Net.CredentialCache]::DefaultCredentials; }; $ProcessesCSV=Invoke-WebRequest -Uri $Url -WebSession $WebRequestSession | ConvertFrom-Csv; $RunningProcesses=Get-Process; $FoundProcesses=@(); foreach ($process in $ProcessesCSV) { $runningProcess=$RunningProcesses|Where-Object {$_.ProcessName -like $process.Process.Replace('.exe','')}; if ($runningProcess) { $FoundProcesses+=[PSCustomObject]@{'Process'=$runningProcess.ProcessName;'Name'=$process.Name;'Type'=$process.Type}; }; }; $FoundProcesses|Format-Table
```
# How it Works
The program uses the CreateToolhelp32Snapshot function from the Windows API to obtain a list of all running processes on the system. It then compares the name of each process with a predefined list of known security software processes. If it finds a match, the program considers that security software is running on the system.

The list of security software processes is located in the main.cpp file in the securitySoftwareProcesses dictionary. You can add, remove, or modify entries in this dictionary as needed.