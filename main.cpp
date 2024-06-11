#include <iostream>
#include <map>
#include <string>
#include <set>
#include <algorithm>
#include <Windows.h>
#include <tlhelp32.h>

#ifndef VERSION
#define VERSION "v1.9"
#endif


struct SecuritySoftware {
    std::string name;
    std::string type;
};

std::string toLower(const std::string& str) {
    std::string lowerCaseStr = str;
    std::transform(lowerCaseStr.begin(), lowerCaseStr.end(), lowerCaseStr.begin(), ::tolower);
    return lowerCaseStr;
}

bool isSecuritySoftwareRunning() {

    // SetConsoleOutputCP(1252); //Set console encoding to Windows 1252
    SetConsoleOutputCP(65001); //Set console encoding to utf8

    std::set<std::string> detectedProcesses;

    std::map<std::string, SecuritySoftware> securitySoftwareProcesses = {
            {"aciseagent.exe", {"Cisco Umbrella Roaming Security", "Security DNS"}},
            {"acnamagent.exe", {"Absolute Persistence", "Asset Management"}},
            {"acnamlogonagent.exe", {"Absolute Persistence", "Asset Management"}},
            {"acumbrellaagent.exe", {"Cisco Umbrella Roaming Security", "Security DNS"}},
            {"agmservice.exe", {"Adobe", "Telemetry"}},
            {"agsservice.exe", {"Adobe", "Telemetry"}},
            {"appcontrolagent.exe", {"Application Control", "Trend Micro"}},
            {"aswidsagent.exe", {"AV", "Avast"}},
            {"avastsvc.exe", {"AV", "Avast"}},
            {"avastui.exe", {"AV", "Avast"}},
            {"avgnt.exe", {"AV", "Avira"}},
            {"avguard.exe", {"AV", "Avira"}},
            {"avp.exe", {"AV", "Kaspersky"}},
            {"avpui.exe", {"AV", "Kaspersky"}},
            {"axcrypt.exe", {"AxCrypt", "Encryption"}},
            {"bdagent.exe", {"AV", "Bitdefender Total Security"}},
            {"bdntwrk.exe", {"AV", "Bitdefender"}},
            {"browserexploitdetection.exe", {"Exploit Detection", "Trend Micro"}},
            {"carbonsensor.exe", {"EDR", "VMware Carbon Black EDR"}},
            {"cbcomms.exe", {"CrowdStrike Falcon Insight XDR", "XDR"}},
            {"ccsvchst.exe", {"AV", "Norton Antivirus"}},
            {"ccsvchst.exe", {"AV", "Symantec Endpoint Protection"}},
            {"clientcommunicationservice.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"clientlogservice.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"clientsolutionframework.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"cmrcservice.exe", {"Microsoft Configuration Manager Remote Control Service","Remote Control"}},
            {"concentr.exe", {"Palo Alto Networks GlobalProtect", "VPN"}},
            {"coreserviceshell.exe", {"AV", "Trend Micro"}},
            {"cpd.exe", {"Check Point Daemon", "Security"}},
            {"cpx.exe", {"SentinelOne Singularity XDR", "XDR"}},
            {"csfalconcontainer.exe", {"CrowdStrike Falcon", "EDR"}},
            {"csfalcondaterepair.exe", {"CrowdStrike Falcon", "EDR"}},
            {"csfalconservice.exe", {"CrowdStrike Falcon Insight XDR", "XDR"}},
            {"cybereason.exe", {"Cybereason EDR", "EDR"}},
            {"cytomicendpoint.exe", {"Cytomic Orion", "Security"}},
            {"cyveraconsole.exe", {"EDR", "Palo Alto Networks (Cyvera)"}},
            {"cyveraservice.exe", {"EDR", "Palo Alto Networks (Cortex XDR)"}},
            {"cyvragentsvc.exe", {"EDR", "Palo Alto Networks (Cortex XDR)"}},
            {"cyvrfsflt.exe", {"EDR", "Palo Alto Networks (Cortex XDR)"}},
            {"darktracetsa.exe", {"Darktrace", "EDR"}},
            {"dataprotectionservice.exe", {"Data Protection", "Trend Micro"}},
            {"dlpagent.exe", {"DLP", "Symantec DLP Agent"}},
            {"dlpsensor.exe", {"DLP", "McAfee DLP Sensor"}},
            {"dsmonitor.exe", {"DriveSentry", "Security"}},
            {"dwengine.exe", {"DriveSentry", "Security"}},
            {"edpa.exe", {"AV", "McAfee Endpoint Security"}},
            {"eegoservice.exe", {"Encryption", "McAfee Endpoint Encryption"}},
            {"egui.exe", {"AV", "ESET NOD32 AV"}},
            {"ekrn.exe", {"AV", "ESET NOD32 AV"}},
            {"endpointbasecamp.exe", {"EDR", "Trend Micro"}},
            {"firesvc.exe", {"FireEye Endpoint Agent", "Security"}},
            {"firetray.exe", {"FireEye Endpoint Agent", "Security"}},
            {"fortiedr.exe", {"EDR", "FortiEDR"}},
            {"fw.exe", {"Check Point Firewall", "Firewall"}},
            {"healthservice.exe", {"Microsoft OMS", "Monitoring"}},
            {"hips.exe", {"HIPS", "Host Intrusion Prevention System"}},
            {"klwtblfs.exe", {"AV", "Kaspersky"}},
            {"klwtpwrs.srv", {"AV", "Kaspersky"}},
            {"kpf4ss.exe", {"Firewall", "Kerio Personal Firewall"}},
            {"ksde.exe", {"Kaspersky Secure Connection", "VPN"}},
            {"ksdeui.exe", {"Kaspersky Secure Connection", "VPN"}},
            {"macmnsvc.exe", {"AV", "McAfee Endpoint Security"}},
            {"masvc.exe", {"AV", "McAfee Endpoint Security"}},
            {"mbae64.sys", {"AV", "Malwarebytes"}},
            {"mbamagent.exe", {"AV", "Malwarebytes"}},
            {"mbamservice.exe", {"AV", "Malwarebytes"}},
            {"mbamswissarmy.sys", {"AV", "Malwarebytes"}},
            {"mbamtray.exe", {"AV", "Malwarebytes"}},
            {"mcshield.exe", {"AV", "McAfee VirusScan"}},
            {"mdecryptservice.exe", {"Encryption", "McAfee Endpoint Encryption"}},
            {"mdnsresponder.exe", {"Bonjour Service", "Network Service"}},
            {"mfeann.exe", {"AV", "McAfee"}},
            {"mfeepehost.exe", {"Encryption", "McAfee Endpoint Encryption"}},
            {"mfefire.exe", {"HIPS", "McAfee Host Intrusion Prevention"}},
            {"mfemactl.exe", {"Firewall", "McAfee Endpoint Security Firewall"}},
            {"mfemms.exe", {"AV", "McAfee"}},
            {"monitoringhost.exe", {"Microsoft Monitoring Agent", "Monitoring"}},
            {"mpdefendercoreservice.exe", {"AV", "Windows Defender"}},
            {"msascuil.exe", {"AV", "Windows Defender"}},
            {"msmpeng.exe", {"AV", "Windows Defender"}},
            {"msseces.exe", {"AV", "Microsoft Security Essentials"}},
            {"mssense.exe", {"Microsoft Defender ATP (Advanced Threat Protection)", "Security"}},
            {"mssense.exe", {"Microsoft Defender ATP", "Security"}},
            {"nissrv.exe", {"AV Network Inspection", "Microsoft Security Essentials"}},
            {"nortonsecurity.exe", {"AV", "Norton Antivirus"}},
            {"npmdagent.exe", {"Network Monitoring", "SolarWinds NPM"}},
            {"ns.exe", {"AV", "Norton Antivirus"}},
            {"nsservice.exe", {"AV", "Norton Antivirus"}},
            {"openvpnserv.exe", {"OpenVPN", "VPN"}},
            {"outpost.exe", {"Agnitum Outpost Firewall", "Firewall"}},
            {"panda_url_filtering.exe", {"AV", "Panda Security"}},
            {"pangps.exe", {"Palo Alto Networks GlobalProtect", "VPN"}},
            {"pavfnsvr.exe", {"AV", "Panda Security"}},
            {"pavsrv.exe", {"AV", "Panda Security"}},
            {"personalfirewallservice.exe", {"Firewall", "Trend Micro"}},
            {"psanhost.exe", {"AV", "Panda Security"}},
            {"realtimescanservice.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"rtvscan.exe", {"AV", "Symantec Endpoint Protection"}},
            {"samplingservice.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"savservice.exe", {"AV", "Sophos Endpoint Security"}},
            {"sbiesvc.exe", {"Sandboxie", "Security"}},
            {"securityagentmonitor.exe", {"Antivirus/EDR", "Trend Micro"}},
            {"securityhealthservice.exe",                    {"Security", "Windows Security Health Service"}},
            {"securityhealthservice.exe", {"Windows Security Health Service", "Security"}},
            {"securityhealthsystray.exe", {"Windows Security Systray", "Security"}},
            {"senseir.exe", {"Windows Defender IR", "Security"}},
            {"sensendr.exe", {"Windows Defender NDR", "Security"}},
            {"sensetvm.exe", {"Windows Defender TVM", "Security"}},
            {"sentinel.exe", {"EDR", "Unknown (Potential: Microsoft Defender)"}},
            {"sentinelagent.exe", {"EDR", "SentinelOne"}},
            {"sentinelagent.exe", {"SentinelOne", "EDR"}},
            {"sentinelctl.exe", {"EDR", "SentinelOne"}},
            {"sentinelmemoryscanner.exe", {"SentinelOne", "EDR"}},
            {"sentinelservicehost.exe", {"SentinelOne", "EDR"}},
            {"sentinelstaticengine.exe", {"SentinelOne", "EDR"}},
            {"sentinelstaticenginescanner.exe", {"SentinelOne", "EDR"}},
            {"sgrmbroker.exe", {"Windows Integrity Management", "System Integrity"}},
            {"shstat.exe", {"AV", "McAfee VirusScan"}},
            {"smsvchost.exe", {"Application", "Microsoft .NET Framework"}},
            {"sophosav.exe", {"AV", "Sophos Endpoint Security"}},
            {"sophosclean.exe", {"AV", "Sophos"}},
            {"sophoshealth.exe", {"AV", "Sophos"}},
            {"sophossps.exe", {"AV", "Sophos Endpoint Security"}},
            {"sophosui.exe", {"AV", "Sophos Endpoint Security"}},
            {"sysmon.exe", {"Microsoft Sysmon", "Security"}},
            {"sysmon64.exe", {"Microsoft Sysmon", "Security"}},
            {"tanclient.exe", {"EDR", "Tanium EDR"}},
            {"telemetryagentservice.exe", {"Telemetry", "Trend Micro"}},
            {"telemetryservice.exe", {"Telemetry", "Unknown"}},
            {"tmntsrv.exe", {"AV", "Trend Micro OfficeScan"}},
            {"tmproxy.exe", {"AV", "Trend Micro OfficeScan"}},
            {"traps.exe", {"EDR", "Palo Alto Networks (Cortex XDR)"}},
            {"trapsagent.exe", {"Palo Alto Networks Cortex XDR", "XDR"}},
            {"trapsd.exe", {"Palo Alto Networks Cortex XDR", "XDR"}},
            {"truecrypt.exe", {"Encryption", "TrueCrypt"}},
            {"uiwinmgr.exe", {"AV", "Trend Micro"}},
            {"updatesrv.exe", {"AV", "Bitdefender"}},
            {"vgauthservice.exe", {"VMware", "Virtualization"}},
            {"vm3dservice.exe", {"VMware", "Virtualization"}},
            {"vmtoolsd.exe", {"VMware", "Virtualization"}},
            {"vpnagent.exe", {"Cisco AnyConnect Secure Mobility Client", "VPN"}},
            {"vpnagent.exe", {"Cisco AnyConnect", "VPN"}},
            {"vpnui.exe", {"Cisco AnyConnect", "VPN"}},
            {"vsserv.exe", {"AV", "Bitdefender Total Security"}},
            {"vulnerabilityprotectionagent.exe",                    {"Trend Micro", "Vulnerability Protection"}},
            {"windefend.exe", {"AV", "Windows Defender"}},
            {"winlogbeat.exe", {"Elastic Winlogbeat", "Security"}},
            {"wireguard.exe", {"VPN", "WireGuard"}},
            {"wrsa.exe", {"AV", "Webroot Anywhere"}},
            {"wscservice.exe", {"Security Service", "Trend Micro"}},
            {"xagt.exe", {"FireEye HX", "Security"}},
    };

    bool found = false;

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return false;
    }

    do {
        std::string processName(pe32.szExeFile);
        std::string lowerCaseProcessName = toLower(processName);

        if (detectedProcesses.find(lowerCaseProcessName) == detectedProcesses.end()) {
            auto it = securitySoftwareProcesses.find(lowerCaseProcessName);
            if (it != securitySoftwareProcesses.end()) {
                found = true;
                std::cout << "Security Software detected: " << it->second.name << " (" << it->second.type << ") - Process: " << processName << std::endl;
                detectedProcesses.insert(lowerCaseProcessName);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return found;
}

int main() {
    std::cout << "AV_detect Version: " << VERSION << std::endl;
    if (isSecuritySoftwareRunning()) {
        std::cout << "\nFound security software process (AV, anti-malware, EDR, XDR, etc.) running." << std::endl;
    } else {
        std::cout << "\nNo security software processes (AV, anti-malware, EDR, XDR, etc.) were found running." << std::endl;
    }
    return 0;
}
