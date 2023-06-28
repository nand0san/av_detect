#include <iostream>
#include <map>
#include <string>
#include <algorithm>
#include <Windows.h>
#include <tlhelp32.h>


struct SecuritySoftware {
    std::string name;
    std::string type;
};


bool isSecuritySoftwareRunning() {

    // SetConsoleOutputCP(1252); //Set console encoding to Windows 1252
    SetConsoleOutputCP(65001); //Set console encoding to utf8

    std::map<std::string, SecuritySoftware> securitySoftwareProcesses = {
            {"SentinelAgent.exe",       {"SentinelOne",                      "EDR"}},
            {"SentinelCtl.exe",         {"SentinelOne",                      "EDR"}},
            {"SophosClean.exe",         {"Sophos",                           "AV"}},
            {"SophosHealth.exe",        {"Sophos",                           "AV"}},
            {"aciseagent.exe", 		   {"Cisco Umbrella Roaming Security", 					"Security"}},
            {"acumbrellaagent.exe",     {"Cisco Umbrella Roaming Security", 					"Security"}},
            {"aswidsagent.exe",         {"Avast",                            "AV"}},
            {"avastsvc.exe",            {"Avast",                            "AV"}},
            {"avastui.exe",             {"Avast",                            "AV"}},
            {"avgnt.exe",               {"Avira",                            "AV"}},
            {"avguard.exe",             {"Avira",                            "AV"}},
            {"avp.exe",                 {"Kaspersky",                        "AV"}},
            {"avpui.exe",		       {"Kaspersky",						"AV"}},
            {"axcrypt.exe",             {"AxCrypt",                          "Encryption"}},
            {"bdagent.exe",             {"Bitdefender Total Security",       "AV"}},
            {"bdntwrk.exe",             {"Bitdefender",                      "AV"}},
            {"carbonsensor.exe",        {"VMware Carbon Black EDR",          "EDR"}},
            {"cbcomms.exe",             {"CrowdStrike Falcon Insight XDR",   "XDR"}},
            {"ccsvchst.exe",            {"Symantec Endpoint Protection",     "AV"}},
            {"coreServiceShell.exe",    {"Trend Micro",                      "AV"}},
            {"cpd.exe",                 {"Check Point Daemon",               "Security"}},
            {"cpx.exe",                 {"SentinelOne Singularity XDR",      "XDR"}},
            {"csfalconcontainer.exe",   {"CrowdStrike Falcon",               "EDR"}},
            {"csfalcondaterepair.exe",  {"CrowdStrike Falcon",               "EDR"}},
            {"csfalconservice.exe",     {"CrowdStrike Falcon Insight XDR",   "XDR"}},
            {"cybereason.exe",          {"Cybereason EDR",                   "EDR"}},
            {"cytomicendpoint.exe",     {"Cytomic Orion",                    "Security"}},
            {"dlpagent.exe",            {"Symantec DLP Agent",               "DLP"}},
            {"dlpsensor.exe",           {"McAfee DLP Sensor",                "DLP"}},
            {"dsmonitor.exe",           {"DriveSentry",                      "Security"}},
            {"dwengine.exe",            {"DriveSentry",                      "Security"}},
            {"edpa.exe",                {"McAfee Endpoint Security",         "AV"}},
            {"eegoservice.exe", 	       {"McAfee Endpoint Encryption", 				"Encryption"}},
            {"egui.exe",                {"ESET NOD32 AV",                    "AV"}},
            {"ekrn.exe",                {"ESET NOD32 AV",                    "AV"}},
            {"firesvc.exe",             {"FireEye Endpoint Agent",           "Security"}},
            {"firetray.exe",            {"FireEye Endpoint Agent",           "Security"}},
            {"fortiedr.exe",            {"FortiEDR",                         "EDR"}},
            {"fw.exe",                  {"Check Point Firewall",             "Firewall"}},
            {"hips.exe",                {"Host Intrusion Prevention System", "HIPS"}},
            {"klwtblfs.exe",            {"Kaspersky",                        "AV"}},
            {"klwtpwrs.srv",            {"Kaspersky",                        "AV"}},
            {"kpf4ss.exe",              {"Kerio Personal Firewall",          "Firewall"}},
            {"ksde.exe", 		       {"Kaspersky Secure Connection",		"VPN"}},
            {"ksdeui.exe", 		       {"Kaspersky Secure Connection", 	"VPN"}},
            {"macmnsvc.exe", 		   {"McAfee Endpoint Security",				"AV"}},
            {"masvc.exe", 			   {"McAfee Endpoint Security",     			"AV"}},
            {"mbae64.sys",              {"Malwarebytes",                     "AV"}},
            {"mbamservice.exe",         {"Malwarebytes",                     "AV"}},
            {"mbamswissarmy.sys",       {"Malwarebytes",                     "AV"}},
            {"mbamtray.exe",            {"Malwarebytes",                     "AV"}},
            {"mcshield.exe",            {"McAfee VirusScan",                 "AV"}},
            {"mdecryptservice.exe",     {"McAfee Endpoint Encryption", 				"Encryption"}},
            {"mfeann.exe",              {"McAfee",                           "AV"}},
            {"mfeepehost.exe", 		   {"McAfee Endpoint Encryption", 				"Encryption"}},
            {"mfefire.exe",             {"McAfee Host Intrusion Prevention", "HIPS"}},
            {"mfemactl.exe", 		   {"McAfee Endpoint Security Firewall", 					"Firewall"}},
            {"mfemms.exe",              {"McAfee",                           "AV"}},
            {"msascuil.exe",            {"Windows Defender",                 "AV"}},
            {"msmpeng.exe",             {"Windows Defender",                 "AV"}},
            {"msseces.exe",             {"Microsoft Security Essentials",    "AV"}},
            {"mssense.exe", 		       {"Microsoft Defender ATP (Advanced Threat Protection)",	"Security"}},
            {"nissrv.exe",              {"Microsoft Security Essentials",    "AV"}},
            {"nortonsecurity.exe",      {"Norton Antivirus",                 "AV"}},
            {"ns.exe",                  {"Norton Antivirus",                 "AV"}},
            {"nsservice.exe",           {"Norton Antivirus",                 "AV"}},
            {"openvpnserv.exe",         {"OpenVPN", 						"VPN"}},
            {"outpost.exe",             {"Agnitum Outpost Firewall",         "Firewall"}},
            {"panda_url_filtering.exe", {"Panda Security",                   "AV"}},
            {"pangps.exe", 			   {"Palo Alto Networks GlobalProtect",		"VPN"}},
            {"pavfnsvr.exe",            {"Panda Security",                   "AV"}},
            {"pavsrv.exe",              {"Panda Security",                   "AV"}},
            {"psanhost.exe",            {"Panda Security",                   "AV"}},
            {"rtvscan.exe",             {"Symantec Endpoint Protection",     "AV"}},
            {"savservice.exe",          {"Sophos Endpoint Security",         "AV"}},
            {"sbiesvc.exe", 	           {"Sandboxie", 						"Security"}},
            {"shstat.exe",              {"McAfee VirusScan",                 "AV"}},
            {"sophosav.exe",            {"Sophos Endpoint Security",         "AV"}},
            {"sophossps.exe",           {"Sophos Endpoint Security",         "AV"}},
            {"sophosui.exe",            {"Sophos Endpoint Security",         "AV"}},
            {"sysmon.exe",              {"Microsoft Sysmon",                  "Security"}},
            {"sysmon64.exe", 	       {"Microsoft Sysmon", 				"Security"}},
            {"tanclient.exe",           {"Tanium EDR",                       "EDR"}},
            {"tmntsrv.exe",             {"Trend Micro OfficeScan",           "AV"}},
            {"tmproxy.exe",             {"Trend Micro OfficeScan",           "AV"}},
            {"trapsagent.exe",          {"Palo Alto Networks Cortex XDR",    "XDR"}},
            {"trapsd.exe",              {"Palo Alto Networks Cortex XDR",    "XDR"}},
            {"truecrypt.exe",           {"TrueCrypt",                        "Encryption"}},
            {"uiWinMgr.exe",            {"Trend Micro",                      "AV"}},
            {"updatesrv.exe",           {"Bitdefender",                      "AV"}},
            {"vpnagent.exe",		       {"Cisco AnyConnect Secure Mobility Client","VPN"}},
            {"vsserv.exe",              {"Bitdefender Total Security",       "AV"}},
            {"windefend.exe",           {"Windows Defender",                 "AV"}},
            {"winlogbeat.exe", 	       {"Elastic Winlogbeat", 				"Security"}},
            {"wireguard.exe", 	       {"WireGuard", 						"VPN"}},
            {"wrsa.exe",                {"Webroot Anywhere",                 "AV"}},
            {"xagt.exe",                {"FireEye HX",                       "Security"}},
            {"concentr.exe",               {"Palo Alto Networks GlobalProtect",       "VPN"}},
            {"CyveraConsole.exe",          {"Palo Alto Networks (Cyvera)",            "EDR"}},
            {"DarktraceTSA.exe",           {"Darktrace",                              "EDR"}},
            {"TelemetryService.exe",       {"Unknown",                                "Telemetry"}},
            {"Sentinel.exe",               {"Unknown (Potential: Microsoft Defender)","EDR"}},
            {"AGMService.exe",             {"Adobe",                                  "Telemetry"}},
            {"AGSService.exe",             {"Adobe",                                  "Telemetry"}},
            {"vm3dservice.exe",            {"VMware",                                 "Virtualization"}},
            {"vmtoolsd.exe",               {"VMware",                                 "Virtualization"}},
            {"VGAuthService.exe",          {"VMware",                                 "Virtualization"}},

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
        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

        auto it = securitySoftwareProcesses.find(processName);
        if (it != securitySoftwareProcesses.end()) {
            found = true;
            std::cout << "Security Software detected: " << it->second.name << " (" << it->second.type << ") - Process: " << processName << std::endl;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return found;
}

int main() {
    if (isSecuritySoftwareRunning()) {
        std::cout << std::endl << "There is a security software process (AV, antimalware, EDR, XDR, etc.) running." << std::endl;
    } else {
        std::cout << std::endl << "No security software processes (AV, antimalware, EDR, XDR, etc.) were found running." << std::endl;
    }
    return 0;
}
