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

    SetConsoleOutputCP(1252); //Set console encoding to Windows 1252
    SetConsoleOutputCP(65001); //Set console encoding to utf8

    std::map<std::string, SecuritySoftware> securitySoftwareProcesses = {
            {"avastsvc.exe",            {"Avast",                            "AV"}},
            {"avastui.exe",             {"Avast",                            "AV"}},
            {"avgnt.exe",               {"Avira",                            "AV"}},
            {"avguard.exe",             {"Avira",                            "AV"}},
            {"avp.exe",                 {"Kaspersky",                        "AV"}},
            {"axcrypt.exe",             {"AxCrypt",                          "Encryption"}},
            {"bdagent.exe",             {"Bitdefender Total Security",       "AV"}},
            {"carbonsensor.exe",        {"VMware Carbon Black EDR",          "EDR"}},
            {"cbcomms.exe",             {"CrowdStrike Falcon Insight XDR",   "XDR"}},
            {"ccsvchst.exe",            {"Symantec Endpoint Protection",     "AV"}},
            {"cpd.exe",                 {"Check Point Daemon",               "Security"}},
            {"cpx.exe",                 {"SentinelOne Singularity XDR",      "XDR"}},
            {"csfalconservice.exe",     {"CrowdStrike Falcon Insight XDR",   "XDR"}},
            {"cybereason.exe",          {"Cybereason EDR",                   "EDR"}},
            {"cytomicendpoint.exe",     {"Cytomic Orion",                    "Security"}},
            {"dlpagent.exe",            {"Symantec DLP Agent",               "DLP"}},
            {"dlpsensor.exe",           {"McAfee DLP Sensor",                "DLP"}},
            {"dsmonitor.exe",           {"DriveSentry",                      "Security"}},
            {"dwengine.exe",            {"DriveSentry",                      "Security"}},
            {"edpa.exe",                {"McAfee Endpoint Security",         "AV"}},
            {"egui.exe",                {"ESET NOD32 AV",                    "AV"}},
            {"ekrn.exe",                {"ESET NOD32 AV",                    "AV"}},
            {"firesvc.exe",             {"FireEye Endpoint Agent",           "Security"}},
            {"firetray.exe",            {"FireEye Endpoint Agent",           "Security"}},
            {"fortiedr.exe",            {"FortiEDR",                         "EDR"}},
            {"fw.exe",                  {"Check Point Firewall",             "Firewall"}},
            {"hips.exe",                {"Host Intrusion Prevention System", "HIPS"}},
            {"kpf4ss.exe",              {"Kerio Personal Firewall",          "Firewall"}},
            {"mbamservice.exe",         {"Malwarebytes",                     "AV"}},
            {"mbamtray.exe",            {"Malwarebytes",                     "AV"}},
            {"mcshield.exe",            {"McAfee VirusScan",                 "AV"}},
            {"mfefire.exe",             {"McAfee Host Intrusion Prevention", "HIPS"}},
            {"msascuil.exe",            {"Windows Defender",                 "AV"}},
            {"msmpeng.exe",             {"Windows Defender",                 "AV"}},
            {"msseces.exe",             {"Microsoft Security Essentials",    "AV"}},
            {"nissrv.exe",              {"Microsoft Security Essentials",    "AV"}},
            {"outpost.exe",             {"Agnitum Outpost Firewall",         "Firewall"}},
            {"panda_url_filtering.exe", {"Panda Security",                   "AV"}},
            {"pavfnsvr.exe",            {"Panda Security",                   "AV"}},
            {"pavsrv.exe",              {"Panda Security",                   "AV"}},
            {"psanhost.exe",            {"Panda Security",                   "AV"}},
            {"rtvscan.exe",             {"Symantec Endpoint Protection",     "AV"}},
            {"savservice.exe",          {"Sophos Endpoint Security",         "AV"}},
            {"shstat.exe",              {"McAfee VirusScan",                 "AV"}},
            {"sophosav.exe",            {"Sophos Endpoint Security",         "AV"}},
            {"sophossps.exe",           {"Sophos Endpoint Security",         "AV"}},
            {"sophosui.exe",            {"Sophos Endpoint Security",         "AV"}},
            {"sysmon.exe",              {"Microsoft Sysmon",                  "Security"}},
            {"tanclient.exe",           {"Tanium EDR",                       "EDR"}},
            {"tmntsrv.exe",             {"Trend Micro OfficeScan",           "AV"}},
            {"tmproxy.exe",             {"Trend Micro OfficeScan",           "AV"}},
            {"trapsagent.exe",          {"Palo Alto Networks Cortex XDR",    "XDR"}},
            {"trapsd.exe",              {"Palo Alto Networks Cortex XDR",    "XDR"}},
            {"truecrypt.exe",           {"TrueCrypt",                        "Encryption"}},
            {"vsserv.exe",              {"Bitdefender Total Security",       "AV"}},
            {"wrsa.exe",                {"Webroot Anywhere",                         "AV"}},
            {"windefend.exe",           {"Windows Defender",                 "AV"}},
            {"xagt.exe",                {"FireEye HX",                       "Security"}}
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
            std::cout << "Security Software detected: " << it->second.name << " (" << it->second.type << ")" << std::endl;
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
