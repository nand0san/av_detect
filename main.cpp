#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <Windows.h>
#include <tlhelp32.h>

#ifndef VERSION
#define VERSION "v2.00"
#endif

struct SecuritySoftware {
    std::string name;  // Producto / Descripción humana
    std::string type;  // Categoría (AV, EDR, XDR, VPN, etc.)
};

/**
 * @brief toLower
 * Normaliza un std::string a minúsculas ASCII.
 */
static std::string toLower(const std::string& str) {
    std::string out = str;
    std::transform(
            out.begin(),
            out.end(),
            out.begin(),
            [](unsigned char c){ return static_cast<char>(::tolower(c)); }
    );
    return out;
}

/**
 * @brief isSecuritySoftwareRunning
 * Enumera procesos vivos y cruza con lista de binarios conocidos
 * de AV / EDR / VPN corporativa / telemetría / DLP / gestión IR.
 *
 * @return true si se detecta al menos un binario interesante.
 */
bool isSecuritySoftwareRunning() {

    // Consola en UTF-8
    SetConsoleOutputCP(65001);

    // Para evitar imprimir el mismo proceso varias veces
    std::unordered_set<std::string> detectedProcesses;

    // Diccionario proceso -> lista de posibles productos
    // NOTA: claves SIEMPRE en minúsculas.
    const std::unordered_map<std::string, std::vector<SecuritySoftware>> securitySoftwareProcesses = {

            // --- Cisco / Zscaler / VPN / Proxy / SASE ---
            {"vpnagent.exe", {
                                     {"Cisco AnyConnect Secure Mobility Client", "VPN"},
                                     {"Cisco AnyConnect", "VPN"}
                             }},
            {"vpnui.exe", {
                                     {"Cisco AnyConnect", "VPN"}
                             }},
            {"concentr.exe", {
                                     {"Palo Alto Networks GlobalProtect", "VPN"}
                             }},
            {"pangps.exe", {
                                     {"Palo Alto Networks GlobalProtect", "VPN"}
                             }},
            {"fortitray.exe", {
                                     {"Fortinet FortiClient / FortiTray (System Tray Controller)", "VPN / Endpoint Security"}
                             }},
            {"fortivpn.exe", {
                                     {"Fortinet FortiClient VPN", "VPN"}
                             }},
            {"zsatray.exe", {
                                     {"Zscaler Client Connector (Zscaler ZTNA / Secure Web Gateway)", "Proxy / CASB / ZTNA"}
                             }},
            {"zsatraymanager.exe", {
                                     {"Zscaler Client Connector (privileged service)", "Proxy / CASB / ZTNA"}
                             }},
            {"ksde.exe", {
                                     {"Kaspersky Secure Connection", "VPN"}
                             }},
            {"ksdeui.exe", {
                                     {"Kaspersky Secure Connection", "VPN"}
                             }},
            {"wireguard.exe", {
                                     {"WireGuard", "VPN"}
                             }},
            {"openvpnserv.exe", {
                                     {"OpenVPN", "VPN"}
                             }},

            // --- CrowdStrike Falcon ---
            {"csfalconservice.exe", {
                                     {"CrowdStrike Falcon Sensor", "EDR / XDR"}
                             }},
            {"csfalconcontainer.exe", {
                                     {"CrowdStrike Falcon Sensor Container", "EDR / XDR"}
                             }},
            {"csfalcondaterepair.exe", {
                                     {"CrowdStrike Falcon Repair Component", "EDR / XDR"}
                             }},

            // --- Microsoft Defender / MDE ---
            {"msmpeng.exe", {
                                     {"Microsoft Defender Antivirus Engine", "AV"}
                             }},
            {"mssense.exe", {
                                     {"Microsoft Defender for Endpoint (MDE / ATP)", "EDR"}
                             }},
            {"senseir.exe", {
                                     {"Microsoft Defender IR component", "Security / IR"}
                             }},
            {"sensendr.exe", {
                                     {"Microsoft Defender NDR component", "Security / NDR"}
                             }},
            {"sensetvm.exe", {
                                     {"Microsoft Defender TVM (Threat & Vulnerability Mgmt)", "Vuln Mgmt"}
                             }},
            {"mpdefendercoreservice.exe", {
                                     {"Microsoft Defender Core Service", "AV"}
                             }},
            {"windefend.exe", {
                                     {"Microsoft Defender AV Service", "AV"}
                             }},
            {"msascuil.exe", {
                                     {"Windows Defender UI", "AV UI"}
                             }},
            {"securityhealthservice.exe", {
                                     {"Windows Security Health Service", "Security / Health"}
                             }},
            {"securityhealthsystray.exe", {
                                     {"Windows Security Systray", "Security / Health"}
                             }},

            // --- Sysmon (telemetría avanzada) ---
            {"sysmon.exe", {
                                     {"Microsoft Sysmon", "Security Telemetry"}
                             }},
            {"sysmon64.exe", {
                                     {"Microsoft Sysmon (64-bit)", "Security Telemetry"}
                             }},

            // --- SentinelOne ---
            {"sentinelagent.exe", {
                                     {"SentinelOne Agent", "EDR / XDR"}
                             }},
            {"sentinelctl.exe", {
                                     {"SentinelOne Control CLI", "EDR / XDR"}
                             }},
            {"sentinelservicehost.exe", {
                                     {"SentinelOne Service Host", "EDR / XDR"}
                             }},
            {"sentinelstaticengine.exe", {
                                     {"SentinelOne Static Engine", "EDR / XDR"}
                             }},
            {"sentinelstaticenginescanner.exe", {
                                     {"SentinelOne Static Engine Scanner", "EDR / XDR"}
                             }},
            {"sentinelmemoryscanner.exe", {
                                     {"SentinelOne Memory Scanner", "EDR / XDR"}
                             }},

            // --- Palo Alto Networks Cortex XDR (antes Traps / Cyvera) ---
            {"cyserver.exe", {
                                     {"Palo Alto Networks Cortex XDR Agent (protected service)", "EDR / XDR"}
                             }},
            {"cyveraconsole.exe", {
                                     {"Palo Alto Networks Cortex XDR Console", "EDR / XDR"}
                             }},
            {"cyveraservice.exe", {
                                     {"Palo Alto Networks Cortex XDR Service (legacy CyveraService)", "EDR / XDR"}
                             }},
            {"cyvragentsvc.exe", {
                                     {"Palo Alto Networks Cortex XDR Agent Service", "EDR / XDR"}
                             }},
            {"cyvrfsflt.exe", {
                                     {"Palo Alto Networks Cortex XDR FS Filter", "EDR / XDR"}
                             }},
            {"traps.exe", {
                                     {"Palo Alto Networks Cortex XDR (Traps)", "EDR / XDR"}
                             }},
            {"trapsagent.exe", {
                                     {"Palo Alto Networks Cortex XDR (Traps Agent)", "EDR / XDR"}
                             }},
            {"trapsd.exe", {
                                     {"Palo Alto Networks Cortex XDR Daemon", "EDR / XDR"}
                             }},

            // --- Elastic (Elastic Defend / Elastic Agent) ---
            {"elastic-endpoint.exe", {
                                     {"Elastic Defend / Elastic Endpoint", "EDR / Telemetry"}
                             }},
            {"endpoint-security.exe", {
                                     {"Elastic Endpoint Security Component", "EDR / Telemetry"}
                             }},
            {"elastic-agent.exe", {
                                     {"Elastic Agent (Fleet / telemetry / security)", "EDR / Telemetry / UEM"}
                             }},

            // --- Tanium ---
            {"taniumclient.exe", {
                                     {"Tanium Client (IR / EDR / Asset Visibility)", "EDR / Asset Mgmt / IR"}
                             }},
            {"tanclient.exe", {
                                     {"Tanium EDR Client (legacy name)", "EDR / IR"}
                             }},

            // --- Rapid7 Insight Agent ---
            {"ir_agent.exe", {
                                     {"Rapid7 Insight Agent", "EDR / Vulnerability / IR"}
                             }},

            // --- Qualys Cloud Agent ---
            {"qualysagent.exe", {
                                     {"Qualys Cloud Agent", "Vuln Mgmt / Compliance"}
                             }},
            {"qualysagentui.exe", {
                                     {"Qualys Cloud Agent UI", "Vuln Mgmt / Compliance"}
                             }},

            // --- Trend Micro / Apex One / OfficeScan ---
            {"tmlisten.exe", {
                                     {"Trend Micro AV / Apex One Core", "AV / EDR"}
                             }},
            {"ntrtscan.exe", {
                                     {"Trend Micro Real-Time Scan Engine", "AV / EDR"}
                             }},
            {"tmproxy.exe", {
                                     {"Trend Micro Network Traffic Scanner / Proxy filter", "AV / Network Filter"}
                             }},
            {"tmntsrv.exe", {
                                     {"Trend Micro OfficeScan / Apex One Service", "AV / EDR"}
                             }},
            {"tmproxy.exe", {
                                     {"Trend Micro OfficeScan Proxy", "AV / Network Filter"}
                             }},
            {"personalfirewallservice.exe", {
                                     {"Trend Micro Personal Firewall", "Firewall"}
                             }},
            {"coreserviceshell.exe", {
                                     {"Trend Micro Core Service Shell", "AV / EDR"}
                             }},
            {"clientcommunicationservice.exe", {
                                     {"Trend Micro Client Communication Service", "AV / EDR"}
                             }},
            {"clientlogservice.exe", {
                                     {"Trend Micro Client Log Service", "AV / EDR"}
                             }},
            {"clientsolutionframework.exe", {
                                     {"Trend Micro Client Solution Framework", "AV / EDR"}
                             }},
            {"endpointbasecamp.exe", {
                                     {"Trend Micro Endpoint Basecamp", "EDR"}
                             }},
            {"realtimescanservice.exe", {
                                     {"Trend Micro RealTime Scan Service", "AV / EDR"}
                             }},
            {"samplingservice.exe", {
                                     {"Trend Micro Sampling Service", "AV / EDR"}
                             }},
            {"telemetryagentservice.exe", {
                                     {"Trend Micro Telemetry Agent Service", "Telemetry"}
                             }},
            {"telemetryservice.exe", {
                                     {"Trend Micro Telemetry Service", "Telemetry"}
                             }},
            {"vulnerabilityprotectionagent.exe", {
                                     {"Trend Micro Vulnerability Protection Agent", "Vuln Mgmt"}
                             }},
            {"wscservice.exe", {
                                     {"Trend Micro Security Service", "AV / EDR"}
                             }},

            // --- McAfee / Trellix ---
            {"macmnsvc.exe", {
                                     {"McAfee Agent Common Service", "AV / EDR"}
                             }},
            {"masvc.exe", {
                                     {"McAfee Agent Service", "AV / EDR"}
                             }},
            {"mfemms.exe", {
                                     {"McAfee Endpoint Security / McAfee Management Service", "AV / EDR"}
                             }},
            {"mfefire.exe", {
                                     {"McAfee Host Intrusion Prevention / Firewall", "HIPS / Firewall"}
                             }},
            {"mfemactl.exe", {
                                     {"McAfee Endpoint Security Firewall Controller", "Firewall"}
                             }},
            {"mcshield.exe", {
                                     {"McAfee VirusScan / On-Access Scanner", "AV"}
                             }},
            {"shstat.exe", {
                                     {"McAfee VirusScan Status Monitor", "AV UI"}
                             }},
            {"edpa.exe", {
                                     {"McAfee Endpoint Security / DLP Agent", "AV / DLP"}
                             }},
            {"dlpsensor.exe", {
                                     {"McAfee DLP Sensor", "DLP"}
                             }},
            {"mfeepehost.exe", {
                                     {"McAfee Endpoint Encryption Host", "Disk Encryption"}
                             }},
            {"mdecryptservice.exe", {
                                     {"McAfee Endpoint Encryption Decrypt Service", "Disk Encryption"}
                             }},

            // --- Symantec / Broadcom / Norton ---
            {"ccsvchst.exe", {
                                     {"Symantec Endpoint Protection / Norton Security", "AV / EDR"}
                             }},
            {"rtvscan.exe", {
                                     {"Symantec Endpoint Protection", "AV"}
                             }},
            {"dlpagent.exe", {
                                     {"Symantec DLP Agent", "DLP"}
                             }},
            {"nortonsecurity.exe", {
                                     {"Norton Security", "AV"}
                             }},
            {"ns.exe", {
                                     {"Norton Security", "AV"}
                             }},
            {"nsservice.exe", {
                                     {"Norton Security Service", "AV"}
                             }},

            // --- Sophos ---
            {"savservice.exe", {
                                     {"Sophos Endpoint Security / SAVService", "AV / EDR"}
                             }},
            {"sophosav.exe", {
                                     {"Sophos Endpoint AV", "AV"}
                             }},
            {"sophosclean.exe", {
                                     {"Sophos Clean", "AV / Remediation"}
                             }},
            {"sophoshealth.exe", {
                                     {"Sophos Health", "AV / Telemetry"}
                             }},
            {"sophossps.exe", {
                                     {"Sophos SophosSps (Exploit Mitigation / Sophos Endpoint Defense)", "EDR / Exploit Guard"}
                             }},
            {"sophosui.exe", {
                                     {"Sophos UI", "AV UI"}
                             }},

            // --- Kaspersky ---
            {"avp.exe", {
                                     {"Kaspersky AV / Kaspersky Endpoint Security", "AV / EDR"}
                             }},
            {"avpui.exe", {
                                     {"Kaspersky UI", "AV UI"}
                             }},
            {"klwtblfs.exe", {
                                     {"Kaspersky", "AV / File System Filter"}
                             }},

            // --- ESET ---
            {"egui.exe", {
                                     {"ESET NOD32 / ESET Endpoint Security GUI", "AV UI"}
                             }},
            {"ekrn.exe", {
                                     {"ESET NOD32 / ESET Endpoint Security Kernel Service", "AV / EDR"}
                             }},

            // --- Bitdefender ---
            {"bdagent.exe", {
                                     {"Bitdefender Total Security Agent", "AV"}
                             }},
            {"bdntwrk.exe", {
                                     {"Bitdefender Network Protection", "AV / Network"}
                             }},
            {"updatesrv.exe", {
                                     {"Bitdefender Update Service", "AV"}
                             }},
            {"vsserv.exe", {
                                     {"Bitdefender Virus Shield Service", "AV"}
                             }},

            // --- Avast / AVG / Panda / Webroot / etc. ---
            {"aswidsagent.exe", {
                                     {"Avast IDS Agent", "AV / IDS"}
                             }},
            {"avastsvc.exe", {
                                     {"Avast AV Service", "AV"}
                             }},
            {"avastui.exe", {
                                     {"Avast UI", "AV UI"}
                             }},
            {"avgnt.exe", {
                                     {"Avira AV Guard UI", "AV UI"}
                             }},
            {"avguard.exe", {
                                     {"Avira AV Guard", "AV"}
                             }},
            {"pavsrv.exe", {
                                     {"Panda Security AV Service", "AV"}
                             }},
            {"pavfnsvr.exe", {
                                     {"Panda AV File Name Server", "AV"}
                             }},
            {"psanhost.exe", {
                                     {"Panda Security Advanced Protection Host", "AV / EDR"}
                             }},
            {"panda_url_filtering.exe", {
                                     {"Panda URL Filtering", "Web Filter"}
                             }},
            {"wrsa.exe", {
                                     {"Webroot SecureAnywhere", "AV / EDR"}
                             }},

            // --- FireEye / Trellix HX ---
            {"xagt.exe", {
                                     {"FireEye Endpoint Agent / Trellix HX Agent", "EDR / IR"}
                             }},
            {"firesvc.exe", {
                                     {"FireEye Endpoint Agent Service", "EDR / IR"}
                             }},
            {"firetray.exe", {
                                     {"FireEye Endpoint Agent Tray", "EDR / IR"}
                             }},

            // --- Check Point / Others ---
            {"fw.exe", {
                                     {"Check Point Firewall", "Firewall"}
                             }},
            {"cpd.exe", {
                                     {"Check Point Daemon", "Security"}
                             }},

            // --- Trend Micro Application Control / HIPS ---
            {"appcontrolagent.exe", {
                                     {"Trend Micro Application Control Agent", "Application Control"}
                             }},
            {"hips.exe", {
                                     {"Host Intrusion Prevention System", "HIPS"}
                             }},

            // --- Data Loss Prevention / cifrado disco / control acceso ---
            {"dlpsensor.exe", {
                                     {"McAfee DLP Sensor", "DLP"}
                             }},
            {"dlpagent.exe", {
                                     {"Symantec DLP Agent", "DLP"}
                             }},
            {"axcrypt.exe", {
                                     {"AxCrypt", "Encryption"}
                             }},
            {"truecrypt.exe", {
                                     {"TrueCrypt", "Encryption"}
                             }},
            {"eegoservice.exe", {
                                     {"McAfee Endpoint Encryption Service", "Disk Encryption"}
                             }},

            // --- Monitoring / Telemetry corporativa ---
            {"healthservice.exe", {
                                     {"Microsoft OMS / SCOM HealthService", "Monitoring"}
                             }},
            {"monitoringhost.exe", {
                                     {"Microsoft Monitoring Agent", "Monitoring"}
                             }},
            {"npmdagent.exe", {
                                     {"SolarWinds NPM Agent", "Network Monitoring"}
                             }},

            // --- VMware guest tools (útil para saber si estás en VM) ---
            {"vgauthservice.exe", {
                                     {"VMware VGAuthService", "Virtualization / Guest Tools"}
                             }},
            {"vm3dservice.exe", {
                                     {"VMware 3D Service", "Virtualization / Guest Tools"}
                             }},
            {"vmtoolsd.exe", {
                                     {"VMware Tools Daemon", "Virtualization / Guest Tools"}
                             }},

            // --- Beats varios de Windows Defender avanzado ---
            {"sgrmbroker.exe", {
                                     {"Windows System Guard Runtime Monitor Broker", "System Integrity"}
                             }},
            {"securityhealthservice.exe", {
                                     {"Windows Security Health Service", "Security / Health"}
                             }},
            {"securityhealthsystray.exe", {
                                     {"Windows Security Systray", "Security / Health"}
                             }},

            // --- Otros heredados que ya tenías ---
            {"cmrcservice.exe", {
                                     {"Microsoft Configuration Manager Remote Control Service", "Remote Control"}
                             }},
            {"sbiesvc.exe", {
                                     {"Sandboxie Service", "Sandbox / Isolation"}
                             }},
            {"winlogbeat.exe", {
                                     {"Elastic Winlogbeat (log forwarder)", "Security Telemetry"}
                             }},
            {"mdnsresponder.exe", {
                                     {"Bonjour Service", "Network Service / mDNS"}
                             }},
            {"smsvchost.exe", {
                                     {"Microsoft .NET Framework service host", "Application"}
                             }}
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

        // ¿ya se reportó este proceso?
        if (detectedProcesses.find(lowerCaseProcessName) == detectedProcesses.end()) {

            auto it = securitySoftwareProcesses.find(lowerCaseProcessName);
            if (it != securitySoftwareProcesses.end()) {
                found = true;

                // imprime TODAS las asociaciones conocidas
                for (const auto& sw : it->second) {
                    std::cout
                            << "Security Software detected: "
                            << sw.name
                            << " (" << sw.type << ")"
                            << " - Process: " << processName
                            << std::endl;
                }

                // marca como ya reportado para no repetir
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
        std::cout
                << "\nFound security software process (AV, anti-malware, EDR, XDR, etc.) running."
                << std::endl;
    } else {
        std::cout
                << "\nNo security software processes (AV, anti-malware, EDR, XDR, etc.) were found running."
                << std::endl;
    }
    return 0;
}
