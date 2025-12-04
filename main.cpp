// av_detect.cpp — v2.4.4
// - Salida monolínea sin comillas envolventes en cmd=/bin=
// - Normalización de espacios en cmd= y strip de comillas exteriores
// - Fallback img= (QueryFullProcessImageNameA) si no hay cmd ni SCM
// - Detecciones ordenadas alfabéticamente con [TAG] al inicio
// - Catálogo extendido (CLOUD/CREDS/RDP/…)
// - Sin SeDebugPrivilege (perfil low-noise)

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <algorithm>
#include <Windows.h>
#include <tlhelp32.h>
#include <winsvc.h>

#ifndef VERSION
#define VERSION "v2.1.0"
#endif

constexpr size_t kLineMax = 96;

struct SecuritySoftware {
    std::string name;  // Descripción humana
    std::string type;  // Descripción larga
    std::string tag;   // Etiqueta compacta
};

struct ServiceInfo {
    std::string name;
    std::string display;
    std::string binary;
    int extra_count = 0;
};

// -------------------- utilidades --------------------
static std::string toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return static_cast<char>(::tolower(c)); });
    return out;
}
static bool hasExeExtension(const std::string& lowerName) {
    const size_t n = lowerName.size();
    return n >= 4 && lowerName.compare(n-4, 4, ".exe") == 0;
}
static std::string selfImageNameLower() {
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return {};
    std::string path(buf, buf + len);
    size_t pos = path.find_last_of("\\/");
    std::string base = (pos == std::string::npos) ? path : path.substr(pos+1);
    return toLower(base);
}
static std::string wideToUtf8(const WCHAR* wstr, size_t wlen) {
    if (!wstr || wlen == 0) return {};
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string out(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, out.data(), bytes, nullptr, nullptr);
    return out;
}
static std::string truncateRight(const std::string& s, size_t maxLen) {
    if (s.size() <= maxLen) return s;
    if (maxLen <= 3) return s.substr(0, maxLen);
    return s.substr(0, maxLen - 3) + "...";
}

// Normaliza espacios y elimina CR/LF/tabs
static std::string collapseWs(std::string s) {
    std::string out; out.reserve(s.size());
    bool inSpace = false;
    for (char c : s) {
        if (c=='\r' || c=='\n' || c=='\t') c = ' ';
        if (c==' ') {
            if (!inSpace) { out.push_back(' '); inSpace = true; }
        } else {
            out.push_back(c); inSpace = false;
        }
    }
    // trim
    while (!out.empty() && out.front()==' ') out.erase(out.begin());
    while (!out.empty() && out.back()==' ') out.pop_back();
    return out;
}

// Elimina comillas exteriores simétricas si las hay (no toca comillas internas)
static std::string stripOuterQuotes(const std::string& s) {
    if (s.size()>=2) {
        char a = s.front(), b = s.back();
        if ((a=='"' && b=='"') || (a=='\'' && b=='\'')) {
            return s.substr(1, s.size()-2);
        }
    }
    return s;
}

// -------------------- baselines --------------------
static const std::unordered_set<std::string>& baselineSystem() {
    static const std::unordered_set<std::string> base = {
            // core/session
            "system","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe","winlogon.exe",
            // services/hosts
            "svchost.exe","fontdrvhost.exe","spoolsv.exe","wudfhost.exe","dllhost.exe","audiodg.exe",
            // shell / UX
            "explorer.exe","sihost.exe","ctfmon.exe","dwm.exe","runtimebroker.exe",
            "shellexperiencehost.exe","startmenuexperiencehost.exe",
            "searchhost.exe","searchindexer.exe",
            "systemsettings.exe","systemsettingsbroker.exe","backgroundtaskhost.exe",
            "searchfilterhost.exe","searchprotocolhost.exe","lockapp.exe","textinputhost.exe",
            "presentationfontcache.exe","lsaiso.exe","unsecapp.exe",
            // consola / utilidades base del SO
            "conhost.exe","taskhostw.exe","taskmgr.exe","rundll32.exe",
            "werfault.exe","cmd.exe","powershell.exe",
            // wmi / compat
            "wmiprvse.exe","compattelrunner.exe","wmiregistrationservice.exe",
            // impresión / 32-64 bridge
            "splwow64.exe",
            // UWP framework y brokers
            "applicationframehost.exe","aggregatorhost.exe","dataexchangehost.exe","dashost.exe",
            // Hyper-V / WSL infraestructura
            "vmcompute.exe","vmms.exe","vmwp.exe","vmmemwsl","wslinstaller.exe",
            // WLAN infra
            "wlanext.exe",
            // componentes nativos adicionales
            "locationnotificationwindows.exe","mmgaserver.exe","modemauthenticator.exe"
    };
    return base;
}

static const std::unordered_set<std::string>& baselineCommonApps() {
    static const std::unordered_set<std::string> base = {
            // Navegadores generalistas
            "msedge.exe","chrome.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe",
            // Office principales y servicio ClickToRun
            "winword.exe","excel.exe","powerpnt.exe","onenote.exe","outlook.exe","officeclicktorun.exe",
            // IM/colaboración mainstream
            "teams.exe","ms-teams.exe","skype.exe","skypeapp.exe",
            "telegram.exe","slack.exe","discord.exe","whatsapp.exe","signal.exe",
            // Terminal moderna y winget backend
            "openconsole.exe","windowsterminal.exe","windowspackagemanagerserver.exe"
    };
    return base;
}

static const std::unordered_set<std::string>& pseudoKernelNames() {
    static const std::unordered_set<std::string> s = {
            "[system process]", "registry", "memory compression", "secure system"
    };
    return s;
}

// -------------------- cmdline best-effort --------------------
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG
);
typedef struct _UNICODE_STRING_LITE {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_LITE;

// Fallback: imagen completa (no requiere VM_READ)
static std::string queryFullImagePathUtf8(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    char buf[MAX_PATH];
    DWORD sz = MAX_PATH;
    std::string out;
    if (QueryFullProcessImageNameA(h, 0, buf, &sz) && sz>0) {
        out.assign(buf, buf+sz);
    }
    CloseHandle(h);
    return out;
}

static std::string tryGetCmdlineUtf8(DWORD pid) {
    static PFN_NtQueryInformationProcess NtQIP = nullptr;
    static bool resolved = false;
    if (!resolved) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) ntdll = LoadLibraryA("ntdll.dll");
        if (ntdll) {
            FARPROC p = GetProcAddress(ntdll, "NtQueryInformationProcess");
            NtQIP = reinterpret_cast<PFN_NtQueryInformationProcess>(p);
        }
        resolved = true;
    }
    if (!NtQIP) return {};

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return {};
    }

    const ULONG ProcessCommandLineInformation = 60;
    ULONG len = 0;
    NTSTATUS st = NtQIP(h, ProcessCommandLineInformation, nullptr, 0, &len);
    if (len == 0) { CloseHandle(h); return {}; }

    std::vector<BYTE> buf(len);
    st = NtQIP(h, ProcessCommandLineInformation, buf.data(), len, &len);
    CloseHandle(h);
    if (st < 0) return {};
    if (len < sizeof(UNICODE_STRING_LITE)) return {};

    auto u = reinterpret_cast<UNICODE_STRING_LITE*>(buf.data());
    if (!u->Buffer || u->Length == 0) return {};
    size_t wlen = u->Length / sizeof(WCHAR);
    return wideToUtf8(u->Buffer, wlen);
}

// -------------------- índice SCM (PID -> ServiceInfo) --------------------
static const std::unordered_map<DWORD, ServiceInfo>& serviceIndexByPid() {
    static bool built = false;
    static std::unordered_map<DWORD, ServiceInfo> idx;
    if (built) return idx;
    built = true;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return idx;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExA(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            nullptr, 0, &bytesNeeded, &count, &resume, nullptr
    );
    if (bytesNeeded == 0) { CloseServiceHandle(scm); return idx; }

    std::vector<BYTE> buf(bytesNeeded);
    if (!EnumServicesStatusExA(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return idx;
    }

    auto arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buf.data());
    for (DWORD i = 0; i < count; ++i) {
        const DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
        if (pid == 0) continue;

        const char* svcName = arr[i].lpServiceName ? arr[i].lpServiceName : "";
        const char* dispName = arr[i].lpDisplayName ? arr[i].lpDisplayName : "";

        auto it = idx.find(pid);
        if (it == idx.end()) {
            std::string binary;
            SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_QUERY_CONFIG);
            if (svc) {
                DWORD need = 0;
                QueryServiceConfigA(svc, nullptr, 0, &need);
                if (need) {
                    std::vector<BYTE> cbuf(need);
                    auto cfg = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(cbuf.data());
                    if (QueryServiceConfigA(svc, cfg, need, &need)) {
                        if (cfg->lpBinaryPathName) binary = cfg->lpBinaryPathName;
                    }
                }
                CloseServiceHandle(svc);
            }
            ServiceInfo info;
            info.name = svcName;
            info.display = dispName;
            info.binary = binary;
            info.extra_count = 0;
            idx.emplace(pid, std::move(info));
        } else {
            it->second.extra_count += 1;
        }
    }

    CloseServiceHandle(scm);
    return idx;
}

// -------------------- helpers de salida --------------------
static std::string buildDetectionLine(const std::string& tagLabel,
                                      const std::string& productName,
                                      const std::string& exeName,
                                      size_t maxLen = kLineMax) {
    const std::string prefix = "[" + tagLabel + "] ";
    const std::string middle = " - exe=";
    size_t fixed = prefix.size() + middle.size() + exeName.size();
    size_t budgetName = (fixed >= maxLen) ? 0 : (maxLen - fixed);
    std::string pname = (productName.size() <= budgetName)
                        ? productName
                        : truncateRight(productName, budgetName);
    return prefix + pname + middle + exeName;
}

static std::string buildUnknownLine(const std::string& exeLower,
                                    DWORD pid,
                                    size_t maxLen = kLineMax)
{
    std::string line = "- " + exeLower;

    // 1) cmd=
    std::string cmd = tryGetCmdlineUtf8(pid);
    if (!cmd.empty()) {
        cmd = collapseWs(stripOuterQuotes(cmd));
        const std::string pfx = " | cmd=";
        size_t fixed = line.size() + pfx.size();
        size_t budget = (fixed >= maxLen) ? 0 : (maxLen - fixed);
        if (budget > 0) line += pfx + truncateRight(cmd, budget);
        return line;
    }

    // 2) Fallback: SCM (svc=/bin=)
    const auto& map = serviceIndexByPid();
    auto it = map.find(pid);
    if (it != map.end()) {
        // svc=
        std::string svc = it->second.name;
        if (it->second.extra_count > 0) svc += "(+" + std::to_string(it->second.extra_count) + ")";
        std::string partSvc = " | svc=" + svc;

        size_t budget = (line.size() >= maxLen) ? 0 : (maxLen - line.size());
        if (budget > 0) {
            if (partSvc.size() <= budget) {
                line += partSvc;
                budget -= partSvc.size();
            } else {
                const std::string pfx = " | svc=";
                size_t avail = (budget > pfx.size()) ? (budget - pfx.size()) : 0;
                line += pfx + truncateRight(svc, avail);
                budget = 0;
            }
        }
        if (budget > 0 && !it->second.binary.empty()) {
            const std::string pfx = " | bin=";
            size_t fixed = line.size() + pfx.size();
            size_t b2 = (fixed >= maxLen) ? 0 : (maxLen - fixed);
            if (b2 > 0) line += pfx + truncateRight(it->second.binary, b2);
        }
        return line;
    }

    // 3) Fallback suave: imagen completa
    std::string img = queryFullImagePathUtf8(pid);
    if (!img.empty()) {
        img = collapseWs(stripOuterQuotes(img));
        const std::string pfx = " | img=";
        size_t fixed = line.size() + pfx.size();
        size_t budget = (fixed >= maxLen) ? 0 : (maxLen - fixed);
        if (budget > 0) line += pfx + truncateRight(img, budget);
    }
    return line;
}

// -------------------- catálogo con TAG explícito --------------------
static const std::unordered_map<std::string, std::vector<SecuritySoftware>>& catalog() {
    static const std::unordered_map<std::string, std::vector<SecuritySoftware>> sw = {
            // VPN / ZTNA
            {"vpnagent.exe", { {"Cisco AnyConnect Secure Mobility Client","VPN","VPN"}, {"Cisco AnyConnect","VPN","VPN"} }},
            {"vpnui.exe",    { {"Cisco AnyConnect","VPN","VPN"} }},
            {"concentr.exe", { {"Palo Alto Networks GlobalProtect","VPN","VPN"} }},
            {"pangps.exe",   { {"Palo Alto Networks GlobalProtect","VPN","VPN"} }},
            {"fortitray.exe",{ {"Fortinet FortiClient / FortiTray","VPN / Endpoint Security","VPN"} }},
            {"fortivpn.exe", { {"Fortinet FortiClient VPN","VPN","VPN"} }},
            {"zsatray.exe",  { {"Zscaler Client Connector (ZTNA / SWG)","Proxy / CASB / ZTNA","ZTNA"} }},
            {"zsatraymanager.exe",{ {"Zscaler Client Connector (privileged)","Proxy / CASB / ZTNA","ZTNA"} }},
            {"ksde.exe",     { {"Kaspersky Secure Connection","VPN","VPN"} }},
            {"ksdeui.exe",   { {"Kaspersky Secure Connection","VPN","VPN"} }},
            {"wireguard.exe",{ {"WireGuard","VPN","VPN"} }},
            {"openvpnserv.exe",  { {"OpenVPN","VPN","VPN"} }},
            {"openvpnserv2.exe", { {"OpenVPN (Service v2)","VPN","VPN"} }},
            {"nsload.exe",   { {"Citrix Secure Access Client Loader","ZTNA / VPN","ZTNA"} }},
            {"nsverctl.exe", { {"Citrix Secure Access Verification Control","ZTNA / VPN","ZTNA"} }},
            {"ctxsdps.exe",  { {"Citrix Endpoint Analysis / Secure Access","ZTNA / VPN","ZTNA"} }},
            {"aoservice.exe",{ {"Citrix Secure Access Client Service","ZTNA / VPN","ZTNA"} }},
            {"appprotection.exe",{ {"Citrix App Protection","ZTNA / Anti-hooking","ZTNA"} }},
            {"updaterservice.exe",{ {"Citrix Workspace Updater (CWAUpdaterService)","ZTNA / Workspace","ZTNA"} }},

            // EDR / AV / Telemetry
            {"csfalconservice.exe",   { {"CrowdStrike Falcon Sensor","EDR / XDR","EDR"} }},
            {"csfalconcontainer.exe", { {"CrowdStrike Falcon Sensor Container","EDR / XDR","EDR"} }},
            {"csfalcondaterepair.exe",{ {"CrowdStrike Falcon Repair Component","EDR / XDR","EDR"} }},
            {"msmpeng.exe",  { {"Microsoft Defender Antivirus Engine","AV","AV"} }},
            {"mssense.exe",  { {"Microsoft Defender for Endpoint (MDE/ATP)","EDR","EDR"} }},
            {"senseir.exe",  { {"Microsoft Defender IR component","Security / IR","OTHER"} }},
            {"sensendr.exe", { {"Microsoft Defender NDR component","Security / NDR","NDR"} }},
            {"sensetvm.exe", { {"Microsoft Defender TVM","Vulnerability Mgmt","VULN"} }},
            {"mpdefendercoreservice.exe",{ {"Microsoft Defender Core Service","AV","AV"} }},
            {"windefend.exe",{ {"Microsoft Defender AV Service","AV","AV"} }},
            {"msascuil.exe", { {"Windows Defender UI","AV UI","AV"} }},
            {"securityhealthservice.exe",{ {"Windows Security Health Service","Security / Health","OTHER"} }},
            {"securityhealthsystray.exe",{ {"Windows Security Systray","Security / Health","OTHER"} }},
            {"sysmon.exe",   { {"Microsoft Sysmon","Security Telemetry","TEL"} }},
            {"sysmon64.exe", { {"Microsoft Sysmon (64-bit)","Security Telemetry","TEL"} }},

            // SentinelOne
            {"sentinelagent.exe", { {"SentinelOne Agent","EDR / XDR","EDR"} }},
            {"sentinelctl.exe",   { {"SentinelOne Control CLI","EDR / XDR","EDR"} }},
            {"sentinelservicehost.exe",{ {"SentinelOne Service Host","EDR / XDR","EDR"} }},
            {"sentinelstaticengine.exe",{ {"SentinelOne Static Engine","EDR / XDR","EDR"} }},
            {"sentinelstaticenginescanner.exe",{ {"SentinelOne Static Engine Scanner","EDR / XDR","EDR"} }},
            {"sentinelmemoryscanner.exe",{ {"SentinelOne Memory Scanner","EDR / XDR","EDR"} }},

            // Cortex XDR (Traps/Cyvera)
            {"cyserver.exe",   { {"Cortex XDR Agent (protected)","EDR / XDR","EDR"} }},
            {"cyveraconsole.exe",{ {"Cortex XDR Console","EDR / XDR","EDR"} }},
            {"cyveraservice.exe",{ {"Cortex XDR Service","EDR / XDR","EDR"} }},
            {"cyvragentsvc.exe",{ {"Cortex XDR Agent Service","EDR / XDR","EDR"} }},
            {"cyvrfsflt.exe",  { {"Cortex XDR FS Filter","EDR / XDR","EDR"} }},
            {"traps.exe",      { {"Cortex XDR (Traps)","EDR / XDR","EDR"} }},
            {"trapsagent.exe", { {"Cortex XDR (Traps Agent)","EDR / XDR","EDR"} }},
            {"trapsd.exe",     { {"Cortex XDR Daemon","EDR / XDR","EDR"} }},

            // Elastic
            {"elastic-endpoint.exe", { {"Elastic Defend / Endpoint","EDR / Telemetry","EDR"} }},
            {"endpoint-security.exe",{ {"Elastic Endpoint Security Component","EDR / Telemetry","EDR"} }},
            {"elastic-agent.exe",    { {"Elastic Agent (Fleet)","EDR / Telemetry / UEM","EDR"} }},

            // Tanium / Rapid7 / Qualys
            {"taniumclient.exe", { {"Tanium Client","EDR / Asset / IR","EDR"} }},
            {"tanclient.exe",    { {"Tanium EDR Client (legacy)","EDR / IR","EDR"} }},
            {"ir_agent.exe",     { {"Rapid7 Insight Agent","EDR / Vuln / IR","EDR"} }},
            {"qualysagent.exe",  { {"Qualys Cloud Agent","Vuln Mgmt / Compliance","VULN"} }},
            {"qualysagentui.exe",{ {"Qualys Cloud Agent UI","Vuln Mgmt / Compliance","VULN"} }},

            // Trend Micro
            {"tmlisten.exe",   { {"Trend Micro AV / Apex One Core","AV / EDR","AV"} }},
            {"ntrtscan.exe",   { {"Trend Micro Real-Time Scan","AV / EDR","AV"} }},
            {"tmntsrv.exe",    { {"Trend Micro OfficeScan / Apex One","AV / EDR","AV"} }},
            {"tmproxy.exe",    { {"Trend Micro Traffic Scanner / Proxy","AV / Network","AV"} }},
            {"personalfirewallservice.exe",{ {"Trend Micro Personal Firewall","Firewall","FW"} }},
            {"coreserviceshell.exe",{ {"Trend Micro Core Service Shell","AV / EDR","AV"} }},
            {"clientcommunicationservice.exe",{ {"Trend Micro Client Comm","AV / EDR","AV"} }},
            {"clientlogservice.exe",{ {"Trend Micro Client Log","AV / EDR","AV"} }},
            {"clientsolutionframework.exe",{ {"Trend Micro Client Solution","AV / EDR","AV"} }},
            {"endpointbasecamp.exe",{ {"Trend Micro Endpoint Basecamp","EDR","EDR"} }},
            {"realtimescanservice.exe",{ {"Trend Micro RealTime Scan Service","AV / EDR","AV"} }},
            {"samplingservice.exe",{ {"Trend Micro Sampling Service","AV / EDR","AV"} }},
            {"telemetryagentservice.exe",{ {"Trend Micro Telemetry Agent","Telemetry","TEL"} }},
            {"telemetryservice.exe",{ {"Trend Micro Telemetry Service","Telemetry","TEL"} }},
            {"vulnerabilityprotectionagent.exe",{ {"Trend Micro Vulnerability Protection Agent","Vuln Mgmt","VULN"} }},
            {"wscservice.exe",{ {"Trend Micro Security Service","AV / EDR","AV"} }},

            // McAfee / Trellix
            {"macmnsvc.exe",{ {"McAfee Agent Common Service","AV / EDR","AV"} }},
            {"masvc.exe",   { {"McAfee Agent Service","AV / EDR","AV"} }},
            {"mfemms.exe",  { {"McAfee Endpoint Security / Mgmt","AV / EDR","AV"} }},
            {"mfefire.exe", { {"McAfee HIPS / Firewall","HIPS / FW","HIPS"} }},
            {"mfemactl.exe",{ {"McAfee ES Firewall Controller","Firewall","FW"} }},
            {"mcshield.exe",{ {"McAfee On-Access Scanner","AV","AV"} }},
            {"shstat.exe",  { {"McAfee Status Monitor","AV UI","AV"} }},
            {"edpa.exe",    { {"McAfee DLP Agent","AV / DLP","DLP"} }},
            {"dlpsensor.exe",{ {"McAfee DLP Sensor","DLP","DLP"} }},
            {"mfeepehost.exe",{ {"McAfee Endpoint Encryption Host","Disk Encryption","ENC"} }},
            {"mdecryptservice.exe",{ {"McAfee Encryption Decrypt Service","Disk Encryption","ENC"} }},

            // Symantec / Norton
            {"ccsvchst.exe",{ {"Symantec Endpoint Protection / Norton","AV / EDR","AV"} }},
            {"rtvscan.exe", { {"Symantec Endpoint Protection","AV","AV"} }},
            {"dlpagent.exe",{ {"Symantec DLP Agent","DLP","DLP"} }},
            {"nortonsecurity.exe",{ {"Norton Security","AV","AV"} }},
            {"ns.exe",      { {"Norton Security","AV","AV"} }},
            {"nsservice.exe",{ {"Norton Security Service","AV","AV"} }},

            // Sophos
            {"savservice.exe",{ {"Sophos Endpoint / SAVService","AV / EDR","AV"} }},
            {"sophosav.exe", { {"Sophos Endpoint AV","AV","AV"} }},
            {"sophosclean.exe",{ {"Sophos Clean","AV / Remediation","AV"} }},
            {"sophoshealth.exe",{ {"Sophos Health","AV / Telemetry","TEL"} }},
            {"sophossps.exe",{ {"SophosSps (Exploit Mitigation / Endpoint Defense)","EDR / Exploit Guard","EDR"} }},
            {"sophosui.exe", { {"Sophos UI","AV UI","AV"} }},

            // Kaspersky
            {"avp.exe",     { {"Kaspersky AV / KES","AV / EDR","EDR"} }},
            {"avpui.exe",   { {"Kaspersky UI","AV UI","AV"} }},
            {"klwtblfs.exe",{ {"Kaspersky FS Filter","AV","AV"} }},

            // ESET
            {"egui.exe", { {"ESET NOD32 / Endpoint GUI","AV UI","AV"} }},
            {"ekrn.exe", { {"ESET Kernel Service","AV / EDR","EDR"} }},

            // Bitdefender
            {"bdagent.exe",{ {"Bitdefender Agent","AV","AV"} }},
            {"bdntwrk.exe",{ {"Bitdefender Network Protection","AV / Network","AV"} }},
            {"updatesrv.exe",{ {"Bitdefender Update Service","AV","AV"} }},
            {"vsserv.exe", { {"Bitdefender Virus Shield","AV","AV"} }},

            // Avast / Avira / Panda / Webroot
            {"aswidsagent.exe",{ {"Avast IDS Agent","AV / IDS","AV"} }},
            {"avastsvc.exe",   { {"Avast AV Service","AV","AV"} }},
            {"avastui.exe",    { {"Avast UI","AV UI","AV"} }},
            {"avgnt.exe",      { {"Avira AV Guard UI","AV UI","AV"} }},
            {"avguard.exe",    { {"Avira AV Guard","AV","AV"} }},
            {"pavsrv.exe",     { {"Panda AV Service","AV","AV"} }},
            {"pavfnsvr.exe",   { {"Panda AV File Name Server","AV","AV"} }},
            {"psanhost.exe",   { {"Panda Advanced Protection Host","AV / EDR","EDR"} }},
            {"panda_url_filtering.exe",{ {"Panda URL Filtering","Web Filter","OTHER"} }},
            {"wrsa.exe",       { {"Webroot SecureAnywhere","AV / EDR","EDR"} }},

            // FireEye / Trellix HX
            {"xagt.exe",   { {"FireEye Endpoint Agent / Trellix HX","EDR / IR","EDR"} }},
            {"firesvc.exe",{ {"FireEye Endpoint Agent Service","EDR / IR","EDR"} }},
            {"firetray.exe",{ {"FireEye Endpoint Agent Tray","EDR / IR","EDR"} }},

            // Check Point
            {"fw.exe", { {"Check Point Firewall","Firewall","FW"} }},
            {"cpd.exe",{ {"Check Point Daemon","Security","OTHER"} }},

            // AppControl / HIPS
            {"appcontrolagent.exe",{ {"Trend Micro Application Control Agent","Application Control","APPC"} }},
            {"hips.exe",          { {"Host Intrusion Prevention System","HIPS","HIPS"} }},

            // DLP / cifrado
            {"axcrypt.exe",{ {"AxCrypt","Encryption","ENC"} }},
            {"truecrypt.exe",{ {"TrueCrypt","Encryption","ENC"} }},
            {"eegoservice.exe",{ {"McAfee Endpoint Encryption Service","Disk Encryption","ENC"} }},

            // Monitoring / Telemetría
            {"healthservice.exe",{ {"Microsoft OMS / SCOM HealthService","Monitoring","MON"} }},
            {"monitoringhost.exe",{ {"Microsoft Monitoring Agent","Monitoring","MON"} }},
            {"npmdagent.exe",{ {"SolarWinds NPM Agent","Network Monitoring","MON"} }},

            // Virtualización (VMware, WSL)
            {"vgauthservice.exe",{ {"VMware VGAuthService","Virtualization / Guest Tools","VIRT"} }},
            {"vm3dservice.exe",  { {"VMware 3D Service","Virtualization / Guest Tools","VIRT"} }},
            {"vmtoolsd.exe",     { {"VMware Tools Daemon","Virtualization / Guest Tools","VIRT"} }},
            {"vmware-authd.exe", { {"VMware Authorization Service","Virtualization / Guest Tools","VIRT"} }},
            {"vmware-usbarbitrator64.exe",{ {"VMware USB Arbitration Service","Virtualization / Guest Tools","VIRT"} }},
            {"vmnat.exe",        { {"VMware NAT Service","Virtualization / Networking","VIRT"} }},
            {"vmnetdhcp.exe",    { {"VMware DHCP Service","Virtualization / Networking","VIRT"} }},
            {"vmware-tray.exe",  { {"VMware Tray","Virtualization / Guest Tools","VIRT"} }},
            {"wsl.exe",          { {"Windows Subsystem for Linux","Virtualization / Subsystem","VIRT"} }},
            {"wslhost.exe",      { {"Windows Subsystem for Linux Host","Virtualization / Subsystem","VIRT"} }},
            {"wslservice.exe",   { {"Windows Subsystem for Linux Service","Virtualization / Subsystem","VIRT"} }},

            // RMM / Remote / RDP
            {"cmrcservice.exe",  { {"ConfigMgr Remote Control Service","Remote Control","RMM"} }},
            {"teamviewer_service.exe",{ {"TeamViewer Service","Remote Control / RMM","RMM"} }},
            {"mstsc.exe",  { {"Microsoft Remote Desktop Client","RDP","RDP"} }},
            {"msrdc.exe",  { {"Microsoft Remote Desktop Client (Modern)","RDP","RDP"} }},
            {"msra.exe",         { {"Windows Remote Assistance","Remote Assistance","RDP"} }},
            {"quickassist.exe",  { {"Microsoft Quick Assist","Remote Assistance","RMM"} }},

            // Integridad / broker
            {"sgrmbroker.exe", { {"Windows System Guard Runtime Monitor Broker","System Integrity","INT"} }},

            // Miscelánea útil
            {"sbiesvc.exe",    { {"Sandboxie Service","Sandbox / Isolation","OTHER"} }},
            {"winlogbeat.exe", { {"Elastic Winlogbeat (log forwarder)","Security Telemetry","TEL"} }},
            {"mdnsresponder.exe",{ {"Bonjour Service","Network Service / mDNS","OTHER"} }},
            {"smsvchost.exe",  { {"Microsoft .NET Framework service host","Application","OTHER"} }},

            // CLOUD / Sync
            {"onedrive.exe",        { {"Microsoft OneDrive","Cloud Sync / OneDrive","CLOUD"} }},
            {"googledrivefs.exe",   { {"Google Drive for Desktop","Cloud Sync / Google Drive","CLOUD"} }},
            {"dropbox.exe",         { {"Dropbox Desktop","Cloud Sync / Dropbox","CLOUD"} }},
            {"nextcloud.exe",       { {"Nextcloud Desktop","Cloud Sync / Nextcloud","CLOUD"} }},
            {"apsdaemon.exe",       { {"Apple iCloud Push Daemon","Cloud Sync / iCloud","CLOUD"} }},
            {"icloudphotos.exe",    { {"Apple iCloud Photos","Cloud Sync / iCloud","CLOUD"} }},
            {"icloudservices.exe",  { {"Apple iCloud Services","Cloud Sync / iCloud","CLOUD"} }},
            {"iclouddrive.exe",     { {"Apple iCloud Drive","Cloud Sync / iCloud","CLOUD"} }},
            {"icloudoutlookconfig64.exe",{ {"Apple iCloud Outlook Config","Cloud Sync / iCloud","CLOUD"} }},
            {"icloudckks.exe",      { {"Apple iCloud CKKS","Cloud Sync / iCloud","CLOUD"} }},
            {"icloudhome.exe",      { {"Apple iCloud Home","Cloud Sync / iCloud","CLOUD"} }},
            {"applephotostreams.exe",{ {"Apple Photo Streams","Cloud Sync / iCloud","CLOUD"} }},
            {"secd.exe",            { {"Apple iCloud Security Daemon","Cloud Sync / iCloud","CLOUD"} }},
            {"box.exe",             { {"Box Desktop","Cloud Sync / Box","CLOUD"} }},
            {"boxdrive.exe",        { {"Box Drive","Cloud Sync / Box","CLOUD"} }},

            // TRUST / OEM / AUDIO / GPU / DRM / USB / TB / NAS
            {"aesm_service.exe", { {"Intel SGX AESM Service","Trusted Execution (SGX)","TRUST"} }},
            {"esif_uf.exe",      { {"Intel Dynamic Platform & Thermal Framework","OEM Thermal Mgmt","OEM"} }},
            {"fmservice64.exe",  { {"Fortemedia APO Service","Audio Processing","AUDIO"} }},
            {"dax3api.exe",      { {"Dolby DAX API Service","Audio Processing","AUDIO"} }},
            {"ibmpmsvc.exe",     { {"Lenovo Power Management Service","OEM Power","OEM"} }},
            {"powermgr.exe",     { {"Lenovo Power Manager","OEM Power","OEM"} }},
            {"shtctky.exe",      { {"Lenovo Hotkeys","OEM Hotkeys","OEM"} }},
            {"tphkload.exe",     { {"Lenovo Hotkey Loader","OEM Hotkeys","OEM"} }},
            {"tposd.exe",        { {"Lenovo On-Screen Display","OEM OSD","OEM"} }},
            {"igfxcuiservice.exe",{ {"Intel Graphics CUI Service","GPU Runtime","GPU"} }},
            {"igfxem.exe",       { {"Intel Graphics EM","GPU Runtime","GPU"} }},
            {"intelcphdcpsvc.exe",{ {"Intel Content Protection HDCP Service","DRM / Content Protection","DRM"} }},
            {"intelcphecisvc.exe",{ {"Intel Component Helper Service","DRM / Content Protection","DRM"} }},
            {"ipoverusbsvc.exe", { {"Microsoft IP over USB","USB networking","USB"} }},
            {"jhi_service.exe",  { {"Intel Dynamic Application Loader (HECI)","OEM Management","OEM"} }},
            {"rtkauduservice64.exe",{ {"Realtek Audio Universal Service","Audio Driver","AUDIO"} }},
            {"ss_conn_service.exe",{ {"Samsung USB Driver Service","USB / Android","USB"} }},
            {"ss_conn_service2.exe",{ {"Samsung USB Driver Service (alt)","USB / Android","USB"} }},
            {"synrpcserver.exe", { {"Synology Assistant RPC Service","NAS Discovery","NAS"} }},
            {"tbtp2pshortcutservice.exe",{ {"Intel Thunderbolt P2P Shortcut Service","Thunderbolt","TB"} }},
            {"thunderboltservice.exe",{ {"Intel Thunderbolt Service","Thunderbolt","TB"} }},

            // Credential Managers (útiles para DFIR/Red)
            {"keepass.exe",    { {"KeePass Password Safe 2","Credential Manager","CREDS"} }},
            {"keepassxc.exe",  { {"KeePassXC","Credential Manager","CREDS"} }},
            {"bitwarden.exe",  { {"Bitwarden","Credential Manager","CREDS"} }},
            {"1password.exe",  { {"1Password","Credential Manager","CREDS"} }},
    };
    return sw;
}

// -------------------- detección principal --------------------
bool isSecuritySoftwareRunning() {
    SetConsoleOutputCP(65001);

    std::unordered_set<std::string> reported;
    std::unordered_set<std::string> seenLower;
    std::map<std::string, DWORD> firstPidByExe;
    std::vector<std::string> detectionLines;
    detectionLines.reserve(128);

    const auto& sw = catalog();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return false; }

    bool anySecurity = false;

    do {
        std::string exe(pe.szExeFile);
        std::string lower = toLower(exe);
        seenLower.insert(lower);
        if (firstPidByExe.find(lower) == firstPidByExe.end()) {
            firstPidByExe[lower] = pe.th32ProcessID;
        }
        if (reported.find(lower) == reported.end()) {
            auto it = sw.find(lower);
            if (it != sw.end()) {
                anySecurity = true;
                for (const auto& x : it->second) {
                    const std::string& tag = x.tag.empty() ? std::string("OTHER") : x.tag;
                    detectionLines.emplace_back(
                            buildDetectionLine(tag, x.name, exe, kLineMax)
                    );
                }
                reported.insert(lower);
            }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    const std::string selfLower = selfImageNameLower();
    std::vector<std::pair<std::string, DWORD>> unknown;
    unknown.reserve(seenLower.size());

    for (const auto& kv : firstPidByExe) {
        const std::string& p = kv.first;
        const DWORD pid = kv.second;
        if (p == selfLower) continue;
        if (pseudoKernelNames().count(p)) continue;
        const bool isKnown  = (sw.find(p) != sw.end());
        const bool isSys    = (baselineSystem().count(p) != 0);
        const bool isCommon = (baselineCommonApps().count(p) != 0);
        if (!isKnown && !isSys && !isCommon) {
            if (!hasExeExtension(p)) continue;
            unknown.emplace_back(p, pid);
        }
    }
    std::sort(unknown.begin(), unknown.end(),
              [](const auto& a, const auto& b){ return a.first < b.first; });

    std::cout << "\n[unknown] Non-system unknown processes (" << unknown.size() << "):" << std::endl;
    for (const auto& u : unknown) {
        std::cout << buildUnknownLine(u.first, u.second, kLineMax) << std::endl;
    }
    std::cout << "\n---\n";

    // Orden determinista alfabético (case-insensitive) de detecciones
    std::sort(detectionLines.begin(), detectionLines.end(),
              [](const std::string& a, const std::string& b) {
                  std::string la = toLower(a), lb = toLower(b);
                  return la < lb;
              });

    for (const auto& line : detectionLines) {
        std::cout << line << std::endl;
    }

    return anySecurity;
}

int main() {
    SetConsoleOutputCP(65001);
    std::cout << "AV_detect Version: " << VERSION << std::endl;

    if (isSecuritySoftwareRunning()) {
        std::cout << "\nFound security software process (AV, anti-malware, EDR, XDR, etc.) running." << std::endl;
    } else {
        std::cout << "\nNo security software processes (AV, anti-malware, EDR, XDR, etc.) were found running." << std::endl;
    }
    return 0;
}
