// av_detect.cpp -- v2.3.0
//
// Security Software Detector (Windows)
// -----------------------------------
// Enumerates live processes on the endpoint and matches each image-name
// (case-insensitive) against a curated catalog of known security-related agents.
//
// Output is stable / parser-friendly:
//   1) "[unknown]" block: non-baseline processes (best-effort metadata)
//   2) Separator line: "---"
//   3) Detections: "[TAG] ProductName - exe=ImageName" sorted alphabetically
//
// Design goals:
//   - Low-noise triage: no SeDebugPrivilege, no invasive inspection.
//   - No admin required: Toolhelp snapshot + best-effort enrichment.
//   - Deterministic output for piping into SIEM parsers.
//
// Limitations (by design):
//   - Name-based detection: renamed/protected processes may evade classification.
//   - Does not validate license/state, drivers, or kernel-mode components.

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <algorithm>
#include <fstream>
#include <limits>
#define NOMINMAX          // prevent Windows.h from defining min/max macros
#include <Windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <cstdint>

#ifndef VERSION
#ifdef VERSION_MAJOR
#define _VS2(a,b,c) "v" #a "." #b "." #c
#define _VS(a,b,c)  _VS2(a,b,c)
#define VERSION _VS(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)
#else
#define VERSION "v2.3.0"
#endif
#endif


// Soft limit for characters per output line (keeps stdout compact and parser-friendly).
constexpr size_t kLineMax = 120;

constexpr size_t kNoLimit = std::numeric_limits<size_t>::max();

// Processes Catalog entry for a known security-related executable.
struct SecuritySoftware {
    std::string name;  // Human-friendly product name
    std::string type;  // Longer descriptor (kept for future use / completeness)
    std::string tag;   // Compact classification tag (EDR, AV, VPN, ...)
};

// Services SCM-derived metadata for a Windows service-hosted process.
// Used to enrich unknown processes when command line is not accessible.
struct ServiceInfo {
    std::string name;      // Service name (SCM key)
    std::string display;   // Display name (not currently printed)
    std::string binary;    // Binary path (QueryServiceConfigA)
    int extra_count = 0;   // Additional services sharing this PID (svchost groups, etc.)
};

// -------------------- RAII guards --------------------

struct HandleGuard {
    HANDLE h = nullptr;
    explicit HandleGuard(HANDLE h = nullptr) : h(h) {}
    ~HandleGuard() { reset(); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& o) noexcept : h(o.h) { o.h = nullptr; }
    HandleGuard& operator=(HandleGuard&& o) noexcept {
        if (this != &o) { reset(); h = o.h; o.h = nullptr; }
        return *this;
    }
    void reset() {
        if (h && h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = nullptr; }
    }
    operator HANDLE() const { return h; }
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

struct ScHandleGuard {
    SC_HANDLE h = nullptr;
    explicit ScHandleGuard(SC_HANDLE h = nullptr) : h(h) {}
    ~ScHandleGuard() { if (h) CloseServiceHandle(h); }
    ScHandleGuard(const ScHandleGuard&) = delete;
    ScHandleGuard& operator=(const ScHandleGuard&) = delete;
    operator SC_HANDLE() const { return h; }
    explicit operator bool() const { return h != nullptr; }
};

// -------------------- utilities --------------------

// Lowercase ASCII conversion used for case-insensitive matching.
static std::string toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return static_cast<char>(::tolower(c)); });
    return out;
}

// Checks whether a lowercased filename ends with ".exe".
static bool hasExeExtension(const std::string& lowerName) {
    const size_t n = lowerName.size();
    return n >= 4 && lowerName.compare(n-4, 4, ".exe") == 0;
}

// Returns this tool's own image name (basename) in lowercase.
// Used to exclude the detector itself from the [unknown] list.
static std::string selfImageNameLower() {
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return {};
    std::string path(buf, buf + len);
    size_t pos = path.find_last_of("\\/");
    std::string base = (pos == std::string::npos) ? path : path.substr(pos+1);
    return toLower(base);
}

// Converts a UTF-16 buffer segment to UTF-8.
// Used after retrieving the command line via NtQueryInformationProcess.
static std::string wideToUtf8(const WCHAR* wstr, size_t wlen) {
    if (!wstr || wlen == 0) return {};
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string out(bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, (int)wlen, out.data(), bytes, nullptr, nullptr);
    return out;
}

// Right-truncates a string to maxLen, appending "..." when possible.
static std::string truncateRight(const std::string& s, size_t maxLen) {
    if (maxLen == kNoLimit) return s;
    if (s.size() <= maxLen) return s;
    if (maxLen <= 3) return s.substr(0, maxLen);
    return s.substr(0, maxLen - 3) + "...";
}

// Normalizes whitespace: converts CR/LF/TAB to spaces, collapses repeats, trims ends.
// Ensures cmd/bin/img fields are monoline and stable for parsers.
// Important: when the result is empty or all spaces, returns an empty string.
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

    // trim (safe even if out is empty or all spaces)
    const size_t first = out.find_first_not_of(' ');
    if (first == std::string::npos) return {};
    out.erase(0, first);
    const size_t last = out.find_last_not_of(' ');
    out.erase(last + 1);

    return out;
}

// Removes symmetric outer quotes if present, without touching internal quotes.
// Also tolerates common "broken" cases (single leading/trailing quote) to keep output clean.
// This is output-sanitization, not a security feature.
static std::string stripOuterQuotes(std::string s) {
    if (s.size() >= 2) {
        const char a = s.front();
        const char b = s.back();

        // Clean case: "..." or '...'
        if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
            s = s.substr(1, s.size() - 2);
            return s;
        }

        // Tolerant case: single quote at either end
        if (a == '"' || a == '\'') s.erase(0, 1);
        if (!s.empty()) {
            const char last = s.back();
            if (last == '"' || last == '\'') s.pop_back();
        }
    }
    return s;
}

// Removes quotes around the *first token* if it looks like a quoted path.
// Handles:  "\"C:\\Program Files\\App\\app.exe\" --arg"  ->  "C:\\Program Files\\App\\app.exe --arg"
static std::string stripQuotedFirstToken(std::string s) {
    if (s.size() < 2) return s;

    const char q = s.front();
    if (q != '"' && q != '\'') return s;

    const size_t end = s.find(q, 1);
    if (end == std::string::npos) {
        // Broken input: starts with quote but never closes -> drop the leading quote
        s.erase(0, 1);
        return s;
    }

    // Remove closing quote first, then opening quote (indices stay valid)
    s.erase(end, 1);
    s.erase(0, 1);
    return s;
}

// -------------------- baselines --------------------

// Baseline list of core Windows processes (noise suppression).
// Anything in this set will NOT be listed under [unknown].
// Keep this conservative: removing too much can hide interesting processes.
static const std::unordered_set<std::string>& baselineSystem() {
    static const std::unordered_set<std::string> base = {

            // core / session
            "system","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe","winlogon.exe",

            // service hosts / brokers
            "svchost.exe","fontdrvhost.exe","spoolsv.exe","wudfhost.exe",
            "dllhost.exe","audiodg.exe",

            // shell / UX
            "explorer.exe","sihost.exe","ctfmon.exe","dwm.exe","runtimebroker.exe",
            "shellexperiencehost.exe","startmenuexperiencehost.exe",
            "searchhost.exe","searchindexer.exe","searchprotocolhost.exe",
            "systemsettings.exe","systemsettingsbroker.exe",
            "backgroundtaskhost.exe","lockapp.exe","textinputhost.exe",
            "presentationfontcache.exe","shellhost.exe",

            // console / base utilities
            "cmd.exe","conhost.exe","taskhostw.exe","taskmgr.exe","rundll32.exe",
            "werfault.exe",

            // WMI / telemetry / compatibility
            "wmiprvse.exe","wmiapsrv.exe","compattelrunner.exe","wmiregistrationservice.exe",
            "lsaiso.exe","ngciso.exe","unsecapp.exe",

            // printing / WOW64 bridge
            "splwow64.exe",

            // UWP / SystemApps
            "applicationframehost.exe","aggregatorhost.exe","dataexchangehost.exe","dashost.exe",
            "appactions.exe","crossdeviceresume.exe","calendar.exe",
            "phoneexperiencehost.exe","storedesktopextension.exe",
            "pacjsworker.exe","chxsmartscreen.exe",

            // security UX (still system)
            "smartscreen.exe",
            "microsoft.aad.brokerplugin.exe","msedgewebview2.exe",

            // Hyper-V / WSL infra
            "vmcompute.exe","vmms.exe","vmwp.exe","vmmemwsl","wslinstaller.exe",

            // WLAN / networking infra
            "wlanext.exe",

            // other native components
            "locationnotificationwindows.exe",
            "mmgaserver.exe",
            "modemauthenticator.exe"
    };
    return base;
}

// Baseline list of common end-user applications (noise suppression).
// This is NOT a security allow-list; it's purely triage noise control.
static const std::unordered_set<std::string>& baselineCommonApps() {
    static const std::unordered_set<std::string> base = {

            // Browsers
            "msedge.exe","chrome.exe","firefox.exe","brave.exe",
            "opera.exe","vivaldi.exe","duckduckgo.exe",

            // Browser helpers / crash handlers
            "bravecrashhandler.exe","bravecrashhandler64.exe",
            "duckduckgo.updater.exe",
            "crashpad_handler.exe",

            // Office / productivity
            "winword.exe","excel.exe","powerpnt.exe","onenote.exe","outlook.exe",
            "officeclicktorun.exe","filecoauth.exe",

            // Collaboration / IM
            "teams.exe","ms-teams.exe","skype.exe","skypeapp.exe",
            "telegram.exe","slack.exe","discord.exe","whatsapp.exe","signal.exe",

            // Modern terminal / dev UX
            "openconsole.exe","windowsterminal.exe",
            "windowspackagemanagerserver.exe"
    };
    return base;
}


// Pseudo-process names sometimes shown by tooling/logs.
// Toolhelp snapshot typically returns real image names, but this helps suppress noise.
static const std::unordered_set<std::string>& pseudoKernelNames() {
    static const std::unordered_set<std::string> s = {
            "[system process]", "registry", "memory compression", "secure system"
    };
    return s;
}

// -------------------- cmdline best-effort --------------------

// Minimal NT definitions (avoids pulling full NT headers).
using NTSTATUS = LONG;

struct UNICODE_STRING_LITE {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

#ifdef __MINGW32__
// MinGW: direct import from ntdll (linked via -lntdll, cleaner import table).
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
);
#else
// MSVC: ntdll.lib from the SDK does not export Nt* functions,
// so we resolve at runtime. Wrapped as a static function with the same
// name so callers don't need to care which path is used.
using PFN_NtQIP_ = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static PFN_NtQIP_ resolveNtQIP_() {
    FARPROC p = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    return reinterpret_cast<PFN_NtQIP_>(reinterpret_cast<void*>(p));
}
static NTSTATUS NtQueryInformationProcess(
        HANDLE h, ULONG cls, PVOID info, ULONG len, PULONG ret) {
    static PFN_NtQIP_ fn = resolveNtQIP_();
    if (!fn) return static_cast<NTSTATUS>(-1);
    return fn(h, cls, info, len, ret);
}
#endif


// Fallback: full image path (does not require VM_READ).
// Requires only PROCESS_QUERY_LIMITED_INFORMATION.
static std::string queryFullImagePathUtf8(DWORD pid) {
    HandleGuard h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) return {};
    char buf[MAX_PATH];
    DWORD sz = MAX_PATH;
    std::string out;
    if (QueryFullProcessImageNameA(h, 0, buf, &sz) && sz > 0) {
        out.assign(buf, buf + sz);
    }
    return out;
}

// Best-effort cmdline extraction via NtQueryInformationProcess(ProcessCommandLineInformation=60).
// - No SeDebugPrivilege: low-noise profile (less friction in real environments).
// - May fail on protected processes (PPL) or due to permissions.
// - Attempts PROCESS_VM_READ first for compatibility; falls back to limited info.
static std::string tryGetCmdlineUtf8(DWORD pid) {
    HandleGuard h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!h) {
        h = HandleGuard(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!h) return {};
    }

    const ULONG ProcessCommandLineInformation = 60;
    ULONG len = 0;

    NtQueryInformationProcess(h, ProcessCommandLineInformation, nullptr, 0, &len);
    if (len == 0) return {};

    std::vector<BYTE> buf(len);
    NTSTATUS st = NtQueryInformationProcess(h, ProcessCommandLineInformation, buf.data(), len, &len);

    if (st < 0) return {};
    if (len < sizeof(UNICODE_STRING_LITE)) return {};

    auto u = reinterpret_cast<UNICODE_STRING_LITE*>(buf.data());
    if (!u->Buffer || u->Length == 0) return {};

    // Validate that Buffer points within our allocation
    const auto* allocStart = reinterpret_cast<const WCHAR*>(buf.data());
    const auto* allocEnd   = reinterpret_cast<const WCHAR*>(buf.data() + len);
    const size_t wlen = static_cast<size_t>(u->Length) / sizeof(WCHAR);
    if (u->Buffer < allocStart || u->Buffer + wlen > allocEnd) return {};

    return wideToUtf8(u->Buffer, wlen);
}


// -------------------- Services tool SCM index (PID -> ServiceInfo) --------------------
//
// Builds a PID -> ServiceInfo index from the Service Control Manager.
// - Heavier than a process snapshot, so it is built lazily and cached (static).
// - Useful enrichment when cmdline cannot be read: svc/bin provides actionable context.
static const std::unordered_map<DWORD, ServiceInfo>& serviceIndexByPid() {
    static bool built = false;
    static std::unordered_map<DWORD, ServiceInfo> idx;
    if (built) return idx;
    built = true;

    ScHandleGuard scm(OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (!scm) return idx;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExA(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            nullptr, 0, &bytesNeeded, &count, &resume, nullptr
    );
    if (bytesNeeded == 0) return idx;

    std::vector<BYTE> buf(bytesNeeded);
    if (!EnumServicesStatusExA(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
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
            ScHandleGuard svc(OpenServiceA(scm, svcName, SERVICE_QUERY_CONFIG));
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

    return idx;
}

// -------------------- output helpers --------------------

// Builds a stable detection line:
//   "[TAG] ProductName - exe=ImageName"
static std::string buildDetectionLine(const std::string& tagLabel,
                                      const std::string& productName,
                                      const std::string& exeName,
                                      size_t maxLen = kLineMax) {
    const std::string prefix = "[" + tagLabel + "] ";
    const std::string middle = " - ";
    size_t fixed = prefix.size() + middle.size() + exeName.size();
    size_t budgetName = (fixed >= maxLen) ? 0 : (maxLen - fixed);

    std::string pname = (productName.size() <= budgetName)
                        ? productName
                        : truncateRight(productName, budgetName);

    return prefix + pname + middle + exeName;
}

// Pre-fetched enrichment data for an unknown process.
struct UnknownProcess {
    std::string exeLower;
    DWORD pid = 0;
    std::string cmdline;
    bool hasService = false;
    std::string svcName;
    int svcExtraCount = 0;
    std::string svcBinary;
    std::string imagePath;
};

// Builds an "unknown process" line from pre-fetched data:
//   "- exeLower | cmd=..."
//   "- exeLower | svc=... | bin=..."
//   "- exeLower | img=..."
// Field selection is best-effort, in priority order.
static std::string buildUnknownLine(const UnknownProcess& proc,
                                    size_t maxLen = kLineMax)
{
    std::string line = "- " + proc.exeLower;

    // 1) cmd= (best triage signal)
    if (!proc.cmdline.empty()) {
        std::string cmd = collapseWs(stripOuterQuotes(stripQuotedFirstToken(proc.cmdline)));
        const std::string pfx = " | cmd=";

        const size_t fixed = line.size() + pfx.size();
        const size_t budget = (fixed >= maxLen) ? 0 : (maxLen - fixed);
        if (budget > 0) line += pfx + truncateRight(cmd, budget);
        return line;
    }

    // 2) SCM svc/bin
    if (proc.hasService) {
        std::string svc = proc.svcName;
        if (proc.svcExtraCount > 0) {
            svc += "(+" + std::to_string(proc.svcExtraCount) + ")";
        }

        const std::string partSvc = " | svc=" + svc;

        size_t budget = (line.size() >= maxLen) ? 0 : (maxLen - line.size());
        if (budget > 0) {
            if (partSvc.size() <= budget) {
                line += partSvc;
                budget -= partSvc.size();
            } else {
                const std::string pfx = " | svc=";
                const size_t avail = (budget > pfx.size()) ? (budget - pfx.size()) : 0;
                line += pfx + truncateRight(svc, avail);
                budget = 0;
            }
        }

        if (budget > 0 && !proc.svcBinary.empty()) {
            std::string bin = collapseWs(stripOuterQuotes(stripQuotedFirstToken(proc.svcBinary)));
            const std::string pfx = " | bin=";

            const size_t fixed2 = line.size() + pfx.size();
            const size_t b2 = (fixed2 >= maxLen) ? 0 : (maxLen - fixed2);
            if (b2 > 0) line += pfx + truncateRight(bin, b2);
        }

        return line;
    }

    // 3) img= full path
    if (!proc.imagePath.empty()) {
        std::string img = collapseWs(stripOuterQuotes(stripQuotedFirstToken(proc.imagePath)));
        const std::string pfx = " | img=";

        const size_t fixed = line.size() + pfx.size();
        const size_t budget = (fixed >= maxLen) ? 0 : (maxLen - fixed);
        if (budget > 0) line += pfx + truncateRight(img, budget);
    }

    return line;
}

// -------------------- catalog (exeLower -> products) --------------------
//
// Notes:
// - Exact match on lowercased ".exe" image name.
// - One executable may map to multiple products/labels.
// - This catalog is intentionally opinionated: it is a triage tool, not an AV engine.
static const std::unordered_map<std::string, std::vector<SecuritySoftware>>& catalog() {
    static const std::unordered_map<std::string, std::vector<SecuritySoftware>> sw = {

            // VPN / ZTNA
            {"vpnagent.exe", { {"Cisco AnyConnect / Secure Client","VPN","VPN"} }},
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

            // Pulse Secure / Ivanti
            {"pulse.exe",        { {"Pulse Secure VPN Client","VPN","VPN"} }},
            {"pulsesecureservice.exe",{ {"Pulse Secure Service","VPN","VPN"} }},

            // Cisco Secure Client (rebrand of AnyConnect)
            {"csc_iseagent.exe", { {"Cisco Secure Client ISE Agent","ZTNA / NAC","ZTNA"} }},
            {"csc_iseposture.exe",{ {"Cisco Secure Client ISE Posture","ZTNA / NAC","ZTNA"} }},
            {"csc_ui.exe",       { {"Cisco Secure Client UI","VPN / ZTNA","VPN"} }},

            // OpenVPN (GUI)
            {"openvpn-gui.exe",  { {"OpenVPN GUI","VPN","VPN"} }},

            // Citrix Workspace / ICA Client
            {"receiver.exe",     { {"Citrix Workspace Receiver","VDI / ZTNA","ZTNA"} }},
            {"selfservice.exe",  { {"Citrix Workspace Self-Service","VDI / ZTNA","ZTNA"} }},
            {"selfserviceplugin.exe",{ {"Citrix Workspace Self-Service Plugin","VDI / ZTNA","ZTNA"} }},
            {"wfcrun32.exe",     { {"Citrix ICA Client Runtime","VDI / ZTNA","ZTNA"} }},
            {"ssonsvr.exe",      { {"Citrix Single Sign-On","VDI / ZTNA","ZTNA"} }},
            {"redirector.exe",   { {"Citrix Redirector","VDI / ZTNA","ZTNA"} }},
            {"authmansvr.exe",   { {"Citrix Authentication Manager","VDI / ZTNA","ZTNA"} }},
            {"analyticssrv.exe", { {"Citrix Analytics Service","VDI / ZTNA","ZTNA"} }},

            // Zscaler ZDP (Digital Experience) + core services
            {"zdpapp.exe",       { {"Zscaler Digital Experience App","ZTNA / DX Monitoring","ZTNA"} }},
            {"zdpclassifier.exe",{ {"Zscaler Digital Experience Classifier","ZTNA / DX Monitoring","ZTNA"} }},
            {"zdpservice.exe",   { {"Zscaler Digital Experience Service","ZTNA / DX Monitoring","ZTNA"} }},
            {"zsaservice.exe",   { {"Zscaler Service Agent","ZTNA / SWG","ZTNA"} }},
            {"zsatunnel.exe",    { {"Zscaler Tunnel Agent","ZTNA / SWG","ZTNA"} }},

            // ZTNA / CASB / DLP (Netskope)
            {"stagentsvc.exe", {{"Netskope Client Service","ZTNA / CASB / DLP","ZTNA"}}},
            {"stagentae.exe", {{"Netskope Agent Engine","ZTNA / CASB / DLP","ZTNA"}}},
            {"stagentui.exe", {{"Netskope Client UI","ZTNA / CASB / DLP","ZTNA"}}},
            {"nssm.exe", {    {"NSSM (Non-Sucking Service Manager)","Service Wrapper / Persistence Helper","OTHER"} }},

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
            {"sentinelhelperservice.exe",{ {"SentinelOne Helper Service","EDR / XDR","EDR"} }},
            {"sentinelui.exe",   { {"SentinelOne UI","EDR / XDR","EDR"} }},

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

            // McAfee / Trellix DLP
            {"fcag.exe",         { {"McAfee/Trellix DLP Agent","DLP","DLP"} }},
            {"fcags.exe",        { {"McAfee/Trellix DLP Agent Service","DLP","DLP"} }},
            {"fcagswd.exe",      { {"McAfee/Trellix DLP Agent Watchdog","DLP","DLP"} }},
            {"fcnm.exe",         { {"McAfee/Trellix DLP Network Monitor","DLP","DLP"} }},
            {"fcom.exe",         { {"McAfee/Trellix DLP Orchestrator","DLP","DLP"} }},

            // McAfee Endpoint Encryption (extra components)
            {"epepcmonitor.exe", { {"McAfee Endpoint Encryption PC Monitor","Disk Encryption","ENC"} }},
            {"toast32.exe",      { {"McAfee Endpoint Encryption Notification","Disk Encryption","ENC"} }},

            // McAfee / Trellix Agent (extra components)
            {"macompatsvc.exe",  { {"McAfee Agent Compatibility Service","AV / Agent","AV"} }},
            {"updaterui.exe",    { {"McAfee Agent Updater UI","AV / Agent","AV"} }},
            {"mctray.exe",       { {"McAfee Agent Tray","AV / Agent","AV"} }},

            // Microsoft Defender DLP components
            {"dlpuseragent.exe", {{"Microsoft Defender DLP User Agent","Data Loss Prevention","DLP"}}},
            {"mpdlpservice.exe", {{"Microsoft Defender DLP Service","Data Loss Prevention","DLP"}}},
            {"sensedlpprocessor.exe", {{"Microsoft Defender DLP Processor","Data Loss Prevention","DLP"}}},

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
            {"avp.exe", { {"Kaspersky AV / KES","AV / EDR","AV"} }},
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

            // DLP / encryption
            {"axcrypt.exe",{ {"AxCrypt","Encryption","ENC"} }},
            {"truecrypt.exe",{ {"TrueCrypt","Encryption","ENC"} }},
            {"eegoservice.exe",{ {"McAfee Endpoint Encryption Service","Disk Encryption","ENC"} }},

            // Monitoring / telemetry
            {"healthservice.exe",{ {"Microsoft OMS / SCOM HealthService","Monitoring","MON"} }},
            {"monitoringhost.exe",{ {"Microsoft Monitoring Agent","Monitoring","MON"} }},
            {"npmdagent.exe",{ {"SolarWinds NPM Agent","Network Monitoring","MON"} }},
            {"nxlog.exe",        { {"nxlog Log Forwarder","Log Collection / SIEM","TEL"} }},

            // Virtualization (VMware, WSL)
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

            // TeamViewer (client + helpers)
            {"teamviewer.exe",   { {"TeamViewer Client","Remote Control / RMM","RMM"} }},
            {"tv_w32.exe",       { {"TeamViewer Helper (32-bit)","Remote Control / RMM","RMM"} }},
            {"tv_x64.exe",       { {"TeamViewer Helper (64-bit)","Remote Control / RMM","RMM"} }},

            // IBM Tivoli Remote Control
            {"trc_base.exe",     { {"IBM Tivoli Remote Control Service","Remote Control / RMM","RMM"} }},
            {"trc_gui.exe",      { {"IBM Tivoli Remote Control GUI","Remote Control / RMM","RMM"} }},

            // Integrity / system guard broker
            {"sgrmbroker.exe", { {"Windows System Guard Runtime Monitor Broker","System Integrity","INT"} }},

            // Misc useful
            {"sbiesvc.exe",    { {"Sandboxie Service","Sandbox / Isolation","OTHER"} }},
            {"winlogbeat.exe", { {"Elastic Winlogbeat (log forwarder)","Security Telemetry","TEL"} }},
            {"mdnsresponder.exe",{ {"Bonjour Service","Network Service / mDNS","OTHER"} }},
            {"smsvchost.exe",  { {"Microsoft .NET Framework service host","Application","OTHER"} }},

            // Cloud sync clients
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
            {"oneapp.igcc.winservice.exe",{ {"Intel Graphics Command Center Service","GPU Runtime","GPU"} }},
            {"intelcphdcpsvc.exe",{ {"Intel Content Protection HDCP Service","DRM / Content Protection","DRM"} }},
            {"intelcphecisvc.exe",{ {"Intel Component Helper Service","DRM / Content Protection","DRM"} }},
            {"ipoverusbsvc.exe", { {"Microsoft IP over USB","USB networking","USB"} }},
            {"jhi_service.exe",  { {"Intel Dynamic Application Loader (HECI)","OEM Management","OEM"} }},
            {"rtkauduservice64.exe",{ {"Realtek Audio Universal Service","Audio Driver","AUDIO"} }},
            {"ss_conn_service.exe",{ {"Samsung USB Driver Service","USB / Android","USB"} }},
            {"ss_conn_service2.exe",{ {"Samsung USB Driver Service (alt)","USB / Android","USB"} }},

            // OEM / Synaptics
            {"syntpenh.exe",     { {"Synaptics TouchPad Enhancements","OEM Input","OEM"} }},
            {"syntpenhservice.exe",{ {"Synaptics TouchPad Service","OEM Input","OEM"} }},
            {"synrpcserver.exe", { {"Synology Assistant RPC Service","NAS Discovery","NAS"} }},
            {"tbtp2pshortcutservice.exe",{ {"Intel Thunderbolt P2P Shortcut Service","Thunderbolt","TB"} }},
            {"thunderboltservice.exe",{ {"Intel Thunderbolt Service","Thunderbolt","TB"} }},

            // OEM / Lenovo (additional)
            {"lenovoaiccloader.exe",{ {"Lenovo AI Core Components","OEM Configuration","OEM"} }},
            {"lenovovisionservice.exe",{ {"Lenovo Vision Service","OEM Camera/Vision","OEM"} }},
            {"smartstandby.exe", { {"Lenovo Smart Standby","OEM Power","OEM"} }},
            {"litssvc.exe",      { {"Lenovo Intelligent Thermal Solution","OEM Thermal","OEM"} }},
            {"epdctrl.exe",      { {"Lenovo ePrivacy Display Control","OEM Privacy Screen","OEM"} }},
            {"epdservice.exe",   { {"Lenovo ePrivacy Display Service","OEM Privacy Screen","OEM"} }},
            {"dockmgr.exe",      { {"Lenovo Dock Manager","OEM Docking","OEM"} }},
            {"dockmgr.svc.exe",  { {"Lenovo Dock Manager Service","OEM Docking","OEM"} }},
            {"easyresume.exe",   { {"Lenovo Instant On / EasyResume","OEM Power","OEM"} }},

            // OEM / Intel (additional)
            {"intelaudioservice.exe",{ {"Intel Audio Service","Audio Driver","AUDIO"} }},
            {"ipf_helper.exe",   { {"Intel Platform Framework Helper","OEM Thermal/Power","OEM"} }},
            {"ipf_uf.exe",       { {"Intel Platform Framework User-Mode","OEM Thermal/Power","OEM"} }},
            {"ipfsvc.exe",       { {"Intel Platform Framework Service","OEM Thermal/Power","OEM"} }},
            {"lms.exe",          { {"Intel AMT Local Management Service","OEM Management","OEM"} }},

            // Audio (additional)
            {"elevoccontrolservice.exe",{ {"Elevoc Audio Control Service","Audio Processing","AUDIO"} }},
            {"senaryaudioapp.svc.exe",{ {"Senary Audio Service","Audio Processing","AUDIO"} }},

            // Credential managers (useful for DFIR / red team hygiene checks)
            {"keepass.exe",    { {"KeePass Password Safe 2","Credential Manager","CREDS"} }},
            {"keepassxc.exe",  { {"KeePassXC","Credential Manager","CREDS"} }},
            {"bitwarden.exe",  { {"Bitwarden","Credential Manager","CREDS"} }},
            {"1password.exe",  { {"1Password","Credential Manager","CREDS"} }},

            // PAM / Application Control (Thycotic / Arellia)
            {"arellia.agent.service.exe", {{"Thycotic / Arellia PAM Agent","PAM / Privileged Access","PAM"}}},
            {"arelliaacsvc.exe", {{"Thycotic / Arellia Application Control","Application Control","APPC"}}},

            // UEM / Endpoint Management (ManageEngine)
            {"dcagentservice.exe", {{"ManageEngine Endpoint Central Agent","UEM / Inventory / Monitoring","UEM"}}},
            {"dcinventory.exe", {{"ManageEngine Inventory Component","UEM / Inventory","UEM"}}},
            {"dcprocessmonitor.exe", {{"ManageEngine Process Monitor","UEM / Process Monitoring","UEM"}}},
            {"dcprocmon.exe", {{"ManageEngine Process Monitor (alt)","UEM / Process Monitoring","UEM"}}},
            {"dcswmeter.exe", {{"ManageEngine Software Metering","UEM / Software Metering","UEM"}}},
            {"dcondemand.exe", {{"ManageEngine On-Demand Agent","UEM / On-Demand","UEM"}}},
            {"uesagentservice.exe", {{"ManageEngine Unified Endpoint Security Agent","UEM / Security","UEM"}}},

            // Microsoft Endpoint Management (SCCM / Intune)
            {"ccmexec.exe",      { {"Microsoft SCCM Client","UEM / Endpoint Management","UEM"} }},
            {"scnotification.exe",{ {"Microsoft SCCM Notification","UEM / Endpoint Management","UEM"} }},
            {"microsoft.management.services.intunewindowsagent.exe",{ {"Microsoft Intune Management Agent","UEM / Endpoint Management","UEM"} }},

            // Vintegris ModuloM (authentication / security)
            {"rtocustodio.exe",  { {"Vintegris ModuloM Security Agent","Authentication / Security","OTHER"} }},
            {"rtosecstartsrv.exe",{ {"Vintegris ModuloM Security Service","Authentication / Security","OTHER"} }},

    };
    return sw;
}

// -------------------- scan result types --------------------

struct DetectionEntry {
    std::string tag;
    std::string productName;
    std::string exeName;     // original case
    std::string sortKey;     // pre-computed lowercase for sorting (#7)
};

struct ScanResult {
    std::vector<DetectionEntry> detections;
    std::vector<UnknownProcess> unknowns;
    bool anySecurity = false;
};

// -------------------- process scanning --------------------

static ScanResult scanProcesses() {
    ScanResult result;

    std::unordered_set<std::string> reported;
    std::unordered_map<std::string, DWORD> firstPidByExe;  // #9: unordered_map

    const auto& sw = catalog();

    HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return result;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snap, &pe)) return result;

    do {
        std::string exe(pe.szExeFile);
        std::string lower = toLower(exe);

        if (firstPidByExe.find(lower) == firstPidByExe.end()) {
            firstPidByExe[lower] = pe.th32ProcessID;
        }

        if (reported.find(lower) == reported.end()) {
            auto it = sw.find(lower);
            if (it != sw.end()) {
                result.anySecurity = true;

                for (const auto& x : it->second) {
                    DetectionEntry entry;
                    entry.tag = x.tag.empty() ? "OTHER" : x.tag;
                    entry.productName = x.name;
                    entry.exeName = exe;
                    entry.sortKey = toLower(
                            "[" + entry.tag + "] " + entry.productName + " - " + entry.exeName);
                    result.detections.push_back(std::move(entry));
                }

                reported.insert(lower);
            }
        }
    } while (Process32Next(snap, &pe));

    // Sort detections using pre-computed keys (#7: no per-comparison allocation)
    std::sort(result.detections.begin(), result.detections.end(),
              [](const DetectionEntry& a, const DetectionEntry& b) {
                  return a.sortKey < b.sortKey;
              });

    // Build unknown list
    const std::string selfLower = selfImageNameLower();
    const auto& pseudo  = pseudoKernelNames();
    const auto& sysBase = baselineSystem();
    const auto& appBase = baselineCommonApps();
    const auto& svcIdx  = serviceIndexByPid();

    std::vector<std::pair<std::string, DWORD>> unknownPids;
    unknownPids.reserve(firstPidByExe.size());

    for (const auto& [p, pid] : firstPidByExe) {
        if (p == selfLower) continue;
        if (pseudo.count(p))  continue;
        if (sw.count(p))      continue;
        if (sysBase.count(p)) continue;
        if (appBase.count(p)) continue;
        if (!hasExeExtension(p)) continue;
        unknownPids.emplace_back(p, pid);
    }

    std::sort(unknownPids.begin(), unknownPids.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    // Enrich unknown processes once (reused for both stdout and file output)
    result.unknowns.reserve(unknownPids.size());
    for (const auto& [exe, pid] : unknownPids) {
        UnknownProcess up;
        up.exeLower = exe;
        up.pid = pid;

        up.cmdline = tryGetCmdlineUtf8(pid);

        if (up.cmdline.empty()) {
            auto svcIt = svcIdx.find(pid);
            if (svcIt != svcIdx.end()) {
                up.hasService = true;
                up.svcName = svcIt->second.name;
                up.svcExtraCount = svcIt->second.extra_count;
                up.svcBinary = svcIt->second.binary;
            } else {
                up.imagePath = queryFullImagePathUtf8(pid);
            }
        }

        result.unknowns.push_back(std::move(up));
    }

    return result;
}

// -------------------- output --------------------

static void printResults(std::ostream& os, const ScanResult& result, size_t maxLen) {
    os << "\n[unknown] Non-system unknown processes (" << result.unknowns.size() << "):" << std::endl;
    for (const auto& u : result.unknowns) {
        os << buildUnknownLine(u, maxLen) << std::endl;
    }
    os << "\n---\n\n";

    for (const auto& d : result.detections) {
        os << buildDetectionLine(d.tag, d.productName, d.exeName, maxLen) << std::endl;
    }
}

// -------------------- program entry point --------------------
int main(int argc, char** argv) {
    SetConsoleOutputCP(65001);
    std::cout << "AV_detect Version: " << VERSION << std::endl;

    // Optional: --full <path>
    std::ofstream fullOut;
    bool writeFull = false;

    if (argc == 3 && std::string(argv[1]) == "--full") {
        fullOut.open(argv[2], std::ios::out | std::ios::trunc);
        if (fullOut.is_open()) {
            writeFull = true;
        } else {
            std::cerr << "Warning: could not open '" << argv[2] << "' for writing.\n";
        }
    }

    // Single snapshot: scan once, output twice (#4: consistent results)
    const ScanResult result = scanProcesses();

    printResults(std::cout, result, kLineMax);

    if (writeFull) {
        fullOut << "AV_detect Version: " << VERSION << "\n";
        printResults(fullOut, result, kNoLimit);
    }

    std::cout << (result.anySecurity
                  ? "\nFound known processes or security software processes (AV, anti-malware, EDR, XDR, etc.) running.\n"
                  : "\nNo security software processes (AV, anti-malware, EDR, XDR, etc.) were found running.\n");
    return 0;
}

