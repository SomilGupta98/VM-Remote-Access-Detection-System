#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

// ---------- Helper: simple struct for checks ----------
struct CheckResult {
    std::string name;
    bool risk;              // true = RISK, false = OK
    std::string detail;     // extra info if any
};

// ---------- Helper: process detection ----------
bool IsProcessRunning(const std::wstring& name) {
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

bool AnyProcessRunning(const std::vector<std::wstring>& names, std::wstring& which) {
    for (const auto& n : names) {
        if (IsProcessRunning(n)) {
            which = n;
            return true;
        }
    }
    return false;
}

// ---------- Helper: RDP detection ----------
CheckResult CheckRdp() {
    bool remote = GetSystemMetrics(SM_REMOTESESSION) != 0;
    CheckResult r;
    r.name = "RDP (Remote Desktop Session)";
    r.risk = remote;
    r.detail = remote ? "Current session is a remote desktop session." : "Local console session.";
    return r;
}

// ---------- Helper: Remote tools ----------
CheckResult CheckRemoteTools() {
    std::vector<std::wstring> remoteNames = {
        L"AnyDesk.exe", L"ad_svc.exe",
        L"TeamViewer.exe", L"TeamViewer_Service.exe",
        L"winvnc.exe", L"tvnserver.exe", L"uvnc_service.exe", L"tightvnc.exe", L"vncserver.exe",
        L"remoting_host.exe",          // Chrome Remote Desktop
        L"QuickAssist.exe", L"RemoteHelp.exe",
        L"RustDesk.exe", L"rustdesk.exe",
        L"ZohoAssist.exe", L"ZohoAssist10.exe",
        L"Splashtop.exe", L"SRServer.exe",
        L"DWRCS.exe", L"DWRCST.exe",   // DameWare / DWService / Remote utilities (some variants)
        L"rutserv.exe", L"rutview.exe" // Remote Utilities
    };

    std::wstring hit;
    bool found = AnyProcessRunning(remoteNames, hit);

    CheckResult r;
    r.name = "Remote Access Tools (AnyDesk/TeamViewer/VNC/etc.)";
    r.risk = found;
    if (found) {
        std::wstring w = L"Detected process: " + hit;
        r.detail = std::string(w.begin(), w.end());
    } else {
        r.detail = "No known remote access processes detected.";
    }
    return r;
}

// ---------- Helper: Virtual Machine detection ----------
bool IsHypervisorPresent() {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    // ECX bit 31 = hypervisor present
    return (cpuInfo[2] & (1 << 31)) != 0;
}

CheckResult CheckVirtualMachine() {
    bool hv = IsHypervisorPresent();

    // Also check some common VM processes
    std::vector<std::wstring> vmNames = {
        L"vmtoolsd.exe", L"vmware.exe", L"vmware-vmx.exe",
        L"vboxservice.exe", L"vboxtray.exe",
        L"qemu-ga.exe", L"qemu-system-x86_64.exe",
        L"vmsrvc.exe", L"vpcmap.exe", // old Virtual PC
        L"prl_tools.exe" // Parallels tools
    };
    std::wstring vmHit;
    bool vmProc = AnyProcessRunning(vmNames, vmHit);

    CheckResult r;
    r.name = "Virtual Machine / Sandbox Environment";
    r.risk = hv || vmProc;

    if (hv && vmProc) {
        std::wstring w = L"Hypervisor bit set; VM process detected: " + vmHit;
        r.detail = std::string(w.begin(), w.end());
    } else if (hv) {
        r.detail = "CPU hypervisor bit is set (running inside a VM).";
    } else if (vmProc) {
        std::wstring w = L"Detected VM-related process: " + vmHit;
        r.detail = std::string(w.begin(), w.end());
    } else {
        r.detail = "No obvious VM indicators detected.";
    }
    return r;
}

// ---------- Helper: Screen recorders / streaming ----------
CheckResult CheckScreenRecorders() {
    std::vector<std::wstring> recNames = {
        L"obs64.exe", L"obs32.exe",
        L"Streamlabs OBS.exe", L"slobs.exe",
        L"GameBar.exe", L"GameBarFTServer.exe", L"GamebarPresenceWriter.exe",
        L"NvidiaShare.exe", L"nvsphelper64.exe",
        L"RadeonSoftware.exe", L"Radeonsettings.exe",
        L"bandicam.exe",
        L"camtasiaStudio.exe", L"camtasia.exe",
        L"XSplit.Core.exe", L"XSplit.Gamecaster.exe",
        L"flashbackrecorder.exe",
        L"ScreenRecorder.exe"
    };

    std::wstring hit;
    bool found = AnyProcessRunning(recNames, hit);

    CheckResult r;
    r.name = "Screen Recording / Streaming Software";
    r.risk = found;
    if (found) {
        std::wstring w = L"Detected process: " + hit;
        r.detail = std::string(w.begin(), w.end());
    } else {
        r.detail = "No known screen recorders detected.";
    }
    return r;
}

// ---------- Helper: Macro / automation tools ----------
CheckResult CheckMacroTools() {
    std::vector<std::wstring> macroNames = {
        L"AutoHotkey.exe", L"AutoHotkeyU64.exe", L"AutoHotkeyU32.exe",
        L"MacroRecorder.exe",
        L"TinyTask.exe",
        L"PuloverMacroCreator.exe"
    };

    std::wstring hit;
    bool found = AnyProcessRunning(macroNames, hit);

    CheckResult r;
    r.name = "Macro / Automation Tools (AutoHotkey, etc.)";
    r.risk = found;
    if (found) {
        std::wstring w = L"Detected process: " + hit;
        r.detail = std::string(w.begin(), w.end());
    } else {
        r.detail = "No common macro tools detected.";
    }
    return r;
}

// ---------- Helper: VPN detection (process-based) ----------
CheckResult CheckVpn() {
    std::vector<std::wstring> vpnNames = {
        L"openvpn.exe",
        L"NordVPN.exe", L"NordVPN.NetworkService.exe",
        L"ProtonVPN.exe",
        L"expressvpn.exe",
        L"pia-client.exe",      // Private Internet Access
        L"pia-nw.exe",
        L"wireguard.exe",
        L"CiscoAnyConnect.exe", L"vpnui.exe", L"vpnagent.exe",
        L"FortiClient.exe",
        L"GlobalProtect.exe",
        L"PulseSecure.exe",
        L"SoftEtherVPN.exe"
    };

    std::wstring hit;
    bool found = AnyProcessRunning(vpnNames, hit);

    CheckResult r;
    r.name = "VPN Software Running";
    r.risk = found;
    if (found) {
        std::wstring w = L"Detected process: " + hit;
        r.detail = std::string(w.begin(), w.end());
    } else {
        r.detail = "No common VPN processes detected.";
    }
    return r;
}

// ---------- Helper: Virtual / mirror displays ----------
bool HasVirtualMonitor() {
    DISPLAY_DEVICEW dd{};
    dd.cb = sizeof(dd);
    int i = 0;
    while (EnumDisplayDevicesW(NULL, i, &dd, 0)) {
        std::wstring dev = dd.DeviceString;
        if (dev.find(L"Virtual") != std::wstring::npos ||
            dev.find(L"RDP") != std::wstring::npos ||
            dev.find(L"Mirr") != std::wstring::npos ||
            dev.find(L"Splashtop") != std::wstring::npos ||
            dev.find(L"DISPLAYLINK") != std::wstring::npos) {
            return true;
        }
        i++;
    }
    return false;
}

CheckResult CheckVirtualDisplays() {
    bool virt = HasVirtualMonitor();
    CheckResult r;
    r.name = "Virtual / Remote / Mirror Display Drivers";
    r.risk = virt;
    r.detail = virt ? "Detected virtual or mirror display device." : "Only physical displays detected.";
    return r;
}

// ---------- Helper: Multiple monitors ----------
CheckResult CheckMultipleMonitors() {
    int monitors = GetSystemMetrics(SM_CMONITORS);
    CheckResult r;
    r.name = "Multiple Monitors Connected";
    r.risk = monitors > 1;
    if (monitors > 1) {
        r.detail = "Active monitors: " + std::to_string(monitors);
    } else {
        r.detail = "Single monitor in use.";
    }
    return r;
}

// ---------- Helper: Suspicious remote / idle input ----------
CheckResult CheckRemoteInputHeuristic() {
    LASTINPUTINFO li{ sizeof(li) };
    GetLastInputInfo(&li);
    DWORD idleMs = GetTickCount() - li.dwTime;

    // Very rough heuristic: long idle (e.g. > 20 sec)
    // during exam could mean remote control / unattended.
    bool suspicious = idleMs > 20000;

    CheckResult r;
    r.name = "Suspicious Idle / Remote Input Pattern";
    r.risk = suspicious;
    r.detail = "System idle for ~" + std::to_string(idleMs / 1000) + " seconds.";
    return r;
}

// ---------- Pretty printing ----------
void PrintResult(const CheckResult& r) {
    std::cout << (r.risk ? "[RISK] " : "[ OK ] ") << r.name << "\n";
    if (!r.detail.empty()) {
        std::cout << "       " << r.detail << "\n";
    }
    std::cout << "\n";
}


int main() {
    while (true) {
        // Clear screen for a fresh output
        system("cls");

        std::cout << "=====================================================\n";
        std::cout << "            EXAM SECURITY MASTER MONITOR\n";
        std::cout << "=====================================================\n";
        std::cout << "   (Press Q to quit)\n\n";

        std::vector<CheckResult> results;

        results.push_back(CheckRdp());
        results.push_back(CheckRemoteTools());
        results.push_back(CheckVirtualMachine());
        results.push_back(CheckScreenRecorders());
        results.push_back(CheckMacroTools());
        results.push_back(CheckVpn());
        results.push_back(CheckVirtualDisplays());
        results.push_back(CheckMultipleMonitors());
        results.push_back(CheckRemoteInputHeuristic());

        bool anyRisk = false;
        for (const auto& r : results) {
            PrintResult(r);
            if (r.risk) anyRisk = true;
        }

        std::cout << "=====================================================\n";
        if (anyRisk) {
            std::cout << "OVERALL STATUS: RISK DETECTED\n";
        } else {
            std::cout << "OVERALL STATUS: CLEAN (No obvious risks)\n";
        }
        std::cout << "=====================================================\n";
        std::cout << "\nRefreshing in 5 seconds... (Press Q to exit)\n";

        // Non-blocking quit check
        for (int i = 0; i < 50; i++) {
            if (GetAsyncKeyState('Q') & 0x8000) {
                system("cls");
                std::cout << "Exiting monitor...\n";
                return 0;
            }
            Sleep(100); // 0.1 sec × 50 = 5 seconds
        }
    }

    return 0;
}
