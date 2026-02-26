/**
 * @file firewall_helper.cpp
 * @brief Elevated helper to add Windows Firewall inbound rules for ExoSend
 *
 * v0.3: Migrated from port-based rules to program-based rules.
 * Rules are now scoped to Private+Domain profiles and LocalSubnet only,
 * removing the NET_FW_PROFILE2_ALL exposure on Public WiFi.
 *
 * Usage:
 *   --check         Returns 0 if program-based rules exist and are active.
 *   --check-rules   Returns 0 if ExoSend rule names exist (by name lookup).
 *   --install       Adds program-based inbound rules (requires admin).
 *   --remove        Removes ExoSend inbound rules (requires admin).
 *                   Also removes legacy v0.2 port-based rules during migration.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <netfw.h>
#include <combaseapi.h>
#include <oleauto.h>
#include <iostream>
#include <string>
#include <vector>

#include "exosend/config.h"

namespace {

struct ComInit {
    explicit ComInit(DWORD coinit = COINIT_APARTMENTTHREADED) : hr(CoInitializeEx(nullptr, coinit)) {}
    ~ComInit() {
        if (SUCCEEDED(hr)) {
            CoUninitialize();
        }
    }
    HRESULT hr;
};

struct AutoBstr {
    AutoBstr() : value(nullptr) {}
    explicit AutoBstr(const wchar_t* s) : value(SysAllocString(s)) {}
    ~AutoBstr() { SysFreeString(value); }
    AutoBstr(const AutoBstr&) = delete;
    AutoBstr& operator=(const AutoBstr&) = delete;
    operator BSTR() const { return value; }
    BSTR* out() { return &value; }
    BSTR value;
};

/// Returns the path to ExoSend.exe in the same directory as this helper.
static std::wstring getExoSendExePath() {
    wchar_t helperPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, helperPath, MAX_PATH);
    std::wstring path(helperPath);
    const auto lastSlash = path.rfind(L'\\');
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash + 1) + L"ExoSend.exe";
    }
    return L"ExoSend.exe";
}

/// Creates an inbound allow rule for ExoSend.exe if it doesn't already exist.
/// Scoped to Private+Domain profiles and LocalSubnet remote addresses.
/// Idempotent: skips creation if a rule with the same name already exists.
static bool ensureInboundProgramRule(INetFwPolicy2*       policy,
                                     const wchar_t*       ruleName,
                                     const wchar_t*       ruleDesc,
                                     const wchar_t*       exePath,
                                     NET_FW_IP_PROTOCOL_  protocol,
                                     std::wstring&        errorMsg) {
    if (!policy) { errorMsg = L"Policy is null"; return false; }

    INetFwRules* pRules = nullptr;
    HRESULT hr = policy->get_Rules(&pRules);
    if (FAILED(hr) || !pRules) { errorMsg = L"get_Rules failed"; return false; }

    // Idempotency: if the rule already exists by name, skip creation.
    INetFwRule* pExisting = nullptr;
    AutoBstr existName(ruleName);
    hr = pRules->Item(existName, &pExisting);
    if (SUCCEEDED(hr) && pExisting) {
        pExisting->Release();
        pRules->Release();
        std::wcout << L"[Firewall] Rule '" << ruleName << L"' already exists -- skipping\n";
        return true;
    }

    INetFwRule* pRule = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                          IID_PPV_ARGS(&pRule));
    if (FAILED(hr) || !pRule) {
        pRules->Release();
        errorMsg = L"CoCreateInstance(NetFwRule) failed";
        return false;
    }

    AutoBstr name(ruleName);
    AutoBstr desc(ruleDesc);
    AutoBstr app(exePath);
    AutoBstr remoteAddr(L"LocalSubnet");

    (void)pRule->put_Name(name);
    (void)pRule->put_Description(desc);
    (void)pRule->put_ApplicationName(app);
    (void)pRule->put_Protocol(protocol);
    (void)pRule->put_Direction(NET_FW_RULE_DIR_IN);
    (void)pRule->put_Action(NET_FW_ACTION_ALLOW);
    // Private + Domain only. Public WiFi profile deliberately excluded.
    (void)pRule->put_Profiles(NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_DOMAIN);
    (void)pRule->put_RemoteAddresses(remoteAddr);
    (void)pRule->put_Enabled(VARIANT_TRUE);
    (void)pRule->put_EdgeTraversal(VARIANT_FALSE);

    hr = pRules->Add(pRule);
    pRule->Release();
    pRules->Release();

    if (FAILED(hr)) {
        wchar_t buf[64];
        swprintf_s(buf, L"Add() failed: hr=0x%08lX", static_cast<unsigned long>(hr));
        errorMsg = buf;
        return false;
    }

    std::wcout << L"[Firewall] Created program rule '" << ruleName << L"' for " << exePath << L"\n";
    return true;
}

/// Returns true if a rule with the given name exists.
static bool programRuleExists(INetFwPolicy2* policy, const wchar_t* ruleName) {
    if (!policy) return false;
    INetFwRules* pRules = nullptr;
    if (FAILED(policy->get_Rules(&pRules)) || !pRules) return false;
    AutoBstr name(ruleName);
    INetFwRule* pRule = nullptr;
    const bool exists = SUCCEEDED(pRules->Item(name, &pRule)) && pRule != nullptr;
    if (pRule) pRule->Release();
    pRules->Release();
    return exists;
}

/// Removes a rule by name. Returns true if removed or not found (idempotent).
static bool removeNamedRule(INetFwPolicy2* policy, const wchar_t* ruleName) {
    if (!policy) return false;
    INetFwRules* pRules = nullptr;
    if (FAILED(policy->get_Rules(&pRules)) || !pRules) return false;
    AutoBstr name(ruleName);
    const HRESULT hr = pRules->Remove(name);
    pRules->Release();
    // ERROR_FILE_NOT_FOUND means rule didn't exist -- acceptable for idempotent remove.
    return SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

static HRESULT getPolicy(INetFwPolicy2** outPolicy) {
    if (!outPolicy) return E_POINTER;
    *outPolicy = nullptr;
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                            CLSCTX_INPROC_SERVER, IID_PPV_ARGS(outPolicy));
}

static void printUsage() {
    std::wcout << L"ExoSendFirewallHelper (v0.3)\n"
               << L"  --check         Returns 0 if program-based inbound rules exist.\n"
               << L"  --check-rules   Returns 0 if ExoSend rule names exist by name.\n"
               << L"  --install       Adds program-based inbound rules (requires admin).\n"
               << L"  --remove        Removes ExoSend rules incl. legacy v0.2 rules.\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    bool doCheck      = false;
    bool doCheckRules = false;
    bool doInstall    = false;
    bool doRemove     = false;

    if (argc <= 1) {
        printUsage();
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if      (arg == L"--check")       doCheck = true;
        else if (arg == L"--check-rules") doCheckRules = true;
        else if (arg == L"--install")     doInstall = true;
        else if (arg == L"--remove")      doRemove = true;
        else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            printUsage();
            return 0;
        } else {
            std::wcerr << L"Unknown argument: " << arg << L"\n";
            printUsage();
            return 1;
        }
    }

    ComInit com;
    if (FAILED(com.hr)) {
        std::wcerr << L"CoInitializeEx failed\n";
        return 1;
    }

    INetFwPolicy2* policy = nullptr;
    HRESULT hr = getPolicy(&policy);
    if (FAILED(hr) || !policy) {
        std::wcerr << L"Failed to open firewall policy\n";
        return 1;
    }

    // v0.3 program-based rule names.
    const wchar_t* udpRuleName = L"ExoSend UDP In";
    const wchar_t* tcpRuleName = L"ExoSend TCP In";

    if (doCheck) {
        // TCP port is now dynamic -- check by program rule existence instead of port number.
        const bool udpOk = programRuleExists(policy, udpRuleName);
        const bool tcpOk = programRuleExists(policy, tcpRuleName);
        policy->Release();
        std::wcout << L"ExoSend UDP In : " << (udpOk ? L"present" : L"MISSING") << L"\n";
        std::wcout << L"ExoSend TCP In : " << (tcpOk ? L"present" : L"MISSING") << L"\n";
        return (udpOk && tcpOk) ? 0 : 2;
    }

    if (doCheckRules) {
        const bool udpOk = programRuleExists(policy, udpRuleName);
        const bool tcpOk = programRuleExists(policy, tcpRuleName);
        policy->Release();
        std::wcout << L"ExoSend UDP In : " << (udpOk ? L"present" : L"MISSING") << L"\n";
        std::wcout << L"ExoSend TCP In : " << (tcpOk ? L"present" : L"MISSING") << L"\n";
        return (udpOk && tcpOk) ? 0 : 2;
    }

    if (doInstall) {
        const std::wstring exePath = getExoSendExePath();
        std::wstring err;
        bool ok = true;
        ok &= ensureInboundProgramRule(
            policy, udpRuleName,
            L"ExoSend LAN discovery -- UDP inbound (Private+Domain, LocalSubnet only)",
            exePath.c_str(), NET_FW_IP_PROTOCOL_UDP, err);
        ok &= ensureInboundProgramRule(
            policy, tcpRuleName,
            L"ExoSend LAN file transfer -- TCP inbound (Private+Domain, LocalSubnet only)",
            exePath.c_str(), NET_FW_IP_PROTOCOL_TCP, err);
        policy->Release();
        if (!ok) {
            std::wcerr << L"Install failed: " << err << L"\n";
            return 1;
        }
        return 0;
    }

    if (doRemove) {
        // Remove v0.3 program-based rules.
        removeNamedRule(policy, udpRuleName);
        removeNamedRule(policy, tcpRuleName);
        // Migration: also remove old v0.2 port-based rules if present.
        removeNamedRule(policy, L"ExoSend UDP Discovery (8888)");
        removeNamedRule(policy, L"ExoSend TCP Transfer (9999)");
        // Remove the catch-all rule created by the original installer netsh line.
        removeNamedRule(policy, L"ExoSend");
        policy->Release();
        std::wcout << L"[Firewall] ExoSend rules removed (incl. legacy v0.2 rules)\n";
        return 0;
    }

    policy->Release();
    printUsage();
    return 1;
}
