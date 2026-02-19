/**
 * @file firewall_helper.cpp
 * @brief Elevated helper to add Windows Firewall inbound rules for ExoSend ports
 *
 * This helper is intended to be launched with UAC elevation from the GUI.
 * It creates idempotent inbound allow rules for:
 * - UDP discovery port (default 8888)
 * - TCP transfer port (default 9999)
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

static std::wstring portToWString(int port) {
    return std::to_wstring(port);
}

static bool portListContains(const wchar_t* portList, int port) {
    if (!portList || portList[0] == L'\0') {
        return true;  // No explicit port restriction
    }

    std::wstring s(portList);
    for (auto& c : s) {
        if (c == L' ') c = L',';
    }

    if (s == L"*" || s == L"Any") {
        return true;
    }

    const std::wstring target = std::to_wstring(port);
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find(L',', start);
        if (end == std::wstring::npos) end = s.size();

        std::wstring token = s.substr(start, end - start);
        if (!token.empty()) {
            const size_t dash = token.find(L'-');
            if (dash == std::wstring::npos) {
                if (token == target) {
                    return true;
                }
            } else {
                const std::wstring a = token.substr(0, dash);
                const std::wstring b = token.substr(dash + 1);
                wchar_t* endPtrA = nullptr;
                wchar_t* endPtrB = nullptr;
                long pa = wcstol(a.c_str(), &endPtrA, 10);
                long pb = wcstol(b.c_str(), &endPtrB, 10);
                if (endPtrA && *endPtrA == L'\0' && endPtrB && *endPtrB == L'\0') {
                    if (pa <= port && port <= pb) {
                        return true;
                    }
                }
            }
        }

        start = end + 1;
    }

    return false;
}

static bool ruleAllowsPort(INetFwPolicy2* policy, INetFwRule* rule, long protocol, int port) {
    if (!policy || !rule) {
        return false;
    }

    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
    if (FAILED(rule->get_Direction(&direction)) || direction != NET_FW_RULE_DIR_IN) {
        return false;
    }

    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (FAILED(rule->get_Enabled(&enabled)) || enabled != VARIANT_TRUE) {
        return false;
    }

    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    if (FAILED(rule->get_Action(&action)) || action != NET_FW_ACTION_ALLOW) {
        return false;
    }

    long currentProfiles = 0;
    if (FAILED(policy->get_CurrentProfileTypes(&currentProfiles))) {
        currentProfiles = NET_FW_PROFILE2_ALL;
    }

    long ruleProfiles = NET_FW_PROFILE2_ALL;
    (void)rule->get_Profiles(&ruleProfiles);
    if (ruleProfiles != NET_FW_PROFILE2_ALL && (ruleProfiles & currentProfiles) == 0) {
        return false;
    }

    long ruleProto = 0;
    if (FAILED(rule->get_Protocol(&ruleProto))) {
        return false;
    }

    if (ruleProto != NET_FW_IP_PROTOCOL_ANY && ruleProto != protocol) {
        return false;
    }

    AutoBstr ports;
    if (FAILED(rule->get_LocalPorts(ports.out()))) {
        return false;
    }

    return portListContains(ports.value, port);
}

static bool isFirewallEnabledForCurrentProfiles(INetFwPolicy2* policy) {
    if (!policy) {
        return true;
    }

    long currentProfiles = 0;
    if (FAILED(policy->get_CurrentProfileTypes(&currentProfiles))) {
        return true;
    }

    bool anyEnabled = false;
    for (const long profile : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC}) {
        if ((currentProfiles & profile) == 0) {
            continue;
        }
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if (SUCCEEDED(policy->get_FirewallEnabled(static_cast<NET_FW_PROFILE_TYPE2>(profile), &enabled)) &&
            enabled == VARIANT_TRUE) {
            anyEnabled = true;
        }
    }

    return anyEnabled;
}

static bool isPortAllowed(INetFwPolicy2* policy, long protocol, int port, std::wstring& errorMsg) {
    if (!policy) {
        errorMsg = L"Policy is null";
        return false;
    }

    if (!isFirewallEnabledForCurrentProfiles(policy)) {
        return true;
    }

    INetFwRules* rules = nullptr;
    HRESULT hr = policy->get_Rules(&rules);
    if (FAILED(hr) || !rules) {
        errorMsg = L"get_Rules failed";
        return false;
    }

    IUnknown* enumUnknown = nullptr;
    hr = rules->get__NewEnum(&enumUnknown);
    rules->Release();
    if (FAILED(hr) || !enumUnknown) {
        errorMsg = L"get__NewEnum failed";
        return false;
    }

    IEnumVARIANT* enumVariant = nullptr;
    hr = enumUnknown->QueryInterface(IID_PPV_ARGS(&enumVariant));
    enumUnknown->Release();
    if (FAILED(hr) || !enumVariant) {
        errorMsg = L"QueryInterface(IEnumVARIANT) failed";
        return false;
    }

    VARIANT v;
    VariantInit(&v);
    bool allowed = false;

    while (enumVariant->Next(1, &v, nullptr) == S_OK) {
        if (v.vt == VT_DISPATCH && v.pdispVal) {
            INetFwRule* rule = nullptr;
            if (SUCCEEDED(v.pdispVal->QueryInterface(IID_PPV_ARGS(&rule))) && rule) {
                if (ruleAllowsPort(policy, rule, protocol, port)) {
                    allowed = true;
                    rule->Release();
                    VariantClear(&v);
                    break;
                }
                rule->Release();
            }
        }
        VariantClear(&v);
    }

    enumVariant->Release();
    return allowed;
}

static bool ensureInboundPortRule(INetFwPolicy2* policy,
                                  const wchar_t* ruleName,
                                  const wchar_t* ruleDesc,
                                  long protocol,
                                  int port,
                                  std::wstring& errorMsg) {
    if (!policy) {
        errorMsg = L"Policy is null";
        return false;
    }

    INetFwRules* rules = nullptr;
    HRESULT hr = policy->get_Rules(&rules);
    if (FAILED(hr) || !rules) {
        errorMsg = L"get_Rules failed";
        return false;
    }

    INetFwRule* rule = nullptr;
    AutoBstr name(ruleName);
    hr = rules->Item(name, &rule);
    const bool existed = (SUCCEEDED(hr) && rule != nullptr);

    if (FAILED(hr) || !rule) {
        hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&rule));
        if (FAILED(hr) || !rule) {
            rules->Release();
            errorMsg = L"CoCreateInstance(NetFwRule) failed";
            return false;
        }
    }

    AutoBstr desc(ruleDesc);
    const std::wstring portStr = portToWString(port);
    AutoBstr portBstr(portStr.c_str());

    (void)rule->put_Name(name);
    (void)rule->put_Description(desc);
    (void)rule->put_Protocol(protocol);
    (void)rule->put_Direction(NET_FW_RULE_DIR_IN);
    (void)rule->put_Action(NET_FW_ACTION_ALLOW);
    (void)rule->put_Enabled(VARIANT_TRUE);
    (void)rule->put_Profiles(NET_FW_PROFILE2_ALL);
    (void)rule->put_LocalPorts(portBstr);
    (void)rule->put_EdgeTraversal(VARIANT_FALSE);

    if (!existed) {
        hr = rules->Add(rule);
        if (FAILED(hr)) {
            rule->Release();
            rules->Release();
            errorMsg = L"Failed to add firewall rule";
            return false;
        }
    }

    rule->Release();
    {
        INetFwRule* verify = nullptr;
        const HRESULT hrVerify = rules->Item(name, &verify);
        if (verify) {
            verify->Release();
        }
        rules->Release();
        if (FAILED(hrVerify)) {
            errorMsg = L"Firewall rule verification failed";
            return false;
        }
    }

    return true;
}

static bool removeRuleByName(INetFwPolicy2* policy, const wchar_t* ruleName, std::wstring& errorMsg) {
    if (!policy) {
        errorMsg = L"Policy is null";
        return false;
    }

    INetFwRules* rules = nullptr;
    HRESULT hr = policy->get_Rules(&rules);
    if (FAILED(hr) || !rules) {
        errorMsg = L"get_Rules failed";
        return false;
    }

    AutoBstr name(ruleName);
    hr = rules->Remove(name);
    rules->Release();

    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        errorMsg = L"Remove failed";
        return false;
    }

    return true;
}

static HRESULT getPolicy(INetFwPolicy2** outPolicy) {
    if (!outPolicy) {
        return E_POINTER;
    }
    *outPolicy = nullptr;
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(outPolicy));
}

static void printUsage() {
    std::wcout << L"ExoSendFirewallHelper\n"
               << L"  --check    Returns 0 if inbound rules allow required ports.\n"
               << L"  --check-rules  Returns 0 if ExoSend rule names exist.\n"
               << L"  --install  Adds or updates required inbound rules (requires admin).\n"
               << L"  --remove   Removes ExoSend inbound port rules (requires admin).\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const int udpPort = static_cast<int>(ExoSend::DISCOVERY_PORT_DEFAULT);
    const int tcpPort = static_cast<int>(ExoSend::TCP_PORT_DEFAULT);

    bool doCheck = false;
    bool doCheckRules = false;
    bool doInstall = false;
    bool doRemove = false;

    if (argc <= 1) {
        printUsage();
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--check") doCheck = true;
        else if (arg == L"--check-rules") doCheckRules = true;
        else if (arg == L"--install") doInstall = true;
        else if (arg == L"--remove") doRemove = true;
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

    const wchar_t* udpRuleName = L"ExoSend UDP Discovery (8888)";
    const wchar_t* tcpRuleName = L"ExoSend TCP Transfer (9999)";
    const wchar_t* udpDesc = L"Allow inbound UDP discovery traffic for ExoSend.";
    const wchar_t* tcpDesc = L"Allow inbound TCP file transfer traffic for ExoSend.";

    if (doCheck) {
        std::wstring err;
        const bool udpOk = isPortAllowed(policy, NET_FW_IP_PROTOCOL_UDP, udpPort, err);
        const bool tcpOk = isPortAllowed(policy, NET_FW_IP_PROTOCOL_TCP, tcpPort, err);
        policy->Release();

        if (udpOk && tcpOk) {
            return 0;
        }
        return 2;
    }

    if (doCheckRules) {
        INetFwRules* rules = nullptr;
        HRESULT hrRules = policy->get_Rules(&rules);
        if (FAILED(hrRules) || !rules) {
            policy->Release();
            return 1;
        }

        INetFwRule* udpRule = nullptr;
        INetFwRule* tcpRule = nullptr;
        AutoBstr udpName(udpRuleName);
        AutoBstr tcpName(tcpRuleName);
        const HRESULT hrUdp = rules->Item(udpName, &udpRule);
        const HRESULT hrTcp = rules->Item(tcpName, &tcpRule);

        if (udpRule) udpRule->Release();
        if (tcpRule) tcpRule->Release();
        rules->Release();
        policy->Release();

        if (SUCCEEDED(hrUdp) && SUCCEEDED(hrTcp)) {
            return 0;
        }
        return 2;
    }

    if (doRemove) {
        std::wstring err;
        const bool a = removeRuleByName(policy, udpRuleName, err);
        const bool b = removeRuleByName(policy, tcpRuleName, err);
        policy->Release();
        return (a && b) ? 0 : 1;
    }

    if (doInstall) {
        std::wstring err;
        const bool a = ensureInboundPortRule(policy, udpRuleName, udpDesc, NET_FW_IP_PROTOCOL_UDP, udpPort, err);
        const bool b = ensureInboundPortRule(policy, tcpRuleName, tcpDesc, NET_FW_IP_PROTOCOL_TCP, tcpPort, err);
        policy->Release();
        if (a && b) {
            return 0;
        }
        std::wcerr << L"Install failed: " << err << L"\n";
        return 1;
    }

    policy->Release();
    printUsage();
    return 1;
}
