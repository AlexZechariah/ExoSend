/**
 * @file reset_tool.cpp
 * @brief Developer-only tool to reset ExoSend to "first run" state.
 *
 * This tool is intended for local development and test cycles.
 * It deletes user-scoped ExoSend state (config + trust store + TLS cert material)
 * and can optionally remove Windows Firewall rules (via ExoSendFirewallHelper.exe).
 */

#include "exosend/AppPaths.h"
#include "exosend/DevResetArgs.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#endif

namespace {

static void printHelp()
{
    std::cout
        << "ExoSendReset (developer-only)\n"
        << "\n"
        << "Usage:\n"
        << "  ExoSendReset.exe [--dry-run] [--force] (--all | --wipe-state | --wipe-certs | --firewall-remove)\n"
        << "\n"
        << "Actions:\n"
        << "  --wipe-state       Remove config.json (forgets trusted peers)\n"
        << "  --wipe-certs       Remove TLS cert/key material\n"
        << "  --firewall-remove  Remove Windows Firewall rules (runs helper with UAC)\n"
        << "  --all              Equivalent to --wipe-state --wipe-certs --firewall-remove\n"
        << "\n"
        << "Safety:\n"
        << "  --dry-run          Print actions without deleting\n"
        << "  --force            Continue even if ExoSend.exe appears to be running\n";
}

#ifdef _WIN32
static bool isProcessRunningByExeName(const std::wstring& exeName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    bool found = false;
    do {
        if (pe.szExeFile[0] == L'\0') {
            continue;
        }
        if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
            found = true;
            break;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return found;
}

static std::filesystem::path moduleDir()
{
    wchar_t buf[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return {};
    }
    return std::filesystem::path(buf).parent_path();
}

static int runFirewallHelperRemove(const std::filesystem::path& helperPath,
                                  std::wstring* outErr)
{
    if (outErr) {
        outErr->clear();
    }

    if (helperPath.empty() || !std::filesystem::exists(helperPath)) {
        if (outErr) {
            *outErr = L"ExoSendFirewallHelper.exe not found next to ExoSendReset.exe";
        }
        return 3;
    }

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = helperPath.c_str();
    sei.lpParameters = L"--remove";
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        if (outErr) {
            const DWORD e = GetLastError();
            *outErr = L"ShellExecuteExW failed (UAC cancelled or blocked). GetLastError=" +
                      std::to_wstring(e);
        }
        return 3;
    }

    if (!sei.hProcess) {
        if (outErr) {
            *outErr = L"ShellExecuteExW returned no process handle";
        }
        return 3;
    }

    WaitForSingleObject(sei.hProcess, INFINITE);

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(sei.hProcess, &exitCode)) {
        CloseHandle(sei.hProcess);
        if (outErr) {
            *outErr = L"GetExitCodeProcess failed";
        }
        return 3;
    }
    CloseHandle(sei.hProcess);
    return static_cast<int>(exitCode);
}
#endif

static bool removePathBestEffort(const std::filesystem::path& p,
                                 bool recursive,
                                 bool dryRun,
                                 std::string& error)
{
    error.clear();
    if (p.empty()) {
        return true;
    }

    std::error_code ec;
    if (!std::filesystem::exists(p, ec)) {
        return true;
    }

    if (dryRun) {
        return true;
    }

    if (recursive) {
        std::filesystem::remove_all(p, ec);
    } else {
        std::filesystem::remove(p, ec);
    }

    if (ec) {
        error = "Failed to remove: " + p.u8string();
        return false;
    }

    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    ExoSend::DevResetArgs args;
    try {
        args = ExoSend::DevResetArgs::parseOrThrow(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Argument error: " << e.what() << "\n";
        printHelp();
        return 2;
    }

    if (args.showHelp) {
        printHelp();
        return 0;
    }

#ifdef _WIN32
    if (!args.force) {
        if (isProcessRunningByExeName(L"ExoSend.exe")) {
            std::cerr
                << "Refusing to reset while ExoSend.exe is running.\n"
                << "Close ExoSend and retry, or use --force.\n";
            return 2;
        }
    }
#endif

    const auto primaryConfig = ExoSend::AppPaths::configJsonPath();
    const auto legacyQtConfig = ExoSend::AppPaths::legacyQtAppLocalConfigJsonPath();

    const auto primaryCerts = ExoSend::AppPaths::certsDir();
    const auto legacyRoamingCerts = ExoSend::AppPaths::legacyRoamingCertsDir();

    std::cout << "Dry run: " << (args.dryRun ? "true" : "false") << "\n";
    std::cout << "Primary config:   " << primaryConfig.u8string() << "\n";
    std::cout << "Legacy config:    " << legacyQtConfig.u8string() << "\n";
    std::cout << "Primary certs:    " << primaryCerts.u8string() << "\n";
    std::cout << "Legacy certs:     " << legacyRoamingCerts.u8string() << "\n";

    bool ok = true;

    if (args.wipeState) {
        std::string err;
        ok = removePathBestEffort(primaryConfig, false, args.dryRun, err) && ok;
        if (!ok && !err.empty()) {
            std::cerr << err << "\n";
        }
        ok = removePathBestEffort(legacyQtConfig, false, args.dryRun, err) && ok;
        if (!ok && !err.empty()) {
            std::cerr << err << "\n";
        }
    }

    if (args.wipeCerts) {
        std::string err;
        ok = removePathBestEffort(primaryCerts, true, args.dryRun, err) && ok;
        if (!ok && !err.empty()) {
            std::cerr << err << "\n";
        }
        ok = removePathBestEffort(legacyRoamingCerts, true, args.dryRun, err) && ok;
        if (!ok && !err.empty()) {
            std::cerr << err << "\n";
        }
    }

    if (args.firewallRemove) {
#ifdef _WIN32
        if (args.dryRun) {
            std::cout << "Would run firewall helper: ExoSendFirewallHelper.exe --remove (elevated)\n";
        } else {
            const auto helper = moduleDir() / "ExoSendFirewallHelper.exe";
            std::wstring errW;
            const int rc = runFirewallHelperRemove(helper, &errW);
            if (rc != 0) {
                ok = false;
                std::wcerr << L"Firewall helper failed. Exit code=" << rc << L"\n";
                if (!errW.empty()) {
                    std::wcerr << errW << L"\n";
                }
            } else {
                std::cout << "Firewall rules removed successfully.\n";
            }
        }
#else
        std::cerr << "Firewall removal is supported on Windows only.\n";
        ok = false;
#endif
    }

    return ok ? 0 : 3;
}
