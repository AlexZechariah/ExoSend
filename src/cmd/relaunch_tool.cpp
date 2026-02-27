/**
 * @file relaunch_tool.cpp
 * @brief Helper that waits for a PID to exit, then launches ExoSend.exe.
 *
 * This is used to implement a reliable in-app "Factory Reset" restart without
 * briefly running two ExoSend instances concurrently.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "exosend/RelaunchArgs.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

static void printUsage()
{
    std::wcerr
        << L"ExoSendRelaunch\n"
        << L"Usage:\n"
        << L"  ExoSendRelaunch.exe --wait-pid <pid> --launch <path-to-ExoSend.exe>\n";
}

static std::wstring win32ErrorToString(DWORD code)
{
    wchar_t* buf = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD n = FormatMessageW(flags,
                                  nullptr,
                                  code,
                                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  reinterpret_cast<wchar_t*>(&buf),
                                  0,
                                  nullptr);
    std::wstring msg;
    if (n > 0 && buf) {
        msg.assign(buf, buf + n);
        // Trim trailing CR/LF.
        while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n')) {
            msg.pop_back();
        }
    }
    if (buf) {
        LocalFree(buf);
    }
    if (msg.empty()) {
        return L"Win32 error " + std::to_wstring(code);
    }
    return msg;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::wstring> args;
    args.reserve(static_cast<size_t>(argc > 1 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i] ? argv[i] : L"");
    }

    ExoSend::RelaunchArgs parsed;
    std::wstring parseErr;
    if (!ExoSend::RelaunchArgs::parse(args, parsed, &parseErr)) {
        std::wcerr << L"Argument error: " << parseErr << L"\n";
        printUsage();
        return 2;
    }

    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(parsed.waitPid));
    if (!h) {
        const DWORD err = GetLastError();
        // If the process already exited, proceed to launch immediately.
        if (err != ERROR_INVALID_PARAMETER) {
            std::wcerr << L"Failed to open process " << parsed.waitPid << L": "
                       << win32ErrorToString(err) << L"\n";
            return 3;
        }
    }

    if (h) {
        // Wait for ExoSend to exit. Timeout is a best-effort guard; if the
        // wait times out, we still attempt to launch to avoid stalling forever.
        constexpr DWORD kWaitMs = 2 * 60 * 1000;
        const DWORD r = WaitForSingleObject(h, kWaitMs);
        CloseHandle(h);
        if (r == WAIT_FAILED) {
            const DWORD err = GetLastError();
            std::wcerr << L"WaitForSingleObject failed: " << win32ErrorToString(err) << L"\n";
            // Proceed to launch anyway.
        }
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring cmdLine = L"\"" + parsed.launchPath + L"\"";
    std::vector<wchar_t> cmdLineBuf(cmdLine.begin(), cmdLine.end());
    cmdLineBuf.push_back(L'\0');

    const BOOL ok = CreateProcessW(
        /*lpApplicationName=*/nullptr,
        /*lpCommandLine=*/cmdLineBuf.data(),
        /*lpProcessAttributes=*/nullptr,
        /*lpThreadAttributes=*/nullptr,
        /*bInheritHandles=*/FALSE,
        /*dwCreationFlags=*/0,
        /*lpEnvironment=*/nullptr,
        /*lpCurrentDirectory=*/nullptr,
        /*lpStartupInfo=*/&si,
        /*lpProcessInformation=*/&pi);

    if (!ok) {
        const DWORD err = GetLastError();
        std::wcerr << L"Failed to launch: " << parsed.launchPath << L"\n"
                   << L"Error: " << win32ErrorToString(err) << L"\n";
        return 4;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

