/**
 * @file RelaunchArgs.cpp
 * @brief Implementation of strict parsing for ExoSendRelaunch.
 */

#include "exosend/RelaunchArgs.h"

#include <cwctype>

namespace ExoSend {
namespace {

static bool isAllDigits(const std::wstring& s)
{
    if (s.empty()) return false;
    for (wchar_t ch : s) {
        if (!iswdigit(ch)) return false;
    }
    return true;
}

static void setErr(std::wstring* outErr, const std::wstring& msg)
{
    if (outErr) *outErr = msg;
}

}  // namespace

bool RelaunchArgs::parse(const std::vector<std::wstring>& args, RelaunchArgs& out, std::wstring* outErr)
{
    out = RelaunchArgs{};

    if (args.empty()) {
        setErr(outErr, L"Missing arguments");
        return false;
    }

    for (size_t i = 0; i < args.size(); ++i) {
        const std::wstring& a = args[i];

        if (a == L"--wait-pid") {
            if (i + 1 >= args.size()) {
                setErr(outErr, L"Missing value for --wait-pid");
                return false;
            }
            const std::wstring& pidStr = args[++i];
            if (!isAllDigits(pidStr)) {
                setErr(outErr, L"Invalid --wait-pid (must be numeric)");
                return false;
            }
            const unsigned long long pid = std::stoull(pidStr);
            if (pid == 0 || pid > 0xFFFFFFFFull) {
                setErr(outErr, L"Invalid --wait-pid (out of range)");
                return false;
            }
            out.waitPid = static_cast<uint32_t>(pid);
            continue;
        }

        if (a == L"--launch") {
            if (i + 1 >= args.size()) {
                setErr(outErr, L"Missing value for --launch");
                return false;
            }
            out.launchPath = args[++i];
            continue;
        }

        setErr(outErr, L"Unknown argument: " + a);
        return false;
    }

    if (out.waitPid == 0) {
        setErr(outErr, L"Missing required flag: --wait-pid");
        return false;
    }
    if (out.launchPath.empty()) {
        setErr(outErr, L"Missing required flag: --launch");
        return false;
    }

    return true;
}

}  // namespace ExoSend

