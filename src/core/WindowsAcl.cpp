/**
 * @file WindowsAcl.cpp
 * @brief Windows ACL hardening helper implementation.
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#endif

#include "exosend/WindowsAcl.h"

#include <vector>

namespace ExoSend {

#ifdef _WIN32

namespace {

static std::wstring formatWin32ErrorMessage(DWORD code)
{
    wchar_t* buf = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD len = FormatMessageW(
        flags,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf),
        0,
        nullptr
    );

    std::wstring out;
    if (len > 0 && buf) {
        out.assign(buf, buf + len);
    } else {
        wchar_t fallback[64] = {};
        swprintf_s(fallback, L"Win32 error %lu", static_cast<unsigned long>(code));
        out = fallback;
    }

    if (buf) {
        LocalFree(buf);
    }

    while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n')) {
        out.pop_back();
    }
    return out;
}

static bool getCurrentUserSid(std::vector<BYTE>& tokenUserBytes, PSID& outSid, std::wstring* errorMsg)
{
    outSid = nullptr;

    HANDLE hToken = INVALID_HANDLE_VALUE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (errorMsg) {
            *errorMsg = L"OpenProcessToken failed: " + formatWin32ErrorMessage(GetLastError());
        }
        return false;
    }

    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLen);
    if (tokenInfoLen == 0) {
        const DWORD lastErr = GetLastError();
        CloseHandle(hToken);
        if (errorMsg) {
            *errorMsg = L"GetTokenInformation(TokenUser) size query failed: " + formatWin32ErrorMessage(lastErr);
        }
        return false;
    }

    tokenUserBytes.resize(tokenInfoLen);
    if (!GetTokenInformation(hToken, TokenUser, tokenUserBytes.data(), tokenInfoLen, &tokenInfoLen)) {
        const DWORD lastErr = GetLastError();
        CloseHandle(hToken);
        if (errorMsg) {
            *errorMsg = L"GetTokenInformation(TokenUser) failed: " + formatWin32ErrorMessage(lastErr);
        }
        return false;
    }
    CloseHandle(hToken);

    auto* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenUserBytes.data());
    outSid = tokenUser->User.Sid;
    if (!outSid || !IsValidSid(outSid)) {
        if (errorMsg) {
            *errorMsg = L"Invalid user SID";
        }
        return false;
    }

    return true;
}

static bool pathIsDirectory(const std::wstring& path, std::wstring* errorMsg)
{
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        if (errorMsg) {
            *errorMsg = L"GetFileAttributesW failed: " + formatWin32ErrorMessage(GetLastError());
        }
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

} // namespace

bool restrictPathToCurrentUser(const std::wstring& path, std::wstring* errorMsg)
{
    if (path.empty()) {
        if (errorMsg) {
            *errorMsg = L"Path is empty";
        }
        return false;
    }

    std::vector<BYTE> tokenUserBytes;
    PSID currentUserSid = nullptr;
    if (!getCurrentUserSid(tokenUserBytes, currentUserSid, errorMsg)) {
        return false;
    }

    std::wstring attrErr;
    const bool isDir = pathIsDirectory(path, &attrErr);
    if (!attrErr.empty()) {
        if (errorMsg) {
            *errorMsg = L"Failed to query file attributes: " + attrErr;
        }
        return false;
    }

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = isDir ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(currentUserSid);

    PACL pAcl = nullptr;
    const DWORD aclRes = SetEntriesInAclW(1, &ea, nullptr, &pAcl);
    if (aclRes != ERROR_SUCCESS || !pAcl) {
        if (errorMsg) {
            *errorMsg = L"SetEntriesInAclW failed: " + formatWin32ErrorMessage(aclRes);
        }
        if (pAcl) {
            LocalFree(pAcl);
        }
        return false;
    }

    // Disable inheritance and set the explicit DACL.
    std::wstring mutablePath = path;
    const DWORD secRes = SetNamedSecurityInfoW(
        mutablePath.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        pAcl,
        nullptr
    );

    LocalFree(pAcl);

    if (secRes != ERROR_SUCCESS) {
        if (errorMsg) {
            *errorMsg = L"SetNamedSecurityInfoW failed: " + formatWin32ErrorMessage(secRes);
        }
        return false;
    }

    if (errorMsg) {
        errorMsg->clear();
    }
    return true;
}

#endif  // _WIN32

}  // namespace ExoSend
