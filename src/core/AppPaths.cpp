/**
 * @file AppPaths.cpp
 * @brief Canonical storage paths for ExoSend.
 */

#include "exosend/AppPaths.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#endif

namespace ExoSend {

static std::filesystem::path knownFolder(REFKNOWNFOLDERID id) {
#ifdef _WIN32
    PWSTR pathW = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &pathW);
    if (hr != S_OK || !pathW) {
        return {};
    }
    std::filesystem::path out(pathW);
    CoTaskMemFree(pathW);
    return out;
#else
    (void)id;
    return {};
#endif
}

std::filesystem::path AppPaths::localAppDataRoot() {
#ifdef _WIN32
    return knownFolder(FOLDERID_LocalAppData);
#else
    return {};
#endif
}

std::filesystem::path AppPaths::roamingAppDataRoot() {
#ifdef _WIN32
    return knownFolder(FOLDERID_RoamingAppData);
#else
    return {};
#endif
}

std::filesystem::path AppPaths::exoSendLocalRoot() {
    const auto root = localAppDataRoot();
    if (root.empty()) {
        return {};
    }
    return root / "ExoSend";
}

std::filesystem::path AppPaths::configJsonPath() {
    const auto root = exoSendLocalRoot();
    if (root.empty()) {
        return {};
    }
    return root / "config.json";
}

std::filesystem::path AppPaths::certsDir() {
    const auto root = exoSendLocalRoot();
    if (root.empty()) {
        return {};
    }
    return root / "certs";
}

std::filesystem::path AppPaths::logsDir() {
    const auto root = exoSendLocalRoot();
    if (root.empty()) {
        return {};
    }
    return root / "logs";
}

std::filesystem::path AppPaths::crashTraceLogPath() {
    const auto dir = logsDir();
    if (dir.empty()) {
        return {};
    }
    return dir / "crash_trace.txt";
}

std::filesystem::path AppPaths::legacyQtAppLocalConfigJsonPath() {
    const auto root = localAppDataRoot();
    if (root.empty()) {
        return {};
    }
    return root / "ExoSend" / "ExoSend" / "config.json";
}

std::filesystem::path AppPaths::legacyRoamingCertsDir() {
    const auto root = roamingAppDataRoot();
    if (root.empty()) {
        return {};
    }
    return root / "ExoSend" / "certs";
}

}  // namespace ExoSend
