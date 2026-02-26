/**
 * @file AppPaths.h
 * @brief Canonical storage paths for ExoSend (Windows-focused).
 *
 * Rationale:
 * - Qt's QStandardPaths::AppLocalDataLocation typically produces
 *   %LOCALAPPDATA%\<OrgName>\<AppName>\ on Windows. If both are "ExoSend",
 *   this becomes %LOCALAPPDATA%\ExoSend\ExoSend\ which is redundant and
 *   does not match ExoSend's documented storage contract.
 *
 * This module provides a stable, testable path contract:
 * - Config: %LOCALAPPDATA%\ExoSend\config.json
 * - Certs:  %LOCALAPPDATA%\ExoSend\certs\
 *
 * Environment overrides (for dev/tests) are implemented by callers.
 */

#pragma once

#include <filesystem>

namespace ExoSend {

class AppPaths {
public:
    /**
     * @brief Returns %LOCALAPPDATA% (Windows) or an empty path on unsupported platforms.
     */
    static std::filesystem::path localAppDataRoot();

    /**
     * @brief Returns %APPDATA% (Roaming) on Windows or an empty path otherwise.
     *
     * Used only for migrations from older storage locations.
     */
    static std::filesystem::path roamingAppDataRoot();

    /**
     * @brief Returns canonical ExoSend root directory under LocalAppData.
     * @return %LOCALAPPDATA%\ExoSend
     */
    static std::filesystem::path exoSendLocalRoot();

    /**
     * @brief Returns canonical config.json path.
     * @return %LOCALAPPDATA%\ExoSend\config.json
     */
    static std::filesystem::path configJsonPath();

    /**
     * @brief Returns canonical cert directory.
     * @return %LOCALAPPDATA%\ExoSend\certs
     */
    static std::filesystem::path certsDir();

    /**
     * @brief Returns canonical logs directory.
     * @return %LOCALAPPDATA%\\ExoSend\\logs
     */
    static std::filesystem::path logsDir();

    /**
     * @brief Returns canonical crash trace log path.
     * @return %LOCALAPPDATA%\\ExoSend\\logs\\crash_trace.txt
     */
    static std::filesystem::path crashTraceLogPath();

    /**
     * @brief Legacy config path produced by Qt's AppLocalDataLocation when both
     *        organizationName and applicationName are "ExoSend".
     * @return %LOCALAPPDATA%\ExoSend\ExoSend\config.json
     *
     * This exists for one-time migration only.
     */
    static std::filesystem::path legacyQtAppLocalConfigJsonPath();

    /**
     * @brief Legacy cert directory used by older builds (Roaming AppData).
     * @return %APPDATA%\ExoSend\certs
     *
     * This exists for one-time migration only.
     */
    static std::filesystem::path legacyRoamingCertsDir();
};

}  // namespace ExoSend
