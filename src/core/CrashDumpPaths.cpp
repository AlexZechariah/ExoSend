/**
 * @file CrashDumpPaths.cpp
 * @brief Canonical crash dump/log storage paths (Windows).
 */

#include "exosend/CrashDumpPaths.h"

#include "exosend/AppPaths.h"

namespace ExoSend::CrashDumpPaths {

std::filesystem::path dumpDir()
{
    const auto root = ExoSend::AppPaths::exoSendLocalRoot();
    if (root.empty()) {
        return {};
    }
    return root / "crash_dumps";
}

std::filesystem::path dumpFilePath(const std::string& timestamp, unsigned long pid)
{
    const auto dir = dumpDir();
    if (dir.empty()) {
        return {};
    }
    return dir / ("crash_" + timestamp + "_pid" + std::to_string(pid) + ".dmp");
}

std::filesystem::path logFilePath(const std::string& timestamp, unsigned long pid)
{
    const auto dir = dumpDir();
    if (dir.empty()) {
        return {};
    }
    return dir / ("crash_" + timestamp + "_pid" + std::to_string(pid) + ".txt");
}

}  // namespace ExoSend::CrashDumpPaths

