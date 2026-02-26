/**
 * @file CrashDumpPaths.h
 * @brief Canonical crash dump/log storage paths (Windows).
 *
 * Security rationale:
 * - Crash dumps may contain sensitive in-memory data.
 * - For maximum security, ExoSend stores crash artifacts only under the
 *   user-scoped LocalAppData directory, and applies ACL hardening to
 *   reduce accidental exposure to other local users.
 */

#pragma once

#include <filesystem>
#include <string>

namespace ExoSend::CrashDumpPaths {

/**
 * @brief Canonical crash dump directory.
 * @return %LOCALAPPDATA%\ExoSend\crash_dumps on Windows; empty path otherwise.
 */
std::filesystem::path dumpDir();

/**
 * @brief Canonical crash dump file path for a given timestamp and pid.
 */
std::filesystem::path dumpFilePath(const std::string& timestamp, unsigned long pid);

/**
 * @brief Canonical crash log file path for a given timestamp and pid.
 */
std::filesystem::path logFilePath(const std::string& timestamp, unsigned long pid);

}  // namespace ExoSend::CrashDumpPaths

