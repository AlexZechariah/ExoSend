/**
 * @file CrashHandler.h
 * @brief Enhanced crash handler for ExoSend application
 *
 * Provides crash dump generation for:
 * - Qt messages (qCritical, qFatal)
 * - C++ signals (SIGABRT, SIGFPE, SIGILL, SIGSEGV)
 * - Windows structured exceptions
 * - C++ std::terminate()
 */

#pragma once

#include <QString>

namespace ExoSend {

/**
 * @brief Install crash handlers for improved crash dump generation
 *
 * This installs handlers for:
 * - Qt messages (qCritical, qFatal)
 * - C++ signals (SIGABRT, SIGFPE, SIGILL, SIGSEGV)
 * - Windows structured exceptions
 * - C++ std::terminate()
 *
 * Crash artifacts (minidump + log) are written to a user-scoped LocalAppData
 * directory when crash dumps are enabled.
 */
void installCrashHandlers();

/**
 * @brief Enable or disable crash dump writing (privacy control).
 *
 * When disabled, ExoSend will not write minidumps or crash logs.
 *
 * This is best-effort and must be called as early as possible to be effective.
 */
void setCrashDumpsEnabled(bool enabled);

/**
 * @brief Returns whether crash dumps are currently enabled.
 */
bool crashDumpsEnabled();

/**
 * @brief Write crash dump with custom message
 * @param reason Description of why the crash occurred
 */
void writeCrashDump(const QString& reason);

} // namespace ExoSend
