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
 * All handlers write crash artifacts to the executable directory before terminating.
 */
void installCrashHandlers();

/**
 * @brief Write crash dump with custom message
 * @param reason Description of why the crash occurred
 */
void writeCrashDump(const QString& reason);

} // namespace ExoSend
