/**
 * @file ThreadSafeLog.h
 * @brief Thread-safe file logging for crash diagnostics
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#pragma once

#include <mutex>
#include <string>

// Forward declaration - avoid including Qt headers in this header
// so it can be safely included from non-Qt translation units
class QString;

namespace ExoSend {

/**
 * @brief Thread-safe logging to crash_trace.txt
 *
 * All crash logging functions across all modules must use this class
 * to prevent file corruption from concurrent writes by multiple threads.
 *
 * Uses a global static mutex to synchronize file access across:
 * - MainWindow (GUI thread)
 * - TransferListModel (worker thread via Qt signals)
 * - TransferServer (listener/cleanup threads)
 * - TransferSession (worker threads)
 *
 * Note: initialize() MUST be called from the Qt main thread before
 * any worker threads start. This pre-computes the log path so that
 * log() never calls Qt APIs (which are not thread-safe) from non-Qt threads.
 */
class ThreadSafeLog {
public:
    /**
     * @brief Initialize the log path (call from Qt main thread ONLY)
     * @param logPath Absolute path to the log file
     *
     * Must be called before any worker threads are started.
     * Calling log() before initialize() will silently fail.
     */
    static void initialize(const std::string& logPath);

    /**
     * @brief Log a std::string message
     * @param message Message to log
     *
     * Thread-safe: locks global mutex before writing to file.
     * Safe to call from any thread after initialize() has been called.
     */
    static void log(const std::string& message);

    /**
     * @brief Log a const char* message
     * @param message Message to log
     *
     * Thread-safe: locks global mutex before writing to file.
     * This overload prevents ambiguity when passing string literals.
     */
    static void log(const char* message);

    /**
     * @brief Log a QString message
     * @param message Message to log
     *
     * Thread-safe: locks global mutex before writing to file.
     * NOTE: This overload is defined in ThreadSafeLog.cpp which includes Qt headers.
     * Do NOT call this from non-Qt threads if Qt is not initialized.
     */
    static void log(const QString& message);

private:
    /// Global mutex for synchronizing file access across all threads
    static std::mutex s_mutex;

    /// Pre-computed log file path (set by initialize(), never changes after that)
    static std::string s_logPath;
};

} // namespace ExoSend
