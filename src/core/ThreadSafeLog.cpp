/**
 * @file ThreadSafeLog.cpp
 * @brief Thread-safe file logging for crash diagnostics implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/ThreadSafeLog.h"
#include <QString>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ExoSend {

// Static member definitions
std::mutex ThreadSafeLog::s_mutex;
std::filesystem::path ThreadSafeLog::s_logPath;

void ThreadSafeLog::initialize(const std::filesystem::path& logPath) {
    // Called from Qt main thread before any worker threads start.
    // No lock needed here since no other threads are running yet.
    s_logPath = logPath;
}

void ThreadSafeLog::log(const std::string& message) {
    // Note: Do not call any Qt APIs here (e.g. QCoreApplication::applicationDirPath())
    // This function is called from non-Qt threads (listener thread, cleanup thread, etc.)
    // Qt APIs are not thread-safe from non-Qt threads.

    if (s_logPath.empty()) {
        return;  // Not initialized yet - silently fail
    }

    std::lock_guard<std::mutex> lock(s_mutex);

    // Get current time using standard C++ (no Qt)
    auto now = std::chrono::system_clock::now();
    auto now_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &now_t);
#else
    localtime_r(&now_t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count()
        << " - " << message << "\n";

    // Use std::ofstream (no Qt) - safe from any thread.
    // Use std::filesystem::path to support Unicode paths on Windows.
    std::ofstream file(s_logPath, std::ios::app);
    if (file.is_open()) {
        file << oss.str();
        file.flush();
    }
}

void ThreadSafeLog::log(const char* message) {
    log(std::string(message));
}

void ThreadSafeLog::log(const QString& message) {
    // Convert to std::string and delegate - this is the only Qt call in this file
    // This overload should only be called from Qt threads (main thread, Qt worker threads)
    log(message.toStdString());
}

} // namespace ExoSend
