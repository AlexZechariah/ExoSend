/**
 * @file Debug.h
 * @brief Debug logging utilities with timestamps
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#pragma once

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <mutex>

namespace ExoSend {

// Note: Global mutex for thread-safe logging
// Prevents concurrent writes to std::cerr which cause memory corruption and crashes
static std::mutex g_logMutex;

/**
 * @brief Get current timestamp as formatted string
 * @return Timestamp in format [HH:MM:SS.mmm]
 */
inline std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif

    std::ostringstream oss;
    oss << "[" << std::setfill('0') << std::setw(2) << tm.tm_hour
        << ":" << std::setfill('0') << std::setw(2) << tm.tm_min
        << ":" << std::setfill('0') << std::setw(2) << tm.tm_sec
        << "." << std::setfill('0') << std::setw(3) << ms.count() << "]";
    return oss.str();
}

/**
 * @brief Thread-safe logging macro with timestamp
 * Note: Added mutex protection to prevent concurrent writes from multiple threads
 * This fixes the memory corruption crash caused by concurrent std::cerr access
 */
#define LOG_INFO(msg) \
    do { \
        std::lock_guard<std::mutex> lock(ExoSend::g_logMutex); \
        std::cerr << ExoSend::getTimestamp() << " [INFO] " << msg << std::endl; \
    } while(0)

#define LOG_DEBUG(msg) \
    do { \
        std::lock_guard<std::mutex> lock(ExoSend::g_logMutex); \
        std::cerr << ExoSend::getTimestamp() << " [DEBUG] " << msg << std::endl; \
    } while(0)

#define LOG_ERROR(msg) \
    do { \
        std::lock_guard<std::mutex> lock(ExoSend::g_logMutex); \
        std::cerr << ExoSend::getTimestamp() << " [ERROR] " << msg << std::endl; \
    } while(0)

#define LOG_WARNING(msg) \
    do { \
        std::lock_guard<std::mutex> lock(ExoSend::g_logMutex); \
        std::cerr << ExoSend::getTimestamp() << " [WARNING] " << msg << std::endl; \
    } while(0)

/**
 * @brief Mouse click logging macro (thread-safe)
 */
#define LOG_MOUSE_CLICK(widget, button) \
    do { \
        std::lock_guard<std::mutex> lock(ExoSend::g_logMutex); \
        std::cerr << ExoSend::getTimestamp() << " [MOUSE] Click: " \
                  << widget << " Button: " << button << std::endl; \
    } while(0)

} // namespace ExoSend
