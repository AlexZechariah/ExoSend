#pragma once
#include <cstdint>
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include "exosend/config.h"

namespace ExoSend {

/// Per-IP sliding-window rate limiter for discovery beacon processing.
/// Thread-safe via internal mutex.
///
/// Call shouldProcess(sourceIp) for each incoming beacon BEFORE JSON parse.
/// Returns true if the beacon should be processed (under the rate limit),
/// false if it should be silently dropped.
class BeaconRateLimiter {
public:
    BeaconRateLimiter() = default;

    /// Construct with custom limits (used in tests).
    explicit BeaconRateLimiter(size_t maxCount, int64_t windowMs, size_t maxIps = BEACON_RATE_LIMIT_MAX_IPS)
        : m_maxCount(maxCount), m_windowMs(windowMs), m_maxIps(maxIps) {}

    /// Returns true if this beacon should be processed (under the rate limit).
    bool shouldProcess(const std::string& sourceIp);

private:
    size_t  m_maxCount{BEACON_RATE_LIMIT_MAX_COUNT};
    int64_t m_windowMs{BEACON_RATE_LIMIT_WINDOW_MS};
    size_t  m_maxIps{BEACON_RATE_LIMIT_MAX_IPS};

    mutable std::mutex m_mutex;
    std::unordered_map<std::string,
        std::deque<std::chrono::steady_clock::time_point>> m_history;
    uint64_t m_callCount{0};
};

} // namespace ExoSend
