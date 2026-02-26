#pragma once

#include <cstdint>
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

#include "exosend/config.h"

namespace ExoSend {

/// Per-IP sliding-window rate limiter for incoming TCP connection handling.
/// Thread-safe via internal mutex.
///
/// Call shouldAccept(sourceIp) for each accepted TCP connection before spawning
/// an expensive handler thread (TLS handshake, header parsing, etc).
class ConnectionRateLimiter {
public:
    ConnectionRateLimiter() = default;

    /// Construct with custom limits (used in tests).
    explicit ConnectionRateLimiter(size_t maxCount,
                                   int64_t windowMs,
                                   size_t maxIps = TRANSFER_CONN_RATE_LIMIT_MAX_IPS)
        : m_maxCount(maxCount), m_windowMs(windowMs), m_maxIps(maxIps) {}

    /// Returns true if this connection should be accepted (under the rate limit).
    bool shouldAccept(const std::string& sourceIp);

private:
    size_t  m_maxCount{TRANSFER_CONN_RATE_LIMIT_MAX_COUNT};
    int64_t m_windowMs{TRANSFER_CONN_RATE_LIMIT_WINDOW_MS};
    size_t  m_maxIps{TRANSFER_CONN_RATE_LIMIT_MAX_IPS};

    mutable std::mutex m_mutex;
    std::unordered_map<std::string,
        std::deque<std::chrono::steady_clock::time_point>> m_history;
    uint64_t m_callCount{0};
};

} // namespace ExoSend

