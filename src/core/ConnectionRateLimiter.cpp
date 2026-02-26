#include "exosend/ConnectionRateLimiter.h"
#include <iostream>

namespace ExoSend {

bool ConnectionRateLimiter::shouldAccept(const std::string& sourceIp) {
    const auto now         = std::chrono::steady_clock::now();
    const auto windowStart = now - std::chrono::milliseconds(m_windowMs);

    std::lock_guard<std::mutex> lock(m_mutex);

    // Periodic sweeping to bound memory growth from long-gone IPs.
    m_callCount++;
    if ((m_callCount % 256) == 0) {
        for (auto it = m_history.begin(); it != m_history.end(); ) {
            auto& hist = it->second;
            while (!hist.empty() && hist.front() < windowStart) {
                hist.pop_front();
            }
            if (hist.empty()) {
                it = m_history.erase(it);
            } else {
                ++it;
            }
        }
    }

    auto it = m_history.find(sourceIp);
    if (it == m_history.end()) {
        if (m_history.size() >= m_maxIps) {
            std::cerr << "[ConnectionRateLimiter] Max IP tracking capacity reached ("
                      << m_maxIps << "); dropping connection from IP: " << sourceIp << "\n";
            return false;
        }
        it = m_history.emplace(sourceIp,
            std::deque<std::chrono::steady_clock::time_point>{}).first;
    }

    auto& dq = it->second;

    while (!dq.empty() && dq.front() < windowStart) {
        dq.pop_front();
    }

    if (dq.size() >= m_maxCount) {
        std::cerr << "[ConnectionRateLimiter] Rate limit exceeded for IP: "
                  << sourceIp << " (" << dq.size()
                  << " accepts in " << m_windowMs << " ms window)\n";
        return false;
    }

    dq.push_back(now);
    return true;
}

} // namespace ExoSend

