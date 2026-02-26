#include "exosend/BeaconRateLimiter.h"
#include <iostream>

namespace ExoSend {

bool BeaconRateLimiter::shouldProcess(const std::string& sourceIp) {
    const auto now         = std::chrono::steady_clock::now();
    const auto windowStart = now - std::chrono::milliseconds(m_windowMs);

    std::lock_guard<std::mutex> lock(m_mutex);

    // Periodic sweeping to bound memory growth from long-gone IPs.
    // This is intentionally lightweight and only runs occasionally.
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
            // Try a full sweep once before denying new IPs. This prevents a flood of
            // one-off spoofed IPs from permanently starving new legitimate peers.
            for (auto sweepIt = m_history.begin(); sweepIt != m_history.end(); ) {
                auto& hist = sweepIt->second;
                while (!hist.empty() && hist.front() < windowStart) {
                    hist.pop_front();
                }
                if (hist.empty()) {
                    sweepIt = m_history.erase(sweepIt);
                } else {
                    ++sweepIt;
                }
            }

            // If still full, evict an arbitrary existing entry to keep availability.
            if (m_history.size() >= m_maxIps) {
                std::cerr << "[BeaconRateLimiter] Max IP tracking capacity reached ("
                          << m_maxIps << "); evicting one entry to admit IP: " << sourceIp << "\n";
                m_history.erase(m_history.begin());
            }
        }
        it = m_history.emplace(sourceIp,
            std::deque<std::chrono::steady_clock::time_point>{}).first;
    }

    auto& dq = it->second;

    // Evict timestamps outside the sliding window.
    while (!dq.empty() && dq.front() < windowStart) {
        dq.pop_front();
    }

    if (dq.size() >= m_maxCount) {
        std::cerr << "[BeaconRateLimiter] Rate limit exceeded for IP: "
                  << sourceIp << " (" << dq.size()
                  << " beacons in " << m_windowMs << " ms window)\n";
        return false;
    }

    dq.push_back(now);
    return true;
}

} // namespace ExoSend
