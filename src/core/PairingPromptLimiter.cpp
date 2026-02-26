/**
 * @file PairingPromptLimiter.cpp
 * @brief Rate-limiting implementation for pairing dialogs.
 */

#include "exosend/PairingPromptLimiter.h"

namespace ExoSend {

PairingPromptLimiter::PairingPromptLimiter(int cooldownSeconds)
    : m_cooldownSeconds(cooldownSeconds)
    , m_promptActive(false)
{
}

bool PairingPromptLimiter::beginPrompt(const std::string& peerUuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Global guard: only one pairing dialog at a time.
    if (m_promptActive) {
        return false;
    }

    // Per-peer cooldown: suppress repeated prompts after a rejection.
    auto it = m_lastRejectedAt.find(peerUuid);
    if (it != m_lastRejectedAt.end()) {
        const auto elapsed = std::chrono::steady_clock::now() - it->second;
        if (elapsed < std::chrono::seconds(m_cooldownSeconds)) {
            return false;
        }
    }

    m_promptActive = true;
    return true;
}

void PairingPromptLimiter::endPrompt(const std::string& peerUuid, bool accepted)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_promptActive = false;

    if (!accepted) {
        // Record rejection time for cooldown tracking.
        m_lastRejectedAt[peerUuid] = std::chrono::steady_clock::now();
    } else {
        // On accept, clear the cooldown so the peer can reconnect freely.
        m_lastRejectedAt.erase(peerUuid);
    }
}

}  // namespace ExoSend
