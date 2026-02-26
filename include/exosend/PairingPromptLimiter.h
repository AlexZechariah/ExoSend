/**
 * @file PairingPromptLimiter.h
 * @brief Rate-limits pairing dialogs to prevent dialog flooding.
 *
 * Enforces that at most one pairing dialog is shown at a time, and that a
 * per-peer cooldown window prevents rapid re-prompts after a rejection.
 *
 * This class has no Qt dependencies and belongs in the core library so it
 * can be unit-tested independently of the GUI.
 *
 * Usage:
 * @code
 * // In the incoming connection callback (worker thread):
 * if (!m_pairingLimiter.beginPrompt(peerUuid)) {
 *     // Rate-limited: silently reject this connection attempt.
 *     return;
 * }
 * bool accepted = showPairingDialog(...);
 * m_pairingLimiter.endPrompt(peerUuid, accepted);
 * @endcode
 */

#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace ExoSend {

class PairingPromptLimiter {
public:
    /**
     * @brief Default per-peer cooldown after a rejection (seconds).
     */
    static constexpr int DEFAULT_COOLDOWN_SECONDS = 10;

    /**
     * @brief Construct a limiter with the given per-peer cooldown.
     * @param cooldownSeconds Seconds to suppress prompts for a peer after rejection.
     */
    explicit PairingPromptLimiter(int cooldownSeconds = DEFAULT_COOLDOWN_SECONDS);

    /**
     * @brief Request permission to show a pairing prompt.
     *
     * Returns true and marks the prompt as active if:
     *   - No prompt is currently showing (global one-at-a-time guard), AND
     *   - The per-peer cooldown for peerUuid has expired (or never triggered).
     *
     * If this returns true, the caller MUST call endPrompt() exactly once when
     * the dialog is dismissed. Failing to do so permanently blocks future prompts.
     *
     * @param peerUuid UUID of the peer requesting pairing.
     * @return true if the prompt is allowed; false if rate-limited.
     */
    bool beginPrompt(const std::string& peerUuid);

    /**
     * @brief Mark a pairing prompt as finished.
     *
     * Must be called after every successful beginPrompt() call, regardless of
     * whether the user accepted or rejected.
     *
     * If the user rejected, records the rejection time for cooldown tracking.
     * If the user accepted, clears any existing cooldown entry for this peer.
     *
     * @param peerUuid UUID of the peer (must match the beginPrompt() call).
     * @param accepted Whether the user accepted (true) or rejected (false) pairing.
     */
    void endPrompt(const std::string& peerUuid, bool accepted);

private:
    mutable std::mutex m_mutex;
    int m_cooldownSeconds;
    bool m_promptActive{false};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_lastRejectedAt;
};

}  // namespace ExoSend
