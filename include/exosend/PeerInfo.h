/**
 * @file PeerInfo.h
 * @brief Peer information structure for discovered devices
 */

#pragma once
#include <string>
#include <chrono>
#include <cstdint>

namespace ExoSend {

    /**
     * @brief Peer connection status for visual indicators
     */
    enum class PeerStatus {
        Active,      ///< Peer is running (seen within timeout period) - GREEN
        Warning,     ///< DEPRECATED: No longer used, kept for compatibility
        Inactive     ///< Peer has quit (not seen within timeout period) - RED
    };

    /**
     * @brief Information about a discovered peer on the network
     *
     * This struct holds all the information we maintain about each
     * discovered peer on the local network. It is stored in the
     * peer table and updated each time we receive a beacon from that peer.
     */
    struct PeerInfo {
        std::string uuid;                                           ///< Unique identifier for this peer
        std::string displayName;                                    ///< Human-readable device name
        std::string certFingerprintSha256Hex;                       ///< Peer certificate fingerprint (SHA-256 hex)
        std::string ipAddress;                                      ///< IP address of the peer
        uint16_t tcpPort;                                           ///< TCP port where peer accepts transfers
        std::chrono::steady_clock::time_point lastSeen;            ///< Timestamp of last beacon received

        PeerInfo() : tcpPort(0), lastSeen(std::chrono::steady_clock::now()) {}

        PeerInfo(const std::string& uuid_, const std::string& name,
                 const std::string& ip, uint16_t port,
                 const std::string& fingerprintSha256Hex = {})
            : uuid(uuid_), displayName(name), certFingerprintSha256Hex(fingerprintSha256Hex), ipAddress(ip),
              tcpPort(port), lastSeen(std::chrono::steady_clock::now()) {}

        /**
         * @brief Check if this peer has timed out (not seen in too long)
         * @param timeoutMs Timeout in milliseconds
         * @return true if peer has timed out
         */
        bool isTimedOut(uint32_t timeoutMs) const {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSeen);
            return elapsed.count() >= static_cast<int64_t>(timeoutMs);
        }

        /**
         * @brief Get the current status of this peer
         * @param timeoutMs Timeout in milliseconds
         * @return PeerStatus::Active if peer seen within timeout, Inactive otherwise
         *
         * Simplified binary status:
         * - Active: Peer has been seen recently (within timeout period) = peer is running
         * - Inactive: Peer hasn't been seen within timeout period = peer has quit
         */
        PeerStatus getStatus(uint32_t timeoutMs) const {
            // Binary status: either running (Active) or quit (Inactive)
            if (isTimedOut(timeoutMs)) {
                return PeerStatus::Inactive;  // Red - peer quit
            }
            return PeerStatus::Active;        // Green - peer running
        }

        /**
         * @brief Get time remaining before peer becomes inactive
         * @param timeoutMs Timeout in milliseconds
         * @return Milliseconds remaining (0 if already timed out)
         */
        int64_t getTimeRemaining(uint32_t timeoutMs) const {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSeen);
            auto remaining = static_cast<int64_t>(timeoutMs) - elapsed.count();
            return (remaining > 0) ? remaining : 0;
        }
    };
}  // namespace ExoSend
