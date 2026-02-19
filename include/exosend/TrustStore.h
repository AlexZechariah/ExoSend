/**
 * @file TrustStore.h
 * @brief Persistent trust store for pairing and certificate pinning
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace ExoSend {

struct PeerTrustRecord {
    std::string pinnedFingerprintSha256Hex;
    std::string firstSeenIso8601;
    std::string lastSeenIso8601;
    std::string displayName;
};

/**
 * @brief Pairing and pinning trust store.
 *
 * Model:
 * - Keyed by peer UUID string.
 * - Stores pinned certificate fingerprint (SHA-256 hex).
 * - Tracks first/last seen and display name for UX.
 */
class TrustStore {
public:
    using Map = std::unordered_map<std::string, PeerTrustRecord>;

    const Map& records() const { return m_records; }

    bool hasPeer(const std::string& peerUuid) const;
    const PeerTrustRecord* getPeer(const std::string& peerUuid) const;

    void pinPeer(const std::string& peerUuid,
                 const std::string& fingerprintSha256Hex,
                 const std::string& displayName,
                 const std::string& nowIso8601);

    void updateSeen(const std::string& peerUuid,
                    const std::string& displayName,
                    const std::string& nowIso8601);

    bool isPinnedFingerprintMatch(const std::string& peerUuid,
                                  const std::string& fingerprintSha256Hex) const;

    nlohmann::json toJson() const;
    static TrustStore fromJson(const nlohmann::json& j);

    static bool isValidFingerprintSha256Hex(const std::string& fingerprintSha256Hex);

private:
    Map m_records;
};

}  // namespace ExoSend

