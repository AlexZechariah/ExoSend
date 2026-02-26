/**
 * @file TrustStore.cpp
 * @brief Persistent trust store for pairing and certificate pinning
 */

#include "exosend/TrustStore.h"

#include <algorithm>
#include <cctype>

namespace ExoSend {

bool TrustStore::hasPeer(const std::string& peerUuid) const {
    return m_records.find(peerUuid) != m_records.end();
}

const PeerTrustRecord* TrustStore::getPeer(const std::string& peerUuid) const {
    auto it = m_records.find(peerUuid);
    if (it == m_records.end()) {
        return nullptr;
    }
    return &it->second;
}

void TrustStore::pinPeer(const std::string& peerUuid,
                         const std::string& fingerprintSha256Hex,
                         const std::string& displayName,
                         const std::string& nowIso8601)
{
    PeerTrustRecord& rec = m_records[peerUuid];
    rec.pinnedFingerprintSha256Hex = fingerprintSha256Hex;
    rec.displayName = displayName;
    if (rec.firstSeenIso8601.empty()) {
        rec.firstSeenIso8601 = nowIso8601;
    }
    rec.lastSeenIso8601 = nowIso8601;
}

void TrustStore::updateSeen(const std::string& peerUuid,
                            const std::string& displayName,
                            const std::string& nowIso8601)
{
    auto it = m_records.find(peerUuid);
    if (it == m_records.end()) {
        return;
    }
    it->second.displayName = displayName;
    it->second.lastSeenIso8601 = nowIso8601;
}

bool TrustStore::isPinnedFingerprintMatch(const std::string& peerUuid,
                                          const std::string& fingerprintSha256Hex) const
{
    const PeerTrustRecord* rec = getPeer(peerUuid);
    if (!rec) {
        return false;
    }
    return rec->pinnedFingerprintSha256Hex == fingerprintSha256Hex;
}

bool TrustStore::revokePeer(const std::string& peerUuid) {
    return m_records.erase(peerUuid) > 0;
}

void TrustStore::clear() {
    m_records.clear();
}

nlohmann::json TrustStore::toJson() const {
    nlohmann::json out = nlohmann::json::object();
    for (const auto& pair : m_records) {
        const auto& uuid = pair.first;
        const auto& rec = pair.second;

        nlohmann::json entry;
        entry["pinned_fingerprint_sha256"] = rec.pinnedFingerprintSha256Hex;
        entry["first_seen"] = rec.firstSeenIso8601;
        entry["last_seen"] = rec.lastSeenIso8601;
        entry["display_name"] = rec.displayName;
        out[uuid] = std::move(entry);
    }
    return out;
}

TrustStore TrustStore::fromJson(const nlohmann::json& j) {
    TrustStore store;
    if (!j.is_object()) {
        return store;
    }

    for (auto it = j.begin(); it != j.end(); ++it) {
        if (!it.value().is_object()) {
            continue;
        }

        PeerTrustRecord rec;
        const auto& obj = it.value();

        if (obj.contains("pinned_fingerprint_sha256") && obj["pinned_fingerprint_sha256"].is_string()) {
            rec.pinnedFingerprintSha256Hex = obj["pinned_fingerprint_sha256"].get<std::string>();
        }
        if (obj.contains("first_seen") && obj["first_seen"].is_string()) {
            rec.firstSeenIso8601 = obj["first_seen"].get<std::string>();
        }
        if (obj.contains("last_seen") && obj["last_seen"].is_string()) {
            rec.lastSeenIso8601 = obj["last_seen"].get<std::string>();
        }
        if (obj.contains("display_name") && obj["display_name"].is_string()) {
            rec.displayName = obj["display_name"].get<std::string>();
        }

        if (rec.pinnedFingerprintSha256Hex.empty() || !isValidFingerprintSha256Hex(rec.pinnedFingerprintSha256Hex)) {
            continue;
        }

        store.m_records[it.key()] = std::move(rec);
    }

    return store;
}

bool TrustStore::isValidFingerprintSha256Hex(const std::string& fingerprintSha256Hex) {
    if (fingerprintSha256Hex.size() != 64) {
        return false;
    }
    return std::all_of(fingerprintSha256Hex.begin(), fingerprintSha256Hex.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

}  // namespace ExoSend

