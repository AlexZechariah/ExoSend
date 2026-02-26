/**
 * @file PairingConfirm.h
 * @brief Pairing confirmation helpers (HKDF + HMAC) bound to a TLS channel binding.
 *
 * This is used for maximum-security pairing. After the TLS handshake completes,
 * both sides compute the RFC 9266 tls-exporter channel binding and use it as
 * a salt in HKDF, with an out-of-band secret as input key material.
 *
 * The derived confirm key is then used to authenticate confirmation tags that
 * bind peer identity attributes (UUID + certificate fingerprint) to the pairing.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace ExoSend {

enum class PairingRole {
    Client,
    Server,
};

class PairingConfirm {
public:
    /**
     * @brief Derive a 32-byte confirmation key from (pairing secret, TLS exporter).
     *
     * HKDF-SHA256:\n
     * - IKM  = pairing secret (128-bit)\n
     * - salt = tls-exporter channel binding (32 bytes)\n
     * - info = "ExoSend Pairing Confirm Key v1"\n
     *
     * @return true on success.
     */
    static bool deriveConfirmKey(const std::array<uint8_t, 16>& pairingSecret,
                                 const std::array<uint8_t, 32>& tlsExporterChannelBinding,
                                 std::array<uint8_t, 32>& outKey,
                                 std::string& errorMsg);

    /**
     * @brief Compute a confirmation tag for the given role and peer identity fields.
     * @return true on success.
     */
    static bool computeTag(const std::array<uint8_t, 32>& confirmKey,
                           PairingRole role,
                           const std::string& localUuid,
                           const std::string& localFingerprint,
                           const std::string& peerUuid,
                           const std::string& peerFingerprint,
                           std::array<uint8_t, 32>& outTag,
                           std::string& errorMsg);

    /**
     * @brief Verify a received confirmation tag (constant-time compare).
     * @return true if tag matches expected.
     */
    static bool verifyTag(const std::array<uint8_t, 32>& confirmKey,
                          PairingRole role,
                          const std::string& localUuid,
                          const std::string& localFingerprint,
                          const std::string& peerUuid,
                          const std::string& peerFingerprint,
                          const std::array<uint8_t, 32>& receivedTag,
                          std::string& errorMsg);
};

}  // namespace ExoSend
