/**
 * @file PairingSecret.h
 * @brief High-entropy pairing secret helper (generation).
 *
 * This is used for secure pairing as out-of-band confirmation material.
 * The secret is never persisted long-term. It is used only to confirm pairing
 * against a TLS channel binding (tls-exporter) to prevent pre-pairing MITM.
 */

#pragma once

#include <array>
#include <string>

namespace ExoSend {

class PairingSecret {
public:
    /**
     * @brief Generate a 128-bit pairing secret using a CSPRNG.
     * @param out Output secret bytes.
     * @param errorMsg Output error message on failure.
     * @return true on success.
     */
    static bool generate128(std::array<uint8_t, 16>& out, std::string& errorMsg);
};

}  // namespace ExoSend
