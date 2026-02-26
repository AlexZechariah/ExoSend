/**
 * @file PairingSecret.h
 * @brief High-entropy pairing secret helper (generation + Base32 Crockford encoding).
 *
 * This is used for maximum-security pairing as an out-of-band shared secret.
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

    /**
     * @brief Encode a 128-bit secret as Crockford Base32 (no separators).
     * @param secret Secret bytes.
     * @return Base32-encoded string (expected length: 26).
     */
    static std::string toBase32Crockford(const std::array<uint8_t, 16>& secret);

    /**
     * @brief Parse a Crockford Base32 pairing code into a 128-bit secret.
     * @param code Input code (whitespace and '-' are ignored; case-insensitive).
     * @param out Output secret bytes.
     * @param errorMsg Output error message on failure.
     * @return true on success.
     */
    static bool parse128Base32Crockford(const std::string& code,
                                        std::array<uint8_t, 16>& out,
                                        std::string& errorMsg);
};

}  // namespace ExoSend

