/**
 * @file ProtectedBlob.h
 * @brief Windows DPAPI wrapper for encrypting sensitive configuration data.
 *
 * Provides user-scoped encryption via CryptProtectData / CryptUnprotectData
 * so that sensitive config data (trust store fingerprints) are not stored in
 * plaintext on disk. The encrypted blob is tied to the current Windows user
 * account and cannot be decrypted by other users or on other machines.
 *
 * Base64 encoding/decoding uses CryptBinaryToStringA / CryptStringToBinaryA
 * (also from Crypt32.lib) to avoid introducing additional dependencies.
 *
 * Usage:
 * @code
 * std::string err;
 * auto cipher = ProtectedBlob::protect("my secret", err);
 * if (!cipher.empty()) {
 *     std::string b64 = ProtectedBlob::toBase64(cipher);
 *     // store b64 in JSON...
 *
 *     auto recovered = ProtectedBlob::fromBase64(b64);
 *     std::string plain = ProtectedBlob::unprotect(recovered, err);
 *     // plain == "my secret"
 * }
 * @endcode
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ExoSend {

class ProtectedBlob {
public:
    /**
     * @brief Encrypt plaintext bytes with Windows DPAPI (current user scope).
     * @param plaintext  Input string to encrypt.
     * @param errorMsg   Output: human-readable error message on failure.
     * @return Encrypted blob bytes, or empty vector on failure.
     *
     * Uses DPAPI user-scope binding (not machine scope). The encrypted blob
     * can only be decrypted by the same Windows user account that encrypted it.
     */
    static std::vector<uint8_t> protect(const std::string& plaintext,
                                        std::string& errorMsg);

    /**
     * @brief Decrypt a DPAPI-encrypted blob (current user scope).
     * @param ciphertext Encrypted blob bytes produced by protect().
     * @param errorMsg   Output: human-readable error message on failure.
     * @return Decrypted plaintext string, or empty string on failure.
     *
     * Returns empty string if the blob is empty, corrupted, or encrypted
     * by a different user account.
     */
    static std::string unprotect(const std::vector<uint8_t>& ciphertext,
                                 std::string& errorMsg);

    /**
     * @brief Encode a byte vector to a Base64 string for JSON storage.
     * @param bytes  Input bytes to encode.
     * @return Base64-encoded string, or empty string if bytes is empty.
     */
    static std::string toBase64(const std::vector<uint8_t>& bytes);

    /**
     * @brief Decode a Base64 string back to bytes.
     * @param b64  Base64-encoded input string.
     * @return Decoded bytes, or empty vector on invalid Base64 input.
     */
    static std::vector<uint8_t> fromBase64(const std::string& b64);
};

}  // namespace ExoSend
