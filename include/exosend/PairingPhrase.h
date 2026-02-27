/**
 * @file PairingPhrase.h
 * @brief RFC 1751 word-phrase encoding for a 128-bit pairing secret.
 *
 * ExoSend uses a 128-bit pairing secret as out-of-band confirmation material.
 * This helper encodes/decodes that secret as a 12-word phrase using the fixed
 * RFC 1751 dictionary (S/Key word list), providing human-friendly entry with
 * built-in parity checks.
 */

#pragma once

#include <array>
#include <string>

namespace ExoSend {

class PairingPhrase {
public:
    /**
     * @brief Encode a 128-bit secret into 12 RFC 1751 words.
     *
     * @param secret 16-byte secret.
     * @param outWords Output words (lowercase).
     * @param errorMsg Output error on failure.
     * @return true on success.
     */
    static bool encodeRfc1751(const std::array<uint8_t, 16>& secret,
                              std::array<std::string, 12>& outWords,
                              std::string& errorMsg);

    /**
     * @brief Decode 12 RFC 1751 words into a 128-bit secret.
     *
     * Input words are case-insensitive.
     *
     * @param words 12 words.
     * @param outSecret Output 16-byte secret.
     * @param errorMsg Output error on failure.
     * @return true on success.
     */
    static bool decodeRfc1751(const std::array<std::string, 12>& words,
                              std::array<uint8_t, 16>& outSecret,
                              std::string& errorMsg);

    /**
     * @brief Format words as a single hyphen-separated share string.
     *
     * Format: word1-word2-...-word12 (lowercase).
     */
    static std::string formatHyphenLine(const std::array<std::string, 12>& words);
};

}  // namespace ExoSend

