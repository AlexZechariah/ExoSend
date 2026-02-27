/**
 * @file PairingPhraseExtract.h
 * @brief Extract a single RFC 1751 pairing phrase from user-provided text.
 *
 * Users often paste pairing phrases from chat apps or logs that may include
 * surrounding text. This helper extracts exactly one candidate phrase
 * (12 RFC 1751 words) and returns it as normalized lowercase words.
 *
 * Security model:
 * - Fail closed on ambiguity (0 or >1 candidates).
 * - Require exactly 12 consecutive RFC 1751 dictionary words.
 */

#pragma once

#include <array>
#include <string>

namespace ExoSend {

class PairingPhraseExtract {
public:
    /**
     * @brief Extract exactly one 12-word RFC1751 phrase from arbitrary text.
     *
     * Accepted formats include:
     * - `word1-word2-...-word12`
     * - `word1 word2 ... word12`
     * - the phrase embedded within a longer message
     *
     * @param text Input text (possibly includes extra content).
     * @param outWords Output words (lowercase) if exactly one candidate is found.
     * @param errorMsg Output error on failure.
     * @return true if exactly one phrase candidate was found and extracted.
     */
    static bool extractSingleRfc1751Phrase(const std::string& text,
                                          std::array<std::string, 12>& outWords,
                                          std::string& errorMsg);
};

}  // namespace ExoSend

