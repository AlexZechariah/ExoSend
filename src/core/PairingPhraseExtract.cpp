/**
 * @file PairingPhraseExtract.cpp
 * @brief PairingPhraseExtract implementation.
 */

#include "exosend/PairingPhraseExtract.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <vector>

// Generated file (committed) containing kRfc1751Words[2048].
#include "Rfc1751Words.inc"

namespace ExoSend {

namespace {

static std::string normalizeTokenToDictionaryKey(std::string_view token, std::string& errorMsg) {
    if (token.empty()) {
        errorMsg = "Empty word";
        return {};
    }
    if (token.size() > 4) {
        errorMsg = "Word is too long";
        return {};
    }

    std::string out;
    out.reserve(token.size());
    for (unsigned char ch : token) {
        if (ch == '1') ch = 'l';
        else if (ch == '0') ch = 'o';
        else if (ch == '5') ch = 's';
        else if (std::isalpha(ch) != 0) ch = static_cast<unsigned char>(std::tolower(ch));
        else {
            errorMsg = "Word contains invalid characters";
            return {};
        }
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

static const std::unordered_map<std::string_view, uint16_t>& rfc1751WordIndex() {
    static const std::unordered_map<std::string_view, uint16_t> index = [] {
        std::unordered_map<std::string_view, uint16_t> m;
        m.reserve(kRfc1751Words.size());
        for (uint16_t i = 0; i < static_cast<uint16_t>(kRfc1751Words.size()); ++i) {
            m.emplace(kRfc1751Words[i], i);
        }
        return m;
    }();
    return index;
}

static bool isRfc1751DictionaryWord(std::string_view rawToken, std::string& normalizedLowercase) {
    std::string err;
    const std::string key = normalizeTokenToDictionaryKey(rawToken, err);
    if (key.empty()) return false;

    const auto& index = rfc1751WordIndex();
    if (index.find(std::string_view(key)) == index.end()) return false;

    normalizedLowercase = key;
    return true;
}

static bool isWordChar(unsigned char ch) {
    // Treat alphabetic and the RFC-standard digit substitutions as word characters.
    return (std::isalpha(ch) != 0) || ch == '0' || ch == '1' || ch == '5';
}

}  // namespace

bool PairingPhraseExtract::extractSingleRfc1751Phrase(const std::string& text,
                                                      std::array<std::string, 12>& outWords,
                                                      std::string& errorMsg) {
    errorMsg.clear();
    for (auto& w : outWords) w.clear();

    // Tokenize into sequences of [A-Za-z015]+. Separators include whitespace and punctuation,
    // including '-' to support the canonical share format.
    std::vector<std::string_view> rawTokens;
    rawTokens.reserve(32);

    const char* s = text.data();
    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        while (i < n && !isWordChar(static_cast<unsigned char>(s[i]))) {
            ++i;
        }
        const size_t start = i;
        while (i < n && isWordChar(static_cast<unsigned char>(s[i]))) {
            ++i;
        }
        const size_t end = i;
        if (end > start) {
            rawTokens.emplace_back(&s[start], end - start);
        }
    }

    if (rawTokens.empty()) {
        errorMsg = "No phrase found";
        return false;
    }

    // Convert to a stream where each token is either a normalized RFC1751 word or an empty marker.
    std::vector<std::string> normalized;
    normalized.reserve(rawTokens.size());
    std::vector<bool> isValid;
    isValid.reserve(rawTokens.size());

    for (const auto& tok : rawTokens) {
        std::string norm;
        const bool ok = isRfc1751DictionaryWord(tok, norm);
        normalized.push_back(ok ? norm : std::string());
        isValid.push_back(ok);
    }

    // Identify maximal runs of consecutive valid RFC1751 words.
    struct Candidate {
        size_t start;
        size_t length;
    };
    std::vector<Candidate> runs;

    size_t pos = 0;
    while (pos < isValid.size()) {
        while (pos < isValid.size() && !isValid[pos]) ++pos;
        const size_t runStart = pos;
        while (pos < isValid.size() && isValid[pos]) ++pos;
        const size_t runEnd = pos;
        const size_t runLen = (runEnd > runStart) ? (runEnd - runStart) : 0;
        if (runLen > 0) {
            runs.push_back(Candidate{runStart, runLen});
        }
    }

    // A phrase candidate is exactly 12 words, with no extra valid words adjacent.
    std::vector<size_t> candidates;
    for (const auto& run : runs) {
        if (run.length == 12) {
            candidates.push_back(run.start);
        }
    }

    if (candidates.empty()) {
        errorMsg = "No 12-word phrase found";
        return false;
    }
    if (candidates.size() > 1) {
        errorMsg = "Multiple phrases found; paste a single phrase";
        return false;
    }

    const size_t startIdx = candidates[0];
    for (size_t w = 0; w < 12; ++w) {
        outWords[w] = normalized[startIdx + w];
    }
    return true;
}

}  // namespace ExoSend

