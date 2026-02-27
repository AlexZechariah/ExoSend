/**
 * @file PairingPhrase.cpp
 * @brief PairingPhrase implementation (RFC 1751).
 */

#include "exosend/PairingPhrase.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <string_view>
#include <unordered_map>

// Generated dictionary include (committed) used for pairing phrase words.
#include "Rfc1751Words.inc"

namespace ExoSend {

namespace {

static uint32_t extractBits(const uint8_t* s, int start, int length) {
    // Ported from RFC 1751 Appendix A extract().
    // start+length <= 66, and the buffer must be at least 9 bytes.
    const uint8_t cl = s[start / 8];
    const uint8_t cc = s[start / 8 + 1];
    const uint8_t cr = s[start / 8 + 2];
    uint32_t x = (static_cast<uint32_t>(cl) << 16) | (static_cast<uint32_t>(cc) << 8) |
                 static_cast<uint32_t>(cr);
    x = x >> (24 - (length + (start % 8)));
    x = (x & (0xFFFFu >> (16 - length)));
    return x;
}

static void insertBits(uint8_t* s, uint32_t x, int start, int length) {
    // Ported from RFC 1751 Appendix A insert().
    const int shift = ((8 - ((start + length) % 8)) % 8);
    const uint32_t y = (x << shift);
    const uint8_t cl = static_cast<uint8_t>((y >> 16) & 0xFFu);
    const uint8_t cc = static_cast<uint8_t>((y >> 8) & 0xFFu);
    const uint8_t cr = static_cast<uint8_t>(y & 0xFFu);

    if (shift + length > 16) {
        s[start / 8] |= cl;
        s[start / 8 + 1] |= cc;
        s[start / 8 + 2] |= cr;
    } else if (shift + length > 8) {
        s[start / 8] |= cc;
        s[start / 8 + 1] |= cr;
    } else {
        s[start / 8] |= cr;
    }
}

static std::string normalizeTokenToDictionaryKey(std::string_view token, std::string& errorMsg) {
    // RFC1751 "standard()" behavior:
    // - uppercases
    // - '1' -> 'L', '0' -> 'O', '5' -> 'S'
    // For ExoSend, we keep dictionary keys as lowercase words.

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

static bool encode64(const uint8_t in[8], std::array<std::string, 6>& outWords, std::string& errorMsg) {
    (void)errorMsg;

    uint8_t cp[9]{};
    std::copy(in, in + 8, cp);

    uint32_t parity = 0;
    for (int i = 0; i < 64; i += 2) {
        parity += extractBits(cp, i, 2);
    }
    cp[8] = static_cast<uint8_t>((parity & 3u) << 6);

    const int starts[6] = {0, 11, 22, 33, 44, 55};
    for (int i = 0; i < 6; ++i) {
        const uint32_t idx = extractBits(cp, starts[i], 11);
        if (idx >= kRfc1751Words.size()) {
            errorMsg = "Internal error: RFC1751 index out of range";
            return false;
        }
        outWords[static_cast<size_t>(i)] = std::string(kRfc1751Words[idx]);
    }
    return true;
}

static bool decode64(const std::array<std::string, 6>& words, uint8_t out[8], std::string& errorMsg) {
    uint8_t b[9]{};
    std::fill(out, out + 8, 0);

    const auto& index = rfc1751WordIndex();

    int bitPos = 0;
    for (int i = 0; i < 6; ++i, bitPos += 11) {
        std::string tokenErr;
        const std::string key = normalizeTokenToDictionaryKey(words[static_cast<size_t>(i)], tokenErr);
        if (key.empty()) {
            errorMsg = "Invalid word: " + tokenErr;
            return false;
        }

        const auto it = index.find(std::string_view(key));
        if (it == index.end()) {
            errorMsg = "Unknown word";
            return false;
        }

        insertBits(b, it->second, bitPos, 11);
    }

    uint32_t parity = 0;
    for (int i = 0; i < 64; i += 2) {
        parity += extractBits(b, i, 2);
    }

    const uint32_t expected = extractBits(b, 64, 2);
    if ((parity & 3u) != expected) {
        errorMsg = "Phrase parity check failed";
        return false;
    }

    std::copy(b, b + 8, out);
    return true;
}

}  // namespace

bool PairingPhrase::encodeRfc1751(const std::array<uint8_t, 16>& secret,
                                  std::array<std::string, 12>& outWords,
                                  std::string& errorMsg) {
    std::array<std::string, 6> w1{};
    std::array<std::string, 6> w2{};

    if (!encode64(secret.data(), w1, errorMsg)) {
        return false;
    }
    if (!encode64(secret.data() + 8, w2, errorMsg)) {
        return false;
    }

    for (size_t i = 0; i < 6; ++i) {
        outWords[i] = w1[i];
        outWords[i + 6] = w2[i];
    }
    return true;
}

bool PairingPhrase::decodeRfc1751(const std::array<std::string, 12>& words,
                                  std::array<uint8_t, 16>& outSecret,
                                  std::string& errorMsg) {
    std::array<std::string, 6> w1{};
    std::array<std::string, 6> w2{};

    for (size_t i = 0; i < 6; ++i) {
        w1[i] = words[i];
        w2[i] = words[i + 6];
    }

    uint8_t out1[8]{};
    uint8_t out2[8]{};
    if (!decode64(w1, out1, errorMsg)) {
        std::fill(outSecret.begin(), outSecret.end(), 0);
        return false;
    }
    if (!decode64(w2, out2, errorMsg)) {
        std::fill(outSecret.begin(), outSecret.end(), 0);
        return false;
    }

    std::copy(out1, out1 + 8, outSecret.data());
    std::copy(out2, out2 + 8, outSecret.data() + 8);
    return true;
}

std::string PairingPhrase::formatHyphenLine(const std::array<std::string, 12>& words) {
    std::string out;
    out.reserve(64);
    for (size_t i = 0; i < words.size(); ++i) {
        if (i != 0) out.push_back('-');
        out.append(words[i]);
    }
    return out;
}

}  // namespace ExoSend
