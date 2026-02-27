/**
 * @file pairing_phrase_test.cpp
 * @brief Unit tests for RFC 1751 pairing phrase encoding/decoding.
 */

#include "exosend/PairingPhrase.h"

#include <gtest/gtest.h>

#include <array>
#include <string>

using namespace ExoSend;

namespace {

static std::array<uint8_t, 16> fixedSecret() {
    std::array<uint8_t, 16> s{};
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = static_cast<uint8_t>(0x10u + (i * 7u));
    }
    return s;
}

}  // namespace

TEST(PairingPhraseTest, EncodesToTwelveWordsAndRoundTrips) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    std::array<uint8_t, 16> parsed{};
    ASSERT_TRUE(PairingPhrase::decodeRfc1751(words, parsed, err)) << err;
    EXPECT_EQ(parsed, secret);
}

TEST(PairingPhraseTest, FormatIsHyphenSeparatedSingleLine) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    const std::string line = PairingPhrase::formatHyphenLine(words);
    ASSERT_FALSE(line.empty());

    // Must not contain whitespace.
    for (unsigned char c : line) {
        EXPECT_FALSE(c == ' ' || c == '\t' || c == '\r' || c == '\n');
    }

    // Must contain exactly 11 hyphens.
    size_t hyphens = 0;
    for (char c : line) {
        if (c == '-') ++hyphens;
    }
    EXPECT_EQ(hyphens, 11u) << line;
}

TEST(PairingPhraseTest, DecodeRejectsParityMismatch) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    // Change one word to another, ensuring decode fails.
    // We don't assume specific vocabulary in the test; we just mutate the word.
    words[0] = words[0] + "x";

    std::array<uint8_t, 16> parsed{};
    EXPECT_FALSE(PairingPhrase::decodeRfc1751(words, parsed, err));
    EXPECT_FALSE(err.empty());
}

