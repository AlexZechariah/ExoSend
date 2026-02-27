/**
 * @file pairing_phrase_extract_test.cpp
 * @brief Unit tests for pairing phrase extraction from arbitrary text.
 */

#include "exosend/PairingPhrase.h"
#include "exosend/PairingPhraseExtract.h"

#include <gtest/gtest.h>

#include <array>
#include <string>

using namespace ExoSend;

namespace {

static std::array<uint8_t, 16> fixedSecret() {
    std::array<uint8_t, 16> s{};
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = static_cast<uint8_t>(0x22u + (i * 5u));
    }
    return s;
}

}  // namespace

TEST(PairingPhraseExtractTest, ExtractsFromHyphenLine) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    const std::string line = PairingPhrase::formatHyphenLine(words);

    std::array<std::string, 12> extracted{};
    ASSERT_TRUE(PairingPhraseExtract::extractSingleRfc1751Phrase(line, extracted, err)) << err;

    std::array<uint8_t, 16> parsed{};
    ASSERT_TRUE(PairingPhrase::decodeRfc1751(extracted, parsed, err)) << err;
    EXPECT_EQ(parsed, secret);
}

TEST(PairingPhraseExtractTest, ExtractsFromMessageWithSurroundingText) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    const std::string line = PairingPhrase::formatHyphenLine(words);
    const std::string msg = "Pairing phrase:\n" + line + "\n(enter this on the other device)";

    std::array<std::string, 12> extracted{};
    ASSERT_TRUE(PairingPhraseExtract::extractSingleRfc1751Phrase(msg, extracted, err)) << err;

    std::array<uint8_t, 16> parsed{};
    ASSERT_TRUE(PairingPhrase::decodeRfc1751(extracted, parsed, err)) << err;
    EXPECT_EQ(parsed, secret);
}

TEST(PairingPhraseExtractTest, RejectsWhenNoCandidateExists) {
    std::array<std::string, 12> extracted{};
    std::string err;
    EXPECT_FALSE(PairingPhraseExtract::extractSingleRfc1751Phrase("hello world", extracted, err));
    EXPECT_FALSE(err.empty());
}

TEST(PairingPhraseExtractTest, RejectsWhenMultipleCandidatesExist) {
    const auto secret = fixedSecret();

    std::array<std::string, 12> words{};
    std::string err;
    ASSERT_TRUE(PairingPhrase::encodeRfc1751(secret, words, err)) << err;

    const std::string line = PairingPhrase::formatHyphenLine(words);
    const std::string msg = line + "\n\n" + line;

    std::array<std::string, 12> extracted{};
    EXPECT_FALSE(PairingPhraseExtract::extractSingleRfc1751Phrase(msg, extracted, err));
    EXPECT_FALSE(err.empty());
}

