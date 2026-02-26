/**
 * @file pairing_secret_test.cpp
 * @brief Unit tests for pairing secret generation and Base32 (Crockford) encoding.
 */

#include "exosend/PairingSecret.h"

#include <gtest/gtest.h>

#include <array>
#include <string>

using namespace ExoSend;

namespace {

static bool isAllZero(const std::array<uint8_t, 16>& v) {
    for (uint8_t b : v) {
        if (b != 0) return false;
    }
    return true;
}

}  // namespace

TEST(PairingSecretTest, Generate128NotAllZeroAndEncodesToExpectedLength) {
    std::array<uint8_t, 16> secret{};
    std::string err;
    ASSERT_TRUE(PairingSecret::generate128(secret, err)) << err;

    EXPECT_FALSE(isAllZero(secret));

    const std::string code = PairingSecret::toBase32Crockford(secret);
    EXPECT_EQ(code.size(), 26u) << code;
}

TEST(PairingSecretTest, Base32RoundTrip) {
    std::array<uint8_t, 16> secret{};
    for (size_t i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<uint8_t>(i * 7 + 3);
    }

    const std::string code = PairingSecret::toBase32Crockford(secret);

    std::array<uint8_t, 16> parsed{};
    std::string err;
    ASSERT_TRUE(PairingSecret::parse128Base32Crockford(code, parsed, err)) << err;
    EXPECT_EQ(parsed, secret);
}

TEST(PairingSecretTest, ParseRejectsInvalidCharacters) {
    std::array<uint8_t, 16> parsed{};
    std::string err;
    EXPECT_FALSE(PairingSecret::parse128Base32Crockford("THIS_IS_NOT_BASE32!!!", parsed, err));
    EXPECT_FALSE(err.empty());
}

TEST(PairingSecretTest, ParseAcceptsWhitespaceAndLowercase) {
    std::array<uint8_t, 16> secret{};
    for (size_t i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<uint8_t>(0xA0u + static_cast<uint8_t>(i));
    }

    const std::string code = PairingSecret::toBase32Crockford(secret);
    const std::string decorated = "  " + std::string(code.begin(), code.end()) + " \r\n";

    std::array<uint8_t, 16> parsed{};
    std::string err;
    ASSERT_TRUE(PairingSecret::parse128Base32Crockford(decorated, parsed, err)) << err;
    EXPECT_EQ(parsed, secret);
}

