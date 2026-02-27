/**
 * @file pairing_secret_test.cpp
 * @brief Unit tests for pairing secret generation.
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

TEST(PairingSecretTest, Generate128NotAllZero) {
    std::array<uint8_t, 16> secret{};
    std::string err;
    ASSERT_TRUE(PairingSecret::generate128(secret, err)) << err;

    EXPECT_FALSE(isAllZero(secret));
}

TEST(PairingSecretTest, Generate128DiffersAcrossCalls) {
    std::array<uint8_t, 16> a{};
    std::array<uint8_t, 16> b{};
    std::string err;
    ASSERT_TRUE(PairingSecret::generate128(a, err)) << err;
    ASSERT_TRUE(PairingSecret::generate128(b, err)) << err;

    EXPECT_FALSE(isAllZero(a));
    EXPECT_FALSE(isAllZero(b));
    EXPECT_NE(a, b);
}
