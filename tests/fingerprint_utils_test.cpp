/**
 * @file fingerprint_utils_test.cpp
 * @brief Tests for FingerprintUtils normalization and formatting
 */

#include <gtest/gtest.h>

#include "exosend/FingerprintUtils.h"
#include "exosend/TrustStore.h"

using ExoSend::FingerprintUtils;

TEST(FingerprintUtilsTest, NormalizeAcceptsColonSeparatedAndLowercase) {
    const std::string normalized =
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    const std::string withColons =
        "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:"
        "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef";

    const std::string out = FingerprintUtils::normalizeSha256Hex(withColons);
    EXPECT_EQ(out, normalized);
    EXPECT_TRUE(ExoSend::TrustStore::isValidFingerprintSha256Hex(out));
}

TEST(FingerprintUtilsTest, NormalizeRejectsInvalidLengthOrChars) {
    EXPECT_TRUE(FingerprintUtils::normalizeSha256Hex("").empty());
    EXPECT_TRUE(FingerprintUtils::normalizeSha256Hex("123").empty());
    EXPECT_TRUE(FingerprintUtils::normalizeSha256Hex(std::string(64, 'g')).empty());
}

TEST(FingerprintUtilsTest, FormatForDisplayAddsColons) {
    const std::string normalized =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const std::string formatted = FingerprintUtils::formatForDisplay(normalized);
    EXPECT_EQ(formatted.size(), 95u);
    EXPECT_EQ(formatted.substr(0, 2), "FF");
    EXPECT_EQ(formatted.substr(2, 1), ":");
    EXPECT_EQ(formatted.substr(93, 2), "FF");
}

