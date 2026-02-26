/**
 * @file protected_blob_test.cpp
 * @brief Unit tests for ProtectedBlob DPAPI wrapper.
 *
 * Tests run on Windows only (DPAPI is a Windows API).
 * Requires the test process to run as a real Windows user account
 * (not a service with no profile loaded).
 */

#include "exosend/ProtectedBlob.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace ExoSend;

// DPAPI encrypt/decrypt round-trip.
TEST(ProtectedBlobTest, RoundTrip) {
    const std::string plaintext = R"({"peer-uuid":{"pinned_fingerprint_sha256":"AABB"}})";
    std::string err;

    auto ciphertext = ProtectedBlob::protect(plaintext, err);
    ASSERT_FALSE(ciphertext.empty()) << "protect failed: " << err;

    // Ciphertext must differ from plaintext bytes.
    const std::string cipherStr(ciphertext.begin(), ciphertext.end());
    EXPECT_NE(plaintext, cipherStr);

    std::string decrypted = ProtectedBlob::unprotect(ciphertext, err);
    ASSERT_FALSE(decrypted.empty()) << "unprotect failed: " << err;
    EXPECT_EQ(plaintext, decrypted);
}

// Base64 encode/decode round-trip with known byte sequence.
TEST(ProtectedBlobTest, Base64RoundTrip) {
    const std::vector<uint8_t> original = {0x00, 0x01, 0xFF, 0xAB, 0xCD, 0xEF, 0x42};

    const std::string b64 = ProtectedBlob::toBase64(original);
    ASSERT_FALSE(b64.empty());

    const auto decoded = ProtectedBlob::fromBase64(b64);
    EXPECT_EQ(original, decoded);
}

// Empty ciphertext must return empty plaintext without crashing.
TEST(ProtectedBlobTest, EmptyCiphertextReturnsEmpty) {
    std::string err;
    const std::string result = ProtectedBlob::unprotect({}, err);
    EXPECT_TRUE(result.empty());
    EXPECT_FALSE(err.empty());  // Error message must be non-empty
}

// Empty bytes must return empty Base64 without crashing.
TEST(ProtectedBlobTest, EmptyBytesToBase64) {
    const std::string b64 = ProtectedBlob::toBase64({});
    EXPECT_TRUE(b64.empty());
}

// Empty Base64 string must return empty bytes without crashing.
TEST(ProtectedBlobTest, EmptyBase64ToBytes) {
    const auto result = ProtectedBlob::fromBase64("");
    EXPECT_TRUE(result.empty());
}

// Encrypt empty string -- DPAPI still produces a non-empty blob.
TEST(ProtectedBlobTest, ProtectEmptyString) {
    std::string err;
    const auto cipher = ProtectedBlob::protect("", err);
    // DPAPI should still succeed and produce a non-empty blob for empty plaintext.
    EXPECT_FALSE(cipher.empty()) << "protect of empty string failed: " << err;

    const std::string plain = ProtectedBlob::unprotect(cipher, err);
    EXPECT_EQ("", plain) << "unprotect of empty-string cipher failed: " << err;
}
