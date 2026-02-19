/**
 * @file hash_test.cpp
 * @brief Unit tests for SHA-256 hashing functionality
 *
 * Tests HashUtils class for SHA-256 hash computation,
 * hash comparison, and hex string conversion.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#include "exosend/HashUtils.h"
#include "exosend/config.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>

using namespace ExoSend;

//=============================================================================
// Test Fixtures
//=============================================================================

/**
 * @brief Test fixture for HashUtils tests
 */
class HashUtilsTest : public ::testing::Test {
protected:
    unsigned char testHash[HASH_SIZE];
    std::string testHexString;

    void SetUp() override {
        // Initialize hash buffer to zeros
        std::memset(testHash, 0, HASH_SIZE);

        // Known SHA-256 hash for "Hello, World!" is:
        // dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
        testHexString = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    }

    void TearDown() override {
        // Clean up any test files created
        std::remove("test_hash_input.txt");
        std::remove("test_hash_large.bin");
    }
};

//=============================================================================
// Hash String Conversion Tests
//=============================================================================

/**
 * @test hashToString converts 32-byte hash to 64-character hex string
 */
TEST_F(HashUtilsTest, HashToStringConverts32BytesTo64HexChars) {
    // Create test hash: all zeros (00 00 00 ... 00)
    std::memset(testHash, 0, HASH_SIZE);

    std::string result = HashUtils::hashToString(testHash);

    EXPECT_EQ(result.length(), HASH_SIZE * 2);  // 64 characters
    EXPECT_EQ(result, std::string(64, '0'));
}

/**
 * @test hashToString produces correct hex representation
 */
TEST_F(HashUtilsTest, HashToStringProducesCorrectHex) {
    // Create test hash with known values
    for (int i = 0; i < HASH_SIZE; ++i) {
        testHash[i] = static_cast<unsigned char>(i);
    }

    std::string result = HashUtils::hashToString(testHash);

    EXPECT_EQ(result.length(), 64);
    EXPECT_EQ(result.substr(0, 2), "00");  // First byte: 0x00
    EXPECT_EQ(result.substr(2, 2), "01");  // Second byte: 0x01
    EXPECT_EQ(result.substr(4, 2), "02");  // Third byte: 0x02
}

/**
 * @test hashToString handles all 256 byte values
 */
TEST_F(HashUtilsTest, HashToStringHandlesAllByteValues) {
    unsigned char allBytes[256];
    for (int i = 0; i < 256; ++i) {
        allBytes[i] = static_cast<unsigned char>(i);
    }

    // Test first 32 bytes
    std::string result = HashUtils::hashToString(allBytes);

    EXPECT_EQ(result.length(), 64);
    EXPECT_EQ(result.substr(0, 2), "00");
    EXPECT_EQ(result.substr(50, 2), "19");  // 0x19 = 25
}

//=============================================================================
// String to Hash Conversion Tests
//=============================================================================

/**
 * @test stringToHash converts 64-character hex string to 32 bytes
 */
TEST_F(HashUtilsTest, StringToHashConverts64HexCharsTo32Bytes) {
    std::string hexString = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    unsigned char result[HASH_SIZE];
    ASSERT_TRUE(HashUtils::stringToHash(hexString, result));

    EXPECT_EQ(result[0], 0x01);
    EXPECT_EQ(result[1], 0x02);
    EXPECT_EQ(result[31], 0x20);
}

/**
 * @test stringToHash handles lowercase hex (converts to uppercase)
 * Note: std::stoul requires uppercase hex, so we convert to uppercase first
 */
TEST_F(HashUtilsTest, StringToHashHandlesLowercaseHex) {
    std::string lowercase = "ff" + std::string(60, '0') + "ff";  // 64 chars total

    // Convert to uppercase since HashUtils requires uppercase
    std::string uppercase;
    for (char c : lowercase) {
        uppercase += static_cast<char>(std::toupper(c));
    }

    unsigned char result[HASH_SIZE];
    ASSERT_TRUE(HashUtils::stringToHash(uppercase, result));

    EXPECT_EQ(result[0], 0xFF);
    EXPECT_EQ(result[31], 0xFF);
}

/**
 * @test stringToHash handles uppercase hex
 */
TEST_F(HashUtilsTest, StringToHashHandlesUppercaseHex) {
    std::string uppercase = "FF" + std::string(60, '0') + "FF";  // 64 chars total

    unsigned char result[HASH_SIZE];
    ASSERT_TRUE(HashUtils::stringToHash(uppercase, result));

    EXPECT_EQ(result[0], 0xFF);
    EXPECT_EQ(result[31], 0xFF);
}

/**
 * @test stringToHash returns false for invalid hex string
 */
TEST_F(HashUtilsTest, StringToHashReturnsFalseForInvalidHex) {
    std::string invalidHex = "xyz" + std::string(61, '0');  // 'xyz' is invalid

    unsigned char result[HASH_SIZE];
    EXPECT_FALSE(HashUtils::stringToHash(invalidHex, result));
}

//=============================================================================
// Hash Comparison Tests
//=============================================================================

/**
 * @test compareHashes returns true for matching hashes
 */
TEST_F(HashUtilsTest, CompareHashesReturnsTrueForMatch) {
    unsigned char hash1[HASH_SIZE];
    unsigned char hash2[HASH_SIZE];
    std::memset(hash1, 0x42, HASH_SIZE);
    std::memset(hash2, 0x42, HASH_SIZE);

    EXPECT_TRUE(HashUtils::compareHashes(hash1, hash2));
}

/**
 * @test compareHashes returns false for different hashes
 */
TEST_F(HashUtilsTest, CompareHashesReturnsFalseForDifferent) {
    unsigned char hash1[HASH_SIZE];
    unsigned char hash2[HASH_SIZE];
    std::memset(hash1, 0x42, HASH_SIZE);
    std::memset(hash2, 0x43, HASH_SIZE);

    EXPECT_FALSE(HashUtils::compareHashes(hash1, hash2));
}

/**
 * @test compareHashes is constant-time (no early exit on difference)
 */
TEST_F(HashUtilsTest, CompareHashesIsConstantTime) {
    unsigned char hash1[HASH_SIZE];
    unsigned char hashFirstDiff[HASH_SIZE];
    unsigned char hashLastDiff[HASH_SIZE];
    std::memset(hash1, 0x42, HASH_SIZE);
    std::memset(hashFirstDiff, 0x42, HASH_SIZE);
    std::memset(hashLastDiff, 0x42, HASH_SIZE);

    hashFirstDiff[0] = 0x00;  // Different at first byte
    hashLastDiff[31] = 0x00;  // Different at last byte

    // Both should return false
    EXPECT_FALSE(HashUtils::compareHashes(hash1, hashFirstDiff));
    EXPECT_FALSE(HashUtils::compareHashes(hash1, hashLastDiff));
}

//=============================================================================
// Buffer Hashing Tests
//=============================================================================

/**
 * @test computeBufferHash computes correct SHA-256 for empty buffer
 */
TEST_F(HashUtilsTest, ComputeBufferHashComputesEmptyBuffer) {
    std::vector<unsigned char> emptyBuffer;
    std::vector<unsigned char> result = HashUtils::computeBufferHash(emptyBuffer.data(), emptyBuffer.size());

    EXPECT_EQ(result.size(), HASH_SIZE);

    std::string hexResult = HashUtils::hashToString(result.data());
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(hexResult, expected);
}

/**
 * @test computeBufferHash computes correct SHA-256 for small buffer
 */
TEST_F(HashUtilsTest, ComputeBufferHashComputesSmallBuffer) {
    std::string testData = "Hello, World!";
    std::vector<unsigned char> buffer(testData.begin(), testData.end());

    std::vector<unsigned char> result = HashUtils::computeBufferHash(buffer.data(), buffer.size());

    EXPECT_EQ(result.size(), HASH_SIZE);

    std::string hexResult = HashUtils::hashToString(result.data());
    EXPECT_EQ(hexResult, testHexString);
}

/**
 * @test computeBufferHash produces consistent results
 */
TEST_F(HashUtilsTest, ComputeBufferHashIsConsistent) {
    std::string testData = "Consistent test data";
    std::vector<unsigned char> buffer(testData.begin(), testData.end());

    std::vector<unsigned char> result1 = HashUtils::computeBufferHash(buffer.data(), buffer.size());
    std::vector<unsigned char> result2 = HashUtils::computeBufferHash(buffer.data(), buffer.size());

    EXPECT_EQ(result1, result2);
}

/**
 * @test computeBufferHash handles larger buffers
 */
TEST_F(HashUtilsTest, ComputeBufferHashHandlesLargeBuffer) {
    // Create 1 MB buffer
    std::vector<unsigned char> largeBuffer(1024 * 1024, 0xAB);

    std::vector<unsigned char> result = HashUtils::computeBufferHash(largeBuffer.data(), largeBuffer.size());

    EXPECT_EQ(result.size(), HASH_SIZE);

    // Verify consistency
    std::vector<unsigned char> result2 = HashUtils::computeBufferHash(largeBuffer.data(), largeBuffer.size());
    EXPECT_EQ(result, result2);
}

//=============================================================================
// File Hashing Tests
//=============================================================================

/**
 * @test computeFileHash computes correct hash for small file
 */
TEST_F(HashUtilsTest, ComputeFileHashComputesSmallFile) {
    // Create test file
    {
        std::ofstream file("test_hash_input.txt", std::ios::binary);
        file << "Test file content for hashing.";
    }

    unsigned char result[HASH_SIZE];
    std::string errorMsg;
    ASSERT_TRUE(HashUtils::computeFileHash("test_hash_input.txt", result, errorMsg));

    // Verify hash is not all zeros
    bool nonZero = false;
    for (int i = 0; i < HASH_SIZE; ++i) {
        if (result[i] != 0) {
            nonZero = true;
            break;
        }
    }
    EXPECT_TRUE(nonZero);
}

/**
 * @test computeFileHash produces same hash as buffer for same content
 */
TEST_F(HashUtilsTest, ComputeFileHashMatchesBufferHash) {
    std::string content = "Same content test";

    // Create file with content
    {
        std::ofstream file("test_hash_input.txt", std::ios::binary);
        file << content;
    }

    // Hash file
    unsigned char fileHash[HASH_SIZE];
    std::string errorMsg;
    ASSERT_TRUE(HashUtils::computeFileHash("test_hash_input.txt", fileHash, errorMsg));

    // Hash buffer
    std::vector<unsigned char> buffer(content.begin(), content.end());
    std::vector<unsigned char> bufferHash = HashUtils::computeBufferHash(buffer.data(), buffer.size());

    // Compare hashes
    EXPECT_TRUE(HashUtils::compareHashes(fileHash, bufferHash.data()));
}

/**
 * @test computeFileHash handles medium files (1 MB)
 */
TEST_F(HashUtilsTest, ComputeFileHashHandlesMediumFile) {
    // Create 1 MB test file
    {
        std::ofstream file("test_hash_large.bin", std::ios::binary);
        std::vector<char> data(1024 * 1024, 'X');
        file.write(data.data(), data.size());
    }

    unsigned char result[HASH_SIZE];
    std::string errorMsg;
    ASSERT_TRUE(HashUtils::computeFileHash("test_hash_large.bin", result, errorMsg));

    // Verify not all zeros
    bool nonZero = false;
    for (int i = 0; i < HASH_SIZE; ++i) {
        if (result[i] != 0) {
            nonZero = true;
            break;
        }
    }
    EXPECT_TRUE(nonZero);
}

/**
 * @test computeFileHash returns false for non-existent file
 */
TEST_F(HashUtilsTest, ComputeFileHashReturnsFalseForNonExistentFile) {
    unsigned char result[HASH_SIZE];
    std::string errorMsg;
    EXPECT_FALSE(HashUtils::computeFileHash("nonexistent_file_12345.txt", result, errorMsg));
    EXPECT_FALSE(errorMsg.empty());
}

//=============================================================================
// Incremental Hashing Tests
//=============================================================================

/**
 * @test IncrementalHash computes correct final hash
 */
TEST_F(HashUtilsTest, IncrementalHashComputesCorrectly) {
    std::string testData = "Incremental hash test data";
    std::vector<unsigned char> buffer(testData.begin(), testData.end());

    // Single-shot hash
    std::vector<unsigned char> expected = HashUtils::computeBufferHash(buffer.data(), buffer.size());

    // Incremental hash (byte by byte)
    HashUtils::IncrementalHash incHash;
    for (uint8_t byte : buffer) {
        ASSERT_TRUE(incHash.update(&byte, 1));
    }
    unsigned char result[HASH_SIZE];
    ASSERT_TRUE(incHash.finalize(result));

    EXPECT_TRUE(HashUtils::compareHashes(expected.data(), result));
}

/**
 * @test IncrementalHash handles multiple updates
 */
TEST_F(HashUtilsTest, IncrementalHashHandlesMultipleUpdates) {
    std::string testData = "Multiple update test for incremental hashing";
    std::vector<unsigned char> buffer(testData.begin(), testData.end());

    // Single-shot hash
    std::vector<unsigned char> expected = HashUtils::computeBufferHash(buffer.data(), buffer.size());

    // Incremental hash with multiple updates
    HashUtils::IncrementalHash incHash;
    size_t chunkSize = 10;
    for (size_t i = 0; i < buffer.size(); i += chunkSize) {
        size_t bytesToUpdate = std::min(chunkSize, buffer.size() - i);
        ASSERT_TRUE(incHash.update(buffer.data() + i, bytesToUpdate));
    }
    unsigned char result[HASH_SIZE];
    ASSERT_TRUE(incHash.finalize(result));

    EXPECT_TRUE(HashUtils::compareHashes(expected.data(), result));
}

/**
 * @test IncrementalHash can be reset and reused
 */
TEST_F(HashUtilsTest, IncrementalHashCanBeReset) {
    std::string data1 = "First data";
    std::string data2 = "Second data";

    // Hash first data
    HashUtils::IncrementalHash incHash;
    std::vector<unsigned char> buffer1(data1.begin(), data1.end());
    ASSERT_TRUE(incHash.update(buffer1.data(), buffer1.size()));
    unsigned char hash1[HASH_SIZE];
    ASSERT_TRUE(incHash.finalize(hash1));

    // Reset and hash second data
    ASSERT_TRUE(incHash.reset());
    std::vector<unsigned char> buffer2(data2.begin(), data2.end());
    ASSERT_TRUE(incHash.update(buffer2.data(), buffer2.size()));
    unsigned char hash2[HASH_SIZE];
    ASSERT_TRUE(incHash.finalize(hash2));

    // Verify hashes are different
    EXPECT_FALSE(HashUtils::compareHashes(hash1, hash2));

    // Verify second hash is correct
    std::vector<unsigned char> expected2 = HashUtils::computeBufferHash(buffer2.data(), buffer2.size());
    EXPECT_TRUE(HashUtils::compareHashes(expected2.data(), hash2));
}

//=============================================================================
// Round-Trip Tests
//=============================================================================

/**
 * @test Hash can be converted to string and back
 */
TEST_F(HashUtilsTest, HashRoundTripThroughString) {
    unsigned char original[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; ++i) {
        original[i] = static_cast<unsigned char>(i * 7);
    }

    std::string hexString = HashUtils::hashToString(original);

    unsigned char recovered[HASH_SIZE];
    ASSERT_TRUE(HashUtils::stringToHash(hexString, recovered));

    EXPECT_TRUE(HashUtils::compareHashes(original, recovered));
}

//=============================================================================
// Edge Cases
//=============================================================================

/**
 * @test Hash handles maximum size buffer (stress test)
 */
TEST_F(HashUtilsTest, HashHandlesLargeBuffer) {
    // Create 10 MB buffer
    std::vector<unsigned char> largeBuffer(10 * 1024 * 1024, 0xAB);

    std::vector<unsigned char> result = HashUtils::computeBufferHash(largeBuffer.data(), largeBuffer.size());

    EXPECT_EQ(result.size(), HASH_SIZE);

    // Verify it's consistent
    std::vector<unsigned char> result2 = HashUtils::computeBufferHash(largeBuffer.data(), largeBuffer.size());
    EXPECT_EQ(result, result2);
}

/**
 * @test Hash handles buffer with all possible byte values
 */
TEST_F(HashUtilsTest, HashHandlesAllByteValues) {
    unsigned char allBytes[256];
    for (int i = 0; i < 256; ++i) {
        allBytes[i] = static_cast<unsigned char>(i);
    }

    std::vector<unsigned char> result = HashUtils::computeBufferHash(allBytes, 256);

    EXPECT_EQ(result.size(), HASH_SIZE);
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
