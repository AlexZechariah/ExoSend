/**
 * @file protocol_test.cpp
 * @brief Unit tests for ExoSend binary protocol header (ExoHeader)
 *
 * Tests ExoHeader construction, serialization, deserialization,
 * validation, and edge cases.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#include "exosend/TransferHeader.h"
#include "exosend/config.h"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstddef>

using namespace ExoSend;

//=============================================================================
// Test Fixtures
//=============================================================================

/**
 * @brief Test fixture for ExoHeader tests
 */
class ExoHeaderTest : public ::testing::Test {
protected:
    std::vector<uint8_t> buffer;

    void SetUp() override {
        buffer.resize(HEADER_SIZE, 0);
    }
};

//=============================================================================
// Construction Tests
//=============================================================================

/**
 * @test Default constructor initializes all fields to zero
 */
TEST_F(ExoHeaderTest, DefaultConstructorInitializesToZero) {
    ExoHeader header;

    EXPECT_EQ(header.magic, 0);
    EXPECT_EQ(header.packetType, 0);
    EXPECT_EQ(header.fileSize, 0);
    EXPECT_EQ(header.filenameLength, 0);
    EXPECT_EQ(header.filename[0], '\0');
    EXPECT_EQ(header.getFilename(), "");
}

/**
 * @test Parameterized constructor sets fields correctly
 */
TEST_F(ExoHeaderTest, ParameterizedConstructorSetsFields) {
    std::string testFilename = "test_file.txt";
    uint64_t testSize = 1024 * 1024;  // 1 MB

    ExoHeader header(PacketType::OFFER, testSize, testFilename);

    EXPECT_EQ(header.fileSize, testSize);
    EXPECT_EQ(header.getPacketType(), PacketType::OFFER);
    EXPECT_EQ(header.getFilename(), testFilename);
    EXPECT_EQ(header.filenameLength, testFilename.length());
}

/**
 * @test Magic number is initialized in constructor
 */
TEST_F(ExoHeaderTest, MagicNumberSetInConstructor) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");

    EXPECT_EQ(header.magic, MAGIC_NUMBER);
}

//=============================================================================
// Filename Handling Tests
//=============================================================================

/**
 * @test Short filename is stored correctly
 */
TEST_F(ExoHeaderTest, ShortFilenameStoredCorrectly) {
    std::string shortName = "a.txt";
    ExoHeader header(PacketType::OFFER, 100, shortName);

    EXPECT_EQ(header.getFilename(), shortName);
    EXPECT_EQ(header.filenameLength, shortName.length());
}

/**
 * @test Long filename is truncated to 255 characters
 */
TEST_F(ExoHeaderTest, LongFilenameTruncatedTo255) {
    // Create a filename longer than 256 characters
    std::string longName(300, 'a');  // 300 'a' characters
    ExoHeader header(PacketType::OFFER, 100, longName);

    // Should be truncated to 255 characters
    EXPECT_EQ(header.getFilename().length(), 255);
    EXPECT_EQ(header.filenameLength, 255);
}

/**
 * @test Filename is null-terminated
 */
TEST_F(ExoHeaderTest, FilenameIsNullTerminated) {
    std::string name = "test.txt";
    ExoHeader header(PacketType::OFFER, 100, name);

    // Find null terminator
    size_t nullPos = 0;
    for (; nullPos < sizeof(header.filename); ++nullPos) {
        if (header.filename[nullPos] == '\0') {
            break;
        }
    }

    EXPECT_GT(nullPos, 0);
    EXPECT_LE(nullPos, sizeof(header.filename) - 1);
}

/**
 * @test Filename with special characters is preserved
 */
TEST_F(ExoHeaderTest, SpecialCharactersPreserved) {
    std::string specialName = "test file (1) [copy].txt";
    ExoHeader header(PacketType::OFFER, 100, specialName);

    EXPECT_EQ(header.getFilename(), specialName);
}

//=============================================================================
// Serialization Tests
//=============================================================================

/**
 * @test serializeToBuffer converts magic number to network byte order
 */
TEST_F(ExoHeaderTest, SerializeConvertsMagicToNetworkByteOrder) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = MAGIC_NUMBER;

    ASSERT_TRUE(header.serializeToBuffer(buffer.data()));

    // First 4 bytes should be magic number in big-endian
    uint32_t networkMagic;
    std::memcpy(&networkMagic, buffer.data(), sizeof(uint32_t));
    uint32_t hostMagic = ntohl(networkMagic);

    EXPECT_EQ(hostMagic, MAGIC_NUMBER);
}

/**
 * @test serializeToBuffer converts file size to network byte order
 */
TEST_F(ExoHeaderTest, SerializeConvertsFileSizeToNetworkByteOrder) {
    uint64_t testSize = 1024 * 1024;  // 1 MB - simpler value
    ExoHeader header(PacketType::OFFER, testSize, "test.txt");
    header.magic = MAGIC_NUMBER;  // Set magic before serialization

    ASSERT_TRUE(header.serializeToBuffer(buffer.data()));

    // File size field should be serialized in big-endian at the wire offset
    uint64_t networkSize;
    std::memcpy(&networkSize, buffer.data() + offsetof(ExoHeader, fileSize), sizeof(uint64_t));

    // Convert back from network byte order
    uint64_t hostSize = ntohll(networkSize);

    EXPECT_EQ(hostSize, testSize);
}

/**
 * @test serializeToBuffer converts filename length to network byte order
 */
TEST_F(ExoHeaderTest, SerializeConvertsFilenameLengthToNetworkByteOrder) {
    std::string name = "test.txt";
    ExoHeader header(PacketType::OFFER, 1024, name);
    header.magic = MAGIC_NUMBER;  // Set magic before serialization

    ASSERT_TRUE(header.serializeToBuffer(buffer.data()));

    // Filename length field should be serialized in big-endian at the wire offset
    uint16_t networkLength;
    std::memcpy(&networkLength, buffer.data() + offsetof(ExoHeader, filenameLength), sizeof(uint16_t));
    uint16_t hostLength = ntohs(networkLength);

    EXPECT_EQ(hostLength, name.length());
}

/**
 * @test serializeToBuffer returns false for null buffer
 */
TEST_F(ExoHeaderTest, SerializeReturnsFalseForNullBuffer) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");

    EXPECT_FALSE(header.serializeToBuffer(nullptr));
}

//=============================================================================
// Deserialization Tests
//=============================================================================

/**
 * @test deserializeFromBuffer converts magic number from network byte order
 */
TEST_F(ExoHeaderTest, DeserializeConvertsMagicFromNetworkByteOrder) {
    // Set up buffer with magic number in network byte order
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    std::memcpy(buffer.data(), &networkMagic, sizeof(uint32_t));

    ExoHeader header;
    ASSERT_TRUE(header.deserializeFromBuffer(buffer.data()));

    EXPECT_EQ(header.magic, MAGIC_NUMBER);
}

/**
 * @test deserializeFromBuffer converts file size from network byte order
 */
TEST_F(ExoHeaderTest, DeserializeConvertsFileSizeFromNetworkByteOrder) {
    uint64_t testSize = 1024 * 1024;  // 1 MB - simpler value

    // Set up buffer with all required fields using struct wire offsets
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    uint64_t networkSize = htonll(testSize);

    // Clear buffer first
    std::memset(buffer.data(), 0, HEADER_SIZE);

    std::memcpy(buffer.data() + offsetof(ExoHeader, magic), &networkMagic, sizeof(uint32_t));
    buffer[offsetof(ExoHeader, packetType)] = static_cast<uint8_t>(PacketType::OFFER);
    std::memcpy(buffer.data() + offsetof(ExoHeader, fileSize), &networkSize, sizeof(uint64_t));

    ExoHeader header;
    ASSERT_TRUE(header.deserializeFromBuffer(buffer.data()));

    EXPECT_EQ(header.fileSize, testSize);
}

/**
 * @test deserializeFromBuffer reads filename correctly
 */
TEST_F(ExoHeaderTest, DeserializeReadsFilenameCorrectly) {
    std::string name = "testfile.bin";
    uint16_t nameLen = static_cast<uint16_t>(name.length());
    uint64_t fileSize = 1024;

    // Set up buffer with all required fields (using actual struct wire offsets)
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    uint64_t networkSize = htonll(fileSize);
    uint16_t networkLen = htons(nameLen);

    // Clear buffer first
    std::memset(buffer.data(), 0, HEADER_SIZE);

    // Use offsetof to get actual field offsets in the struct
    size_t magicOffset = offsetof(ExoHeader, magic);
    size_t packetTypeOffset = offsetof(ExoHeader, packetType);
    size_t fileSizeOffset = offsetof(ExoHeader, fileSize);
    size_t filenameLengthOffset = offsetof(ExoHeader, filenameLength);
    size_t filenameOffset = offsetof(ExoHeader, filename);

    std::memcpy(buffer.data() + magicOffset, &networkMagic, sizeof(uint32_t));
    buffer[packetTypeOffset] = static_cast<uint8_t>(PacketType::OFFER);
    std::memcpy(buffer.data() + fileSizeOffset, &networkSize, sizeof(uint64_t));
    std::memcpy(buffer.data() + filenameLengthOffset, &networkLen, sizeof(uint16_t));
    std::memcpy(buffer.data() + filenameOffset, name.c_str(), nameLen);

    ExoHeader header;
    ASSERT_TRUE(header.deserializeFromBuffer(buffer.data()));

    EXPECT_EQ(header.getFilename(), name);
    EXPECT_EQ(header.filenameLength, nameLen);
}

/**
 * @test deserializeFromBuffer returns false for null buffer
 */
TEST_F(ExoHeaderTest, DeserializeReturnsFalseForNullBuffer) {
    ExoHeader header;
    EXPECT_FALSE(header.deserializeFromBuffer(nullptr));
}

//=============================================================================
// Validation Tests
//=============================================================================

/**
 * @test isValid returns true for valid header
 */
TEST_F(ExoHeaderTest, IsValidReturnsTrueForValidHeader) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = MAGIC_NUMBER;

    EXPECT_TRUE(header.isValid());
}

/**
 * @test isValid returns false for wrong magic number
 */
TEST_F(ExoHeaderTest, IsValidReturnsFalseForWrongMagic) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = 0x12345678;  // Wrong magic

    EXPECT_FALSE(header.isValid());
}

/**
 * @test isValid returns false for invalid packet type
 */
TEST_F(ExoHeaderTest, IsValidReturnsFalseForInvalidPacketType) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = MAGIC_NUMBER;
    header.packetType = 0xFF;  // Invalid type

    EXPECT_FALSE(header.isValid());
}

/**
 * @test isValid returns false for filename too long
 */
TEST_F(ExoHeaderTest, IsValidReturnsFalseForFilenameTooLong) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = MAGIC_NUMBER;
    header.filenameLength = 257;  // Too long

    EXPECT_FALSE(header.isValid());
}

//=============================================================================
// Packet Type Tests
//=============================================================================

/**
 * @test getPacketType returns correct enum values
 */
TEST_F(ExoHeaderTest, GetPacketTypeReturnsCorrectEnum) {
    ExoHeader offerHeader(PacketType::OFFER, 100, "test.txt");
    EXPECT_EQ(offerHeader.getPacketType(), PacketType::OFFER);

    ExoHeader acceptHeader(PacketType::ACCEPT, 100, "test.txt");
    EXPECT_EQ(acceptHeader.getPacketType(), PacketType::ACCEPT);

    ExoHeader rejectHeader(PacketType::REJECT, 100, "test.txt");
    EXPECT_EQ(rejectHeader.getPacketType(), PacketType::REJECT);

    ExoHeader busyHeader(PacketType::BUSY, 100, "test.txt");
    EXPECT_EQ(busyHeader.getPacketType(), PacketType::BUSY);

    ExoHeader hashHeader(PacketType::HASH, 0, "");
    EXPECT_EQ(hashHeader.getPacketType(), PacketType::HASH);

    ExoHeader hashOkHeader(PacketType::HASH_OK, 0, "");
    EXPECT_EQ(hashOkHeader.getPacketType(), PacketType::HASH_OK);

    ExoHeader hashBadHeader(PacketType::HASH_BAD, 0, "");
    EXPECT_EQ(hashBadHeader.getPacketType(), PacketType::HASH_BAD);

    // Pairing protocol extensions (maximum-security hardening)
    ExoHeader pairReqHeader(PacketType::PAIR_REQ, 0, "");
    EXPECT_EQ(pairReqHeader.getPacketType(), PacketType::PAIR_REQ);

    ExoHeader pairRespHeader(PacketType::PAIR_RESP, 0, "");
    EXPECT_EQ(pairRespHeader.getPacketType(), PacketType::PAIR_RESP);
}

/**
 * @test getPacketTypeString returns correct strings
 */
TEST_F(ExoHeaderTest, GetPacketTypeStringReturnsCorrectStrings) {
    ExoHeader header(PacketType::OFFER, 100, "test.txt");

    header.packetType = static_cast<uint8_t>(PacketType::OFFER);
    EXPECT_EQ(header.getPacketTypeString(), "OFFER");

    header.packetType = static_cast<uint8_t>(PacketType::ACCEPT);
    EXPECT_EQ(header.getPacketTypeString(), "ACCEPT");

    header.packetType = static_cast<uint8_t>(PacketType::REJECT);
    EXPECT_EQ(header.getPacketTypeString(), "REJECT");

    header.packetType = static_cast<uint8_t>(PacketType::BUSY);
    EXPECT_EQ(header.getPacketTypeString(), "BUSY");

    header.packetType = static_cast<uint8_t>(PacketType::HASH);
    EXPECT_EQ(header.getPacketTypeString(), "HASH");

    header.packetType = static_cast<uint8_t>(PacketType::HASH_OK);
    EXPECT_EQ(header.getPacketTypeString(), "HASH_OK");

    header.packetType = static_cast<uint8_t>(PacketType::HASH_BAD);
    EXPECT_EQ(header.getPacketTypeString(), "HASH_BAD");

    header.packetType = static_cast<uint8_t>(PacketType::PAIR_REQ);
    EXPECT_EQ(header.getPacketTypeString(), "PAIR_REQ");

    header.packetType = static_cast<uint8_t>(PacketType::PAIR_RESP);
    EXPECT_EQ(header.getPacketTypeString(), "PAIR_RESP");
}

//=============================================================================
// File Size Formatting Tests
//=============================================================================

/**
 * @test getFileSizeString formats bytes correctly
 */
TEST_F(ExoHeaderTest, GetFileSizeStringFormatsBytes) {
    ExoHeader header(PacketType::OFFER, 512, "test.txt");
    std::string sizeStr = header.getFileSizeString();
    EXPECT_TRUE(sizeStr.find("bytes") != std::string::npos);
}

/**
 * @test getFileSizeString formats kilobytes correctly
 */
TEST_F(ExoHeaderTest, GetFileSizeStringFormatsKB) {
    ExoHeader header(PacketType::OFFER, 1024 * 10, "test.txt");  // 10 KB
    std::string sizeStr = header.getFileSizeString();
    EXPECT_TRUE(sizeStr.find("KB") != std::string::npos);
}

/**
 * @test getFileSizeString formats megabytes correctly
 */
TEST_F(ExoHeaderTest, GetFileSizeStringFormatsMB) {
    ExoHeader header(PacketType::OFFER, 1024 * 1024 * 100, "test.txt");  // 100 MB
    std::string sizeStr = header.getFileSizeString();
    EXPECT_TRUE(sizeStr.find("MB") != std::string::npos);
}

/**
 * @test getFileSizeString formats gigabytes correctly
 */
TEST_F(ExoHeaderTest, GetFileSizeStringFormatsGB) {
    ExoHeader header(PacketType::OFFER, uint64_t(1024) * 1024 * 1024 * 2, "test.txt");  // 2 GB
    std::string sizeStr = header.getFileSizeString();
    EXPECT_TRUE(sizeStr.find("GB") != std::string::npos);
}

//=============================================================================
// Round-Trip Tests
//=============================================================================

/**
 * @test Serialize then deserialize preserves all data
 */
TEST_F(ExoHeaderTest, SerializeDeserializeRoundTrip) {
    std::string originalName = "original_file.bin";
    uint64_t originalSize = 5 * 1024 * 1024;  // 5 MB

    ExoHeader original(PacketType::ACCEPT, originalSize, originalName);
    original.magic = MAGIC_NUMBER;  // Set magic before serialization
    ASSERT_TRUE(original.serializeToBuffer(buffer.data()));

    ExoHeader deserialized;
    ASSERT_TRUE(deserialized.deserializeFromBuffer(buffer.data()));

    EXPECT_EQ(deserialized.magic, MAGIC_NUMBER);
    EXPECT_EQ(deserialized.getPacketType(), PacketType::ACCEPT);
    EXPECT_EQ(deserialized.fileSize, originalSize);
    EXPECT_EQ(deserialized.getFilename(), originalName);
}

/**
 * @test Multiple headers can be serialized and deserialized
 */
TEST_F(ExoHeaderTest, MultipleHeadersRoundTrip) {
    std::vector<std::pair<std::string, uint64_t>> testFiles = {
        {"a.txt", 100},
        {"medium_file.dat", 1024 * 1024},
        {"large_file.bin", uint64_t(1024) * 1024 * 1024}
    };

    for (const auto& [name, size] : testFiles) {
        ExoHeader original(PacketType::OFFER, size, name);
        ASSERT_TRUE(original.serializeToBuffer(buffer.data()));

        ExoHeader deserialized;
        ASSERT_TRUE(deserialized.deserializeFromBuffer(buffer.data()));

        EXPECT_EQ(deserialized.getFilename(), name);
        EXPECT_EQ(deserialized.fileSize, size);
    }
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
