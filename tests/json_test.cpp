/**
 * @file json_test.cpp
 * @brief Unit tests for discovery beacon JSON parsing
 *
 * Tests JSON structure validation for peer discovery beacons,
 * including protocol_id, UUID format, and required fields.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#include "exosend/config.h"
#include "exosend/PeerInfo.h"
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <regex>

using json = nlohmann::json;
using namespace ExoSend;

//=============================================================================
// Test Fixtures
//=============================================================================

/**
 * @brief Test fixture for JSON beacon tests
 */
class BeaconJsonTest : public ::testing::Test {
protected:
    std::string validUuid = "550e8400-e29b-41d4-a716-446655440000";
    std::string validDisplayName = "TestPC-01";
    std::string validProtocolId = PROTOCOL_ID;
    uint16_t validPort = TCP_PORT_DEFAULT;

    void SetUp() override {}
    void TearDown() override {}
};

//=============================================================================
// JSON Structure Tests
//=============================================================================

/**
 * @test Valid JSON beacon has all required fields
 */
TEST_F(BeaconJsonTest, ValidBeaconHasAllRequiredFields) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "TestPC-01",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);

    EXPECT_TRUE(j.contains("protocol_id"));
    EXPECT_TRUE(j.contains("device_uuid"));
    EXPECT_TRUE(j.contains("display_name"));
    EXPECT_TRUE(j.contains("os_platform"));
    EXPECT_TRUE(j.contains("tcp_port"));
}

/**
 * @test JSON beacon with extra fields is still valid
 */
TEST_F(BeaconJsonTest, BeaconWithExtraFieldsParses) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": 9999,
        "extra_field": "ignored",
        "another_field": 12345
    })";

    // Should parse successfully
    json j = json::parse(jsonStr);
    EXPECT_TRUE(j.is_object());
}

//=============================================================================
// Protocol ID Tests
//=============================================================================

/**
 * @test Valid protocol_id is EXOSEND_V1
 */
TEST_F(BeaconJsonTest, ValidProtocolIdIsExoSendV1) {
    EXPECT_EQ(validProtocolId, "EXOSEND_V1");
}

/**
 * @test Protocol_id field can be extracted from JSON
 */
TEST_F(BeaconJsonTest, ProtocolIdCanBeExtracted) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string protocolId = j["protocol_id"];

    EXPECT_EQ(protocolId, "EXOSEND_V1");
}

//=============================================================================
// UUID Format Tests
//=============================================================================

/**
 * @test Valid UUID v4 format matches regex
 */
TEST_F(BeaconJsonTest, ValidUuidMatchesRegex) {
    std::regex uuidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    EXPECT_TRUE(std::regex_match(validUuid, uuidRegex));
}

/**
 * @test UUID without hyphens doesn't match regex
 */
TEST_F(BeaconJsonTest, UuidWithoutHyphensDoesNotMatchRegex) {
    std::string invalidUuid = "550e8400e29b41d4a716446655440000";
    std::regex uuidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    EXPECT_FALSE(std::regex_match(invalidUuid, uuidRegex));
}

/**
 * @test UUID with invalid characters doesn't match regex
 */
TEST_F(BeaconJsonTest, UuidWithInvalidCharsDoesNotMatchRegex) {
    std::string invalidUuid = "550e8400-e29b-41d4-a716-44665544000G";  // 'G' is invalid
    std::regex uuidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    EXPECT_FALSE(std::regex_match(invalidUuid, uuidRegex));
}

/**
 * @test UUID can be extracted from JSON
 */
TEST_F(BeaconJsonTest, UuidCanBeExtracted) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string uuid = j["device_uuid"];

    EXPECT_EQ(uuid, "550e8400-e29b-41d4-a716-446655440000");
}

//=============================================================================
// Display Name Tests
//=============================================================================

/**
 * @test Display name can be extracted from JSON
 */
TEST_F(BeaconJsonTest, DisplayNameCanBeExtracted) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "My Computer",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string displayName = j["display_name"];

    EXPECT_EQ(displayName, "My Computer");
}

/**
 * @test Display name with special characters is preserved
 */
TEST_F(BeaconJsonTest, DisplayNameWithSpecialCharsPreserved) {
    std::string specialName = "PC-01 (Office) [2]";
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": ")" + specialName + R"(",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string displayName = j["display_name"];

    EXPECT_EQ(displayName, specialName);
}

/**
 * @test Display name with Unicode characters is preserved
 */
TEST_F(BeaconJsonTest, DisplayNameWithUnicodePreserved) {
    std::string unicodeName = "电脑-01";  // Chinese characters
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": ")" + unicodeName + R"(",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string displayName = j["display_name"];

    EXPECT_EQ(displayName, unicodeName);
}

/**
 * @test Maximum length display name is within limits
 */
TEST_F(BeaconJsonTest, MaxLengthDisplayNameIsWithinLimits) {
    std::string maxName(MAX_DISPLAY_NAME, 'A');  // 64 'A' characters

    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": ")" + maxName + R"(",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string displayName = j["display_name"];

    EXPECT_EQ(displayName.length(), MAX_DISPLAY_NAME);
}

//=============================================================================
// TCP Port Tests
//=============================================================================

/**
 * @test TCP port can be extracted from JSON
 */
TEST_F(BeaconJsonTest, TcpPortCanBeExtracted) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": 8888
    })";

    json j = json::parse(jsonStr);
    uint16_t port = j["tcp_port"];

    EXPECT_EQ(port, 8888);
}

/**
 * @test TCP port default value matches config
 */
TEST_F(BeaconJsonTest, TcpPortDefaultMatchesConfig) {
    EXPECT_EQ(validPort, 9999);
}

/**
 * @test TCP port is within valid range
 */
TEST_F(BeaconJsonTest, TcpPortIsWithinValidRange) {
    // Valid port range: 1024-65535
    uint16_t port = 9999;
    EXPECT_GE(port, 1024);
    EXPECT_LE(port, 65535);
}

//=============================================================================
// OS Platform Tests
//=============================================================================

/**
 * @test OS platform can be extracted from JSON
 */
TEST_F(BeaconJsonTest, OsPlatformCanBeExtracted) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string osPlatform = j["os_platform"];

    EXPECT_EQ(osPlatform, "Windows 10");
}

/**
 * @test OS platform constant matches expected value
 */
TEST_F(BeaconJsonTest, OsPlatformConstantMatchesExpected) {
    EXPECT_EQ(OS_PLATFORM, "Windows 10");
}

//=============================================================================
// PeerInfo Structure Tests
//=============================================================================

/**
 * @test PeerInfo default constructor initializes fields
 */
TEST_F(BeaconJsonTest, PeerInfoDefaultConstructorInitializesFields) {
    PeerInfo peer;

    EXPECT_TRUE(peer.uuid.empty());
    EXPECT_TRUE(peer.displayName.empty());
    EXPECT_TRUE(peer.ipAddress.empty());
    EXPECT_EQ(peer.tcpPort, 0);
}

/**
 * @test PeerInfo parameterized constructor sets fields
 */
TEST_F(BeaconJsonTest, PeerInfoParameterizedConstructorSetsFields) {
    PeerInfo peer("uuid-123", "TestPC", "192.168.1.100", 9999);

    EXPECT_EQ(peer.uuid, "uuid-123");
    EXPECT_EQ(peer.displayName, "TestPC");
    EXPECT_EQ(peer.ipAddress, "192.168.1.100");
    EXPECT_EQ(peer.tcpPort, 9999);
}

/**
 * @test PeerInfo timeout detection works
 */
TEST_F(BeaconJsonTest, PeerInfoTimeoutDetection) {
    PeerInfo peer("uuid-123", "TestPC", "192.168.1.100", 9999);

    // Just created, should not be timed out
    EXPECT_FALSE(peer.isTimedOut(PEER_TIMEOUT_MS));
}

//=============================================================================
// JSON Parsing Edge Cases
//=============================================================================

/**
 * @test JSON with missing field can still be parsed
 */
TEST_F(BeaconJsonTest, JsonWithMissingFieldStillParses) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "tcp_port": 9999
    })";

    // Missing os_platform, but should still parse
    json j = json::parse(jsonStr);
    EXPECT_TRUE(j.is_object());
    EXPECT_FALSE(j.contains("os_platform"));
}

/**
 * @test Empty display name is handled
 */
TEST_F(BeaconJsonTest, EmptyDisplayNameHandled) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);
    std::string displayName = j["display_name"];

    EXPECT_TRUE(displayName.empty());
}

/**
 * @test TCP port as string is handled by JSON parser
 */
TEST_F(BeaconJsonTest, TcpPortAsStringHandled) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "Test",
        "os_platform": "Windows 10",
        "tcp_port": "7777"
    })";

    json j = json::parse(jsonStr);

    // JSON will parse port as string
    EXPECT_TRUE(j["tcp_port"].is_string());
    EXPECT_EQ(j["tcp_port"], "7777");
}

//=============================================================================
// Integration Tests
//=============================================================================

/**
 * @test Complete beacon can be parsed and values extracted
 */
TEST_F(BeaconJsonTest, CompleteBeaconCanBeParsed) {
    std::string jsonStr = R"({
        "protocol_id": "EXOSEND_V1",
        "device_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "display_name": "TestPC-01",
        "os_platform": "Windows 10",
        "tcp_port": 9999
    })";

    json j = json::parse(jsonStr);

    EXPECT_EQ(j["protocol_id"], "EXOSEND_V1");
    EXPECT_EQ(j["device_uuid"], "550e8400-e29b-41d4-a716-446655440000");
    EXPECT_EQ(j["display_name"], "TestPC-01");
    EXPECT_EQ(j["os_platform"], "Windows 10");
    EXPECT_EQ(j["tcp_port"], 9999);
}

/**
 * @test Multiple beacons with different values can be parsed
 */
TEST_F(BeaconJsonTest, MultipleBeaconsCanBeParsed) {
    std::vector<std::tuple<std::string, std::string, uint16_t>> testCases = {
        {"uuid-1", "PC-One", 9999},
        {"uuid-2", "PC-Two", 8888},
        {"uuid-3", "PC-Three", 7777}
    };

    for (const auto& [uuid, name, port] : testCases) {
        std::string jsonStr = R"({
            "protocol_id": "EXOSEND_V1",
            "device_uuid": ")" + uuid + R"(",
            "display_name": ")" + name + R"(",
            "os_platform": "Windows 10",
            "tcp_port": )" + std::to_string(port) + R"(
        })";

        json j = json::parse(jsonStr);
        EXPECT_EQ(j["device_uuid"], uuid);
        EXPECT_EQ(j["display_name"], name);
        EXPECT_EQ(j["tcp_port"], port);
    }
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
