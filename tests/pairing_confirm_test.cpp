/**
 * @file pairing_confirm_test.cpp
 * @brief Unit tests for pairing confirmation key and tag derivation (HKDF + HMAC).
 */

#include "exosend/PairingConfirm.h"

#include <gtest/gtest.h>

#include <array>
#include <string>

using namespace ExoSend;

namespace {

static std::array<uint8_t, 16> makeSecret() {
    std::array<uint8_t, 16> s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(0x10u + i);
    return s;
}

static std::array<uint8_t, 32> makeExporter(uint8_t start) {
    std::array<uint8_t, 32> e{};
    for (size_t i = 0; i < e.size(); ++i) e[i] = static_cast<uint8_t>(start + i);
    return e;
}

}  // namespace

TEST(PairingConfirmTest, TagsDifferByRoleAndVerify) {
    const auto secret = makeSecret();
    const auto exporter = makeExporter(0xA0);

    std::array<uint8_t, 32> key{};
    std::string err;
    ASSERT_TRUE(PairingConfirm::deriveConfirmKey(secret, exporter, key, err)) << err;

    const std::string peerUuid = "peer-uuid-123";
    const std::string peerFp = "ABCDEF0123456789";
    const std::string localUuid = "local-uuid-456";
    const std::string localFp = "0123456789ABCDEF";

    std::array<uint8_t, 32> tagClient{};
    std::array<uint8_t, 32> tagServer{};

    ASSERT_TRUE(PairingConfirm::computeTag(key, PairingRole::Client, localUuid, localFp, peerUuid, peerFp, tagClient, err)) << err;
    ASSERT_TRUE(PairingConfirm::computeTag(key, PairingRole::Server, localUuid, localFp, peerUuid, peerFp, tagServer, err)) << err;

    EXPECT_NE(tagClient, tagServer);
    EXPECT_TRUE(PairingConfirm::verifyTag(key, PairingRole::Client, localUuid, localFp, peerUuid, peerFp, tagClient, err)) << err;
    EXPECT_TRUE(PairingConfirm::verifyTag(key, PairingRole::Server, localUuid, localFp, peerUuid, peerFp, tagServer, err)) << err;
}

TEST(PairingConfirmTest, WrongInputsFailVerification) {
    const auto secret = makeSecret();
    const auto exporter = makeExporter(0x20);

    std::array<uint8_t, 32> key{};
    std::string err;
    ASSERT_TRUE(PairingConfirm::deriveConfirmKey(secret, exporter, key, err)) << err;

    const std::string peerUuid = "peer-uuid-123";
    const std::string peerFp = "ABCDEF0123456789";
    const std::string localUuid = "local-uuid-456";
    const std::string localFp = "0123456789ABCDEF";

    std::array<uint8_t, 32> tag{};
    ASSERT_TRUE(PairingConfirm::computeTag(key, PairingRole::Client, localUuid, localFp, peerUuid, peerFp, tag, err)) << err;

    EXPECT_FALSE(PairingConfirm::verifyTag(key, PairingRole::Client, localUuid, localFp, "different", peerFp, tag, err));
    EXPECT_FALSE(PairingConfirm::verifyTag(key, PairingRole::Client, localUuid, localFp, peerUuid, "different", tag, err));

    const auto exporter2 = makeExporter(0x21);
    std::array<uint8_t, 32> wrongKey{};
    ASSERT_TRUE(PairingConfirm::deriveConfirmKey(secret, exporter2, wrongKey, err)) << err;
    EXPECT_FALSE(PairingConfirm::verifyTag(wrongKey, PairingRole::Client, localUuid, localFp, peerUuid, peerFp, tag, err));
}
