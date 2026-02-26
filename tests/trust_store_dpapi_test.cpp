#include <gtest/gtest.h>

#include "exosend/TrustStoreDpapi.h"

TEST(TrustStoreDpapiTest, PreservesExistingWhenProtectFails)
{
    auto failingProtect = [](const std::string&, std::string& err) -> std::vector<uint8_t> {
        err = "forced failure";
        return {};
    };

    const auto r = ExoSend::protectTrustStoreJsonToBase64(
        R"({"dummy":true})",
        "EXISTING_B64",
        failingProtect);

    EXPECT_TRUE(r.ok);
    EXPECT_TRUE(r.usedExisting);
    EXPECT_EQ(r.trustStoreDpapiBase64, "EXISTING_B64");
}

TEST(TrustStoreDpapiTest, FailsWhenProtectFailsAndNoExisting)
{
    auto failingProtect = [](const std::string&, std::string& err) -> std::vector<uint8_t> {
        err = "forced failure";
        return {};
    };

    const auto r = ExoSend::protectTrustStoreJsonToBase64(
        R"({"dummy":true})",
        "",
        failingProtect);

    EXPECT_FALSE(r.ok);
}

TEST(TrustStoreDpapiTest, UsesProtectedValueWhenProtectSucceeds)
{
    auto fakeProtect = [](const std::string&, std::string& err) -> std::vector<uint8_t> {
        err.clear();
        return std::vector<uint8_t>{0x01, 0x02, 0x03};
    };

    const auto r = ExoSend::protectTrustStoreJsonToBase64(
        R"({"dummy":true})",
        "EXISTING_B64",
        fakeProtect);

    EXPECT_TRUE(r.ok);
    EXPECT_FALSE(r.usedExisting);
    EXPECT_FALSE(r.trustStoreDpapiBase64.empty());
    EXPECT_NE(r.trustStoreDpapiBase64, "EXISTING_B64");
}

