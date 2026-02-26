#include <gtest/gtest.h>

#include "exosend/IncomingTransferPolicy.h"

TEST(IncomingTransferPolicyTest, AutoAcceptFalseWhenDisabled)
{
    EXPECT_FALSE(ExoSend::shouldAutoAcceptIncoming(
        false,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

TEST(IncomingTransferPolicyTest, AutoAcceptFalseWhenNotPinned)
{
    EXPECT_FALSE(ExoSend::shouldAutoAcceptIncoming(
        true,
        "",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

TEST(IncomingTransferPolicyTest, AutoAcceptTrueWhenPinnedAndMatches)
{
    EXPECT_TRUE(ExoSend::shouldAutoAcceptIncoming(
        true,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

TEST(IncomingTransferPolicyTest, AutoAcceptFalseWhenPinnedMismatch)
{
    EXPECT_FALSE(ExoSend::shouldAutoAcceptIncoming(
        true,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
}

