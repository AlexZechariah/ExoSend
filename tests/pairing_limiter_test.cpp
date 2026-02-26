/**
 * @file pairing_limiter_test.cpp
 * @brief Unit tests for PairingPromptLimiter rate-limiting behavior.
 */

#include "exosend/PairingPromptLimiter.h"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using namespace ExoSend;

// First prompt for a fresh limiter must be allowed.
TEST(PairingLimiterTest, AllowsFirstPrompt) {
    PairingPromptLimiter limiter;
    EXPECT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);
}

// A second concurrent prompt (different peer) must be blocked by the global guard.
TEST(PairingLimiterTest, BlocksSecondConcurrentPrompt) {
    PairingPromptLimiter limiter;
    ASSERT_TRUE(limiter.beginPrompt("peer-a"));
    // peer-b blocked because peer-a's prompt is still active.
    EXPECT_FALSE(limiter.beginPrompt("peer-b"));
    limiter.endPrompt("peer-a", false);
}

// A second prompt for the same peer within the cooldown window must be blocked.
TEST(PairingLimiterTest, CooldownAfterRejection) {
    PairingPromptLimiter limiter;
    ASSERT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);

    // Immediately try again -- must be in cooldown.
    EXPECT_FALSE(limiter.beginPrompt("peer-a"));
}

// After an acceptance, the peer has no cooldown and can be prompted again immediately.
TEST(PairingLimiterTest, NoBlockAfterAccept) {
    PairingPromptLimiter limiter;
    ASSERT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", true);

    // Accept clears the cooldown: next prompt must be allowed.
    EXPECT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);
}

// Different peers have independent cooldowns.
TEST(PairingLimiterTest, IndependentCooldownsPerPeer) {
    PairingPromptLimiter limiter;

    ASSERT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);  // peer-a now in cooldown

    // peer-b has never been seen; its prompt must be allowed.
    EXPECT_TRUE(limiter.beginPrompt("peer-b"));
    limiter.endPrompt("peer-b", false);
}

// After the cooldown window expires, the peer can be prompted again.
// Uses a 1-second limiter and sleeps 1.1 seconds.
TEST(PairingLimiterTest, CooldownExpires) {
    PairingPromptLimiter limiter(1);  // 1-second cooldown
    ASSERT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);

    // Should be blocked immediately.
    EXPECT_FALSE(limiter.beginPrompt("peer-a"));

    // Wait for cooldown to expire.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Now must be allowed.
    EXPECT_TRUE(limiter.beginPrompt("peer-a"));
    limiter.endPrompt("peer-a", false);
}
