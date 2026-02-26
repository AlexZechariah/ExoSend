#include <gtest/gtest.h>
#include "exosend/ConnectionRateLimiter.h"

#include <thread>
#include <chrono>

using namespace ExoSend;

class ConnectionRateLimiterTest : public ::testing::Test {
protected:
    ConnectionRateLimiter limiter;
    const std::string ip1 = "192.168.1.200";
    const std::string ip2 = "192.168.1.201";
};

TEST_F(ConnectionRateLimiterTest, AcceptsFirstConnectionFromNewIp) {
    EXPECT_TRUE(limiter.shouldAccept(ip1));
}

TEST_F(ConnectionRateLimiterTest, AcceptsUpToMaxInWindow) {
    for (size_t i = 0; i < TRANSFER_CONN_RATE_LIMIT_MAX_COUNT; ++i) {
        EXPECT_TRUE(limiter.shouldAccept(ip1)) << "Failed on call " << i;
    }
}

TEST_F(ConnectionRateLimiterTest, RejectsOverLimit) {
    for (size_t i = 0; i < TRANSFER_CONN_RATE_LIMIT_MAX_COUNT; ++i) {
        limiter.shouldAccept(ip1);
    }
    EXPECT_FALSE(limiter.shouldAccept(ip1));
}

TEST_F(ConnectionRateLimiterTest, DifferentIpsTrackedIndependently) {
    for (size_t i = 0; i < TRANSFER_CONN_RATE_LIMIT_MAX_COUNT; ++i) {
        limiter.shouldAccept(ip1);
    }
    EXPECT_TRUE(limiter.shouldAccept(ip2));
    EXPECT_FALSE(limiter.shouldAccept(ip1));
}

TEST_F(ConnectionRateLimiterTest, WindowExpiryResetsCount) {
    ConnectionRateLimiter shortLimiter(/*maxCount=*/3, /*windowMs=*/50);
    shortLimiter.shouldAccept(ip1);
    shortLimiter.shouldAccept(ip1);
    shortLimiter.shouldAccept(ip1);
    EXPECT_FALSE(shortLimiter.shouldAccept(ip1));

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_TRUE(shortLimiter.shouldAccept(ip1));
}

