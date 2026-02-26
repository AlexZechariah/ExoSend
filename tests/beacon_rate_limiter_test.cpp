#include <gtest/gtest.h>
#include "exosend/BeaconRateLimiter.h"
#include <thread>
#include <chrono>

using namespace ExoSend;

class BeaconRateLimiterTest : public ::testing::Test {
protected:
    BeaconRateLimiter limiter;
    const std::string ip1 = "192.168.1.100";
    const std::string ip2 = "192.168.1.101";
};

TEST_F(BeaconRateLimiterTest, AcceptsFirstBeaconFromNewIp) {
    EXPECT_TRUE(limiter.shouldProcess(ip1));
}

TEST_F(BeaconRateLimiterTest, AcceptsUpToMaxBeaconsInWindow) {
    for (size_t i = 0; i < BEACON_RATE_LIMIT_MAX_COUNT; ++i) {
        EXPECT_TRUE(limiter.shouldProcess(ip1)) << "Failed on call " << i;
    }
}

TEST_F(BeaconRateLimiterTest, RejectsBeaconOverLimit) {
    for (size_t i = 0; i < BEACON_RATE_LIMIT_MAX_COUNT; ++i) {
        limiter.shouldProcess(ip1);
    }
    EXPECT_FALSE(limiter.shouldProcess(ip1));
}

TEST_F(BeaconRateLimiterTest, DifferentIpsTrackedIndependently) {
    for (size_t i = 0; i < BEACON_RATE_LIMIT_MAX_COUNT; ++i) {
        limiter.shouldProcess(ip1);
    }
    EXPECT_TRUE(limiter.shouldProcess(ip2));   // ip2 unaffected
    EXPECT_FALSE(limiter.shouldProcess(ip1));  // ip1 at limit
}

TEST_F(BeaconRateLimiterTest, WindowExpiryResetsCount) {
    BeaconRateLimiter shortLimiter(/*maxCount=*/3, /*windowMs=*/50);
    shortLimiter.shouldProcess(ip1);
    shortLimiter.shouldProcess(ip1);
    shortLimiter.shouldProcess(ip1);
    EXPECT_FALSE(shortLimiter.shouldProcess(ip1));  // at limit

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_TRUE(shortLimiter.shouldProcess(ip1));   // window expired, count reset
}

TEST_F(BeaconRateLimiterTest, MaxIpTableEvictsToAdmitNewIp) {
    BeaconRateLimiter smallLimiter(/*maxCount=*/1, /*windowMs=*/5000, /*maxIps=*/2);
    EXPECT_TRUE(smallLimiter.shouldProcess("10.0.0.1"));
    EXPECT_TRUE(smallLimiter.shouldProcess("10.0.0.2"));

    // Previously this could be denied once the table hit capacity. ExoSend now evicts
    // an existing entry to keep availability under spoofed-IP floods.
    EXPECT_TRUE(smallLimiter.shouldProcess("10.0.0.3"));
}
