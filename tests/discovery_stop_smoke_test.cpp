// Smoke test for DiscoveryService::stop() reliability.
//
// Motivation: On some Windows systems, adapter enumeration (GetAdaptersAddresses)
// can stall during shutdown/network transitions. ExoSend must be able to stop
// DiscoveryService promptly (e.g., during Settings → Factory Reset… restart).

#include "exosend/DiscoveryService.h"

#include <gtest/gtest.h>

#include <chrono>

TEST(DiscoveryStopSmokeTest, StopCompletesQuicklyWhenStarted)
{
    ExoSend::DiscoveryService discovery;

    if (!discovery.start()) {
        GTEST_SKIP() << "DiscoveryService could not start (ports unavailable or Winsock init failed).";
    }

    const auto t0 = std::chrono::steady_clock::now();
    discovery.stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    // This should normally be well under a second. Use a generous limit to avoid
    // false failures on slow machines while still catching shutdown stalls.
    EXPECT_LT(ms, 5000) << "DiscoveryService::stop() took too long (" << ms << "ms).";
}

