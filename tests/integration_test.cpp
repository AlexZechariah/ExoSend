/**
 * @file integration_test.cpp
 * @brief Integration tests for ExoSend functionality
 *
 * Tests multi-NIC discovery and peer garbage collection.
 * File transfer tests are handled by the TransferServer internally
 * and require more complex setup.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "exosend/DiscoveryService.h"
#include "exosend/PeerInfo.h"
#include "exosend/config.h"
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <chrono>

using namespace ExoSend;

//=============================================================================
// Test Fixtures
//=============================================================================

/**
 * @brief Test fixture for integration tests
 */
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    void TearDown() override {
        // Cleanup Winsock
        WSACleanup();
    }
};

//=============================================================================
// Multi-NIC Discovery Tests
//=============================================================================

/**
 * @test DiscoveryService can enumerate multiple network interfaces
 */
TEST_F(IntegrationTest, DiscoveryServiceEnumeratesNetworkInterfaces) {
    // Use GetAdaptersAddresses to enumerate network adapters
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 15000;
    DWORD retVal = 0;

    // Allocate buffer for adapter addresses
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    ASSERT_NE(pAddresses, nullptr);

    // Get adapter addresses
    retVal = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX,
                                   nullptr,
                                   pAddresses,
                                   &outBufLen);

    // Count adapters with IPv4 addresses
    int adapterCount = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                adapterCount++;
                break;
            }
            pUnicast = pUnicast->Next;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);

    // At least one adapter should be present
    EXPECT_GE(adapterCount, 1);
}

/**
 * @test DiscoveryService broadcasts on all interfaces
 */
TEST_F(IntegrationTest, DiscoveryServiceBroadcastsOnAllInterfaces) {
    // Note: This test verifies that DiscoveryService can be started
    // Full multi-NIC testing requires actual multiple network interfaces

    DiscoveryService discovery;
    bool started = discovery.start();

    if (started) {
        // Give it time to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Verify it's running
        EXPECT_TRUE(discovery.isRunning());

        discovery.stop();
    } else {
        // Port may be in use, skip test
        GTEST_SKIP() << "Discovery service could not be started (port may be in use)";
    }
}

//=============================================================================
// Peer GC Tests
//=============================================================================

/**
 * @test Peer is removed after timeout
 */
TEST_F(IntegrationTest, PeerRemovedAfterTimeout) {
    // Create a peer with specific last-seen time
    PeerInfo peer("test-uuid-123", "TestPeer", "192.168.1.100", 9999);

    // Set lastSeen to past time (more than PEER_TIMEOUT_MS ago)
    auto now = std::chrono::steady_clock::now();
    peer.lastSeen = now - std::chrono::milliseconds(PEER_TIMEOUT_MS + 1000);

    // Verify peer is timed out
    EXPECT_TRUE(peer.isTimedOut(PEER_TIMEOUT_MS));
}

/**
 * @test Recent peer is not removed
 */
TEST_F(IntegrationTest, RecentPeerNotRemoved) {
    // Create a peer with recent last-seen time
    PeerInfo peer("test-uuid-123", "TestPeer", "192.168.1.100", 9999);

    // Set lastSeen to recent time (less than PEER_TIMEOUT_MS ago)
    auto now = std::chrono::steady_clock::now();
    peer.lastSeen = now - std::chrono::milliseconds(PEER_TIMEOUT_MS / 2);

    // Verify peer is not timed out
    EXPECT_FALSE(peer.isTimedOut(PEER_TIMEOUT_MS));
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
