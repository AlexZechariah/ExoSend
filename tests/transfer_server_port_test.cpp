#include <gtest/gtest.h>
#include "exosend/TransferServer.h"
#include <winsock2.h>

using namespace ExoSend;

class TransferServerPortTest : public ::testing::Test {
protected:
    void SetUp() override {
        WSADATA wsaData;
        ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsaData), 0);
    }
    void TearDown() override { WSACleanup(); }
};

TEST_F(TransferServerPortTest, ReturnsZeroPortBeforeStart) {
    TransferServer server;
    EXPECT_EQ(server.getTcpPort(), 0u);
}

TEST_F(TransferServerPortTest, BindsToNonZeroPortAfterStart) {
    TransferServer server;
    ASSERT_TRUE(server.start());
    EXPECT_NE(server.getTcpPort(), 0u);
    server.stop();
}

TEST_F(TransferServerPortTest, TwoInstancesReceiveDifferentPorts) {
    TransferServer s1, s2;
    ASSERT_TRUE(s1.start());
    ASSERT_TRUE(s2.start());
    EXPECT_NE(s1.getTcpPort(), s2.getTcpPort());
    s1.stop();
    s2.stop();
}

TEST_F(TransferServerPortTest, BoundPortIsInEphemeralRange) {
    TransferServer server;
    ASSERT_TRUE(server.start());
    uint16_t port = server.getTcpPort();
    // Windows ephemeral range: 49152-65535 (IANA standard since Vista)
    EXPECT_GE(port, 49152u);
    EXPECT_LE(port, 65535u);
    server.stop();
}

TEST_F(TransferServerPortTest, PortIsZeroAfterStop) {
    TransferServer server;
    ASSERT_TRUE(server.start());
    EXPECT_NE(server.getTcpPort(), 0u);
    server.stop();
    EXPECT_EQ(server.getTcpPort(), 0u);
}

TEST_F(TransferServerPortTest, IpValidatorCallbackCompiles) {
    TransferServer server;
    server.setIpValidatorCallback([](const std::string& ip) {
        return ip == "192.168.1.100";
    });
    ASSERT_TRUE(server.start());
    // Compile-time verification that setIpValidatorCallback works.
    server.stop();
}

// Regression test: TransferServer must call WSAStartup internally.
// In v0.3, TransferServer starts BEFORE DiscoveryService (which was the
// previous Winsock initializer). Without its own WSAStartup, socket() would
// fail with WSANOTINITIALISED (10093), causing the "Initialization Error" dialog
// and preventing discovery from ever starting.
// This plain TEST (no fixture) provides no external WSAStartup.
TEST(TransferServerSelfInitTest, StartsAndInitializesWinsockItself) {
    TransferServer server;
    bool started = server.start();
    EXPECT_TRUE(started)
        << "TransferServer must call WSAStartup internally and start successfully";
    if (started) {
        EXPECT_GT(server.getTcpPort(), 0u);
        server.stop();
    }
}
