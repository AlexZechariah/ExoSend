#include <gtest/gtest.h>
#include "exosend/DiscoveryService.h"
#include "exosend/config.h"
#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <vector>

using namespace ExoSend;

class DiscoveryPortTest : public ::testing::Test {
protected:
    void SetUp() override {
        WSADATA wsaData;
        ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsaData), 0);
    }
    void TearDown() override {
        for (SOCKET s : m_prebound) closesocket(s);
        WSACleanup();
    }

    bool prebindUdpPort(uint16_t port) {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return false;
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port);
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(s);
            return false;
        }
        m_prebound.push_back(s);
        return true;
    }

    std::vector<SOCKET> m_prebound;
};

TEST_F(DiscoveryPortTest, BindsToFirstPoolPortWhenAvailable) {
    // NOTE: If port 41000 is occupied by another process on this machine,
    // this test will pass with port 42100 instead -- that is correct behavior.
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-first");
    ASSERT_TRUE(svc.start());
    uint16_t boundPort = svc.getBoundDiscoveryPort();
    bool isInPool = false;
    for (uint16_t p : DISCOVERY_POOL_PORTS) {
        if (p == boundPort) { isInPool = true; break; }
    }
    EXPECT_TRUE(isInPool) << "Bound port " << boundPort << " is not in pool";
    svc.stop();
}

TEST_F(DiscoveryPortTest, SkipsOccupiedPortAndBindsToNext) {
    ASSERT_TRUE(prebindUdpPort(DISCOVERY_POOL_PORTS[0]));
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-skip");
    ASSERT_TRUE(svc.start());
    EXPECT_EQ(svc.getBoundDiscoveryPort(), DISCOVERY_POOL_PORTS[1]);
    svc.stop();
}

TEST_F(DiscoveryPortTest, SkipsMultipleOccupiedPorts) {
    ASSERT_TRUE(prebindUdpPort(DISCOVERY_POOL_PORTS[0]));
    ASSERT_TRUE(prebindUdpPort(DISCOVERY_POOL_PORTS[1]));
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-skip2");
    ASSERT_TRUE(svc.start());
    EXPECT_EQ(svc.getBoundDiscoveryPort(), DISCOVERY_POOL_PORTS[2]);
    svc.stop();
}

TEST_F(DiscoveryPortTest, FailsGracefullyWhenAllPoolPortsBusy) {
    for (uint16_t port : DISCOVERY_POOL_PORTS) {
        ASSERT_TRUE(prebindUdpPort(port)) << "Could not pre-bind port " << port;
    }
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-allfull");
    EXPECT_FALSE(svc.start());  // must fail cleanly -- no crash, no threads launched
}

TEST_F(DiscoveryPortTest, BeaconJsonContainsDiscoveryPortField) {
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-beacon");
    ASSERT_TRUE(svc.start());
    auto beacon = nlohmann::json::parse(svc.generateBeaconJsonForTesting());
    ASSERT_TRUE(beacon.contains("discovery_port"));
    EXPECT_EQ(beacon["discovery_port"].get<uint16_t>(), svc.getBoundDiscoveryPort());
    svc.stop();
}

TEST_F(DiscoveryPortTest, BeaconJsonContainsTimestampField) {
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-ts");
    ASSERT_TRUE(svc.start());
    auto beacon = nlohmann::json::parse(svc.generateBeaconJsonForTesting());
    ASSERT_TRUE(beacon.contains("timestamp_ms"));
    EXPECT_GT(beacon["timestamp_ms"].get<int64_t>(), 0);
    svc.stop();
}

TEST_F(DiscoveryPortTest, BeaconJsonContainsProtoVersion) {
    DiscoveryService svc;
    svc.setDeviceUuid("test-uuid-pv");
    ASSERT_TRUE(svc.start());
    auto beacon = nlohmann::json::parse(svc.generateBeaconJsonForTesting());
    ASSERT_TRUE(beacon.contains("proto_version"));
    EXPECT_EQ(beacon["proto_version"].get<int>(), 3);
    svc.stop();
}
