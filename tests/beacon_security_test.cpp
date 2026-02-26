#include <gtest/gtest.h>
#include "exosend/DiscoveryService.h"
#include "exosend/config.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <string>

using namespace ExoSend;

static int64_t nowMs() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

static std::string makeGoodbyeBeacon(const std::string& uuid) {
    nlohmann::json j;
    j["protocol_id"]    = "EXOSEND_V1";
    j["beacon_type"]    = "goodbye";
    j["device_uuid"]    = uuid;
    j["display_name"]   = "TestPeer";
    j["tcp_port"]       = 40001;
    j["discovery_port"] = DISCOVERY_POOL_PORTS[0];
    j["timestamp_ms"]   = nowMs();
    j["proto_version"]  = 3;
    return j.dump();
}

static std::string makeAnnounceBeacon(const std::string& uuid,
                                      const std::string& name,
                                      uint16_t tcpPort,
                                      int64_t tsOverride = -1) {
    nlohmann::json j;
    j["protocol_id"]    = "EXOSEND_V1";
    j["beacon_type"]    = "announce";
    j["device_uuid"]    = uuid;
    j["display_name"]   = name;
    j["os_platform"]    = "Windows 10";
    j["tcp_port"]       = tcpPort;
    j["discovery_port"] = DISCOVERY_POOL_PORTS[0];
    j["timestamp_ms"]   = (tsOverride >= 0) ? tsOverride : nowMs();
    j["proto_version"]  = 3;
    return j.dump();
}

class BeaconSecurityTest : public ::testing::Test {
protected:
    DiscoveryService svc;
    void SetUp() override { svc.setDeviceUuid("test-self-uuid"); }
};

// --- Goodbye beacon IP validation ---

TEST_F(BeaconSecurityTest, GoodbyeFromMatchingIpRemovesPeer) {
    svc.injectPeerForTesting("peer-a", "PeerA", "192.168.1.50", 40001);
    ASSERT_TRUE(svc.hasPeer("peer-a"));
    svc.simulateIncomingBeacon(makeGoodbyeBeacon("peer-a"), "192.168.1.50");
    EXPECT_FALSE(svc.hasPeer("peer-a"));
}

TEST_F(BeaconSecurityTest, GoodbyeFromWrongIpIsIgnored) {
    svc.injectPeerForTesting("peer-b", "PeerB", "192.168.1.50", 40002);
    ASSERT_TRUE(svc.hasPeer("peer-b"));
    svc.simulateIncomingBeacon(makeGoodbyeBeacon("peer-b"), "192.168.1.99");
    EXPECT_TRUE(svc.hasPeer("peer-b"));  // must NOT be removed
}

TEST_F(BeaconSecurityTest, GoodbyeForUnknownUuidIsIgnored) {
    EXPECT_NO_FATAL_FAILURE(
        svc.simulateIncomingBeacon(makeGoodbyeBeacon("no-such-uuid"), "192.168.1.50")
    );
}

// --- Beacon rate limiting ---

TEST_F(BeaconSecurityTest, AnnouncesUnderRateLimitAreProcessed) {
    svc.simulateIncomingBeacon(
        makeAnnounceBeacon("peer-c", "PeerC", 40003), "192.168.1.60");
    EXPECT_TRUE(svc.hasPeer("peer-c"));
}

TEST_F(BeaconSecurityTest, FloodFromSingleIpDoesNotCrash) {
    std::string beacon = makeAnnounceBeacon("peer-flood", "Flood", 40004);
    for (size_t i = 0; i < BEACON_RATE_LIMIT_MAX_COUNT * 3; ++i) {
        EXPECT_NO_FATAL_FAILURE(
            svc.simulateIncomingBeacon(beacon, "192.168.1.200")
        );
    }
    // First batch processed, rest dropped -- no crash, at most 1 peer entry.
    EXPECT_LE(svc.getPeers().size(), 1u);
}

// --- Timestamp anti-replay (optional field -- backward compat) ---

TEST_F(BeaconSecurityTest, FreshTimestampIsAccepted) {
    svc.simulateIncomingBeacon(
        makeAnnounceBeacon("peer-fresh", "Fresh", 40005, nowMs()), "192.168.1.70");
    EXPECT_TRUE(svc.hasPeer("peer-fresh"));
}

TEST_F(BeaconSecurityTest, StaleTimestampIsRejected) {
    // 70 seconds in the past > BEACON_TIMESTAMP_MAX_AGE_MS (60s)
    int64_t stale = nowMs() - (BEACON_TIMESTAMP_MAX_AGE_MS + 10000);
    svc.simulateIncomingBeacon(
        makeAnnounceBeacon("peer-stale", "Stale", 40006, stale), "192.168.1.71");
    EXPECT_FALSE(svc.hasPeer("peer-stale"));
}

TEST_F(BeaconSecurityTest, FutureTimestampIsRejected) {
    int64_t future = nowMs() + (BEACON_TIMESTAMP_MAX_AGE_MS + 10000);
    svc.simulateIncomingBeacon(
        makeAnnounceBeacon("peer-future", "Future", 40007, future), "192.168.1.72");
    EXPECT_FALSE(svc.hasPeer("peer-future"));
}

TEST_F(BeaconSecurityTest, MissingTimestampIsAccepted_BackwardCompat) {
    // v0.2 beacon has no timestamp_ms -- must be accepted for backward compat.
    nlohmann::json j;
    j["protocol_id"]  = "EXOSEND_V1";
    j["beacon_type"]  = "announce";
    j["device_uuid"]  = "peer-v2";
    j["display_name"] = "OldPeer";
    j["os_platform"]  = "Windows 10";
    j["tcp_port"]     = 40008;
    // No timestamp_ms intentionally -- simulates a v0.2 peer.
    svc.simulateIncomingBeacon(j.dump(), "192.168.1.80");
    EXPECT_TRUE(svc.hasPeer("peer-v2"));
}
