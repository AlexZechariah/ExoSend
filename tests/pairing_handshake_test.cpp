/**
 * @file pairing_handshake_test.cpp
 * @brief Integration test for PAIR_REQ/PAIR_RESP pairing handshake over TLS.
 */

#include "exosend/PairingConfirm.h"
#include "exosend/TransferHeader.h"
#include "exosend/TransferServer.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"

#include <gtest/gtest.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <array>
#include <filesystem>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace ExoSend;

namespace {

struct WsaGuard {
    int rc = -1;
    WsaGuard() {
        WSADATA wsaData{};
        rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    ~WsaGuard() {
        if (rc == 0) WSACleanup();
    }
};

static std::string makeUniqueTempDir(const std::string& prefix) {
    const auto base = std::filesystem::temp_directory_path();
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();
    const auto dir = base / (prefix + "-" + std::to_string(pid) + "-" + std::to_string(tid));
    std::filesystem::create_directories(dir);
    return dir.string();
}

static void setTestCertDirOrFail() {
    const std::string dir = makeUniqueTempDir("exosend-test-certs");
    ASSERT_EQ(_putenv_s("EXOSEND_CERT_DIR", dir.c_str()), 0);
}

static void closeSocketIfValid(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

static SOCKET connectLoopback(uint16_t port, std::string& errorMsg) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        errorMsg = "socket() failed: " + std::to_string(WSAGetLastError());
        return INVALID_SOCKET;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        errorMsg = "connect() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(s);
        return INVALID_SOCKET;
    }

    return s;
}

static std::array<uint8_t, 16> fixedSecret() {
    std::array<uint8_t, 16> s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(0x42u + i);
    return s;
}

}  // namespace

TEST(PairingHandshakeTest, PairReqRespOverTlsVerifiesBothWays) {
    WsaGuard wsa;
    ASSERT_EQ(wsa.rc, 0);

    setTestCertDirOrFail();

    const std::string serverUuid = "server-uuid-test";
    const std::string clientUuid = "client-uuid-test";

    const auto secret = fixedSecret();

    TransferServer server(0);
    server.setLocalDeviceUuid(serverUuid);

    std::atomic<bool> callbackCalled{false};
    server.setIncomingPairingCallback(
        [&callbackCalled, &secret](
            const std::string& /*clientIp*/,
            const std::string& reqClientUuid,
            const std::string& reqClientFingerprint,
            const std::string& reqServerUuid,
            const std::string& reqServerFingerprint,
            const std::array<uint8_t, 32>& exporter,
            const std::array<uint8_t, 32>& clientTag,
            std::array<uint8_t, 32>& outServerTag,
            std::string& errorMsg
        ) -> bool {
            callbackCalled.store(true);

            if (reqClientUuid.empty() || reqServerUuid.empty()) {
                errorMsg = "Missing UUID";
                return false;
            }

            std::array<uint8_t, 32> key{};
            if (!PairingConfirm::deriveConfirmKey(secret, exporter, key, errorMsg)) {
                return false;
            }

            if (!PairingConfirm::verifyTag(
                    key,
                    PairingRole::Client,
                    reqClientUuid,
                    reqClientFingerprint,
                    reqServerUuid,
                    reqServerFingerprint,
                    clientTag,
                    errorMsg)) {
                return false;
            }

            return PairingConfirm::computeTag(
                key,
                PairingRole::Server,
                reqServerUuid,
                reqServerFingerprint,
                reqClientUuid,
                reqClientFingerprint,
                outServerTag,
                errorMsg);
        }
    );

    ASSERT_TRUE(server.start());
    const uint16_t port = server.getTcpPort();
    ASSERT_NE(port, 0);

    std::string connectErr;
    SOCKET sock = connectLoopback(port, connectErr);
    ASSERT_NE(sock, INVALID_SOCKET) << connectErr;

    std::string tlsErr;
    TlsSocket tls(sock, TlsRole::CLIENT);
    ASSERT_TRUE(tls.handshake(tlsErr)) << tlsErr;
    TlsTransportStream stream(tls);

    std::array<uint8_t, 32> exporter{};
    ASSERT_TRUE(tls.getTlsExporterChannelBinding(exporter, tlsErr)) << tlsErr;

    std::string fpErr;
    const std::string clientFp = tls.getLocalFingerprint(fpErr);
    ASSERT_FALSE(clientFp.empty()) << fpErr;

    const std::string serverFp = tls.getPeerFingerprint(fpErr);
    ASSERT_FALSE(serverFp.empty()) << fpErr;

    std::array<uint8_t, 32> key{};
    ASSERT_TRUE(PairingConfirm::deriveConfirmKey(secret, exporter, key, tlsErr)) << tlsErr;

    std::array<uint8_t, 32> clientTag{};
    ASSERT_TRUE(PairingConfirm::computeTag(
                    key,
                    PairingRole::Client,
                    clientUuid,
                    clientFp,
                    serverUuid,
                    serverFp,
                    clientTag,
                    tlsErr)) << tlsErr;

    ExoHeader req(PacketType::PAIR_REQ, 0, "");
    req.setSenderUuid(clientUuid);
    req.setSha256Bytes(clientTag.data());

    std::vector<uint8_t> buf(HEADER_SIZE);
    ASSERT_TRUE(req.serializeToBuffer(buf.data()));

    std::string ioErr;
    ASSERT_TRUE(stream.sendExact(buf.data(), buf.size(), ioErr)) << ioErr;

    std::vector<uint8_t> respBuf(HEADER_SIZE);
    ASSERT_TRUE(stream.recvExact(respBuf.data(), respBuf.size(), ioErr)) << ioErr;

    ExoHeader resp;
    ASSERT_TRUE(resp.deserializeFromBuffer(respBuf.data()));
    ASSERT_TRUE(resp.isValid());
    EXPECT_EQ(resp.getPacketType(), PacketType::PAIR_RESP);
    EXPECT_EQ(resp.getSenderUuid(), serverUuid);

    const auto serverTag = resp.getSha256Bytes();
    ASSERT_TRUE(PairingConfirm::verifyTag(
                    key,
                    PairingRole::Server,
                    serverUuid,
                    serverFp,
                    clientUuid,
                    clientFp,
                    serverTag,
                    tlsErr)) << tlsErr;

    stream.shutdown();
    closeSocketIfValid(sock);

    server.stop();

    EXPECT_TRUE(callbackCalled.load());
}
