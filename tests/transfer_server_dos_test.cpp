/**
 * @file transfer_server_dos_test.cpp
 * @brief DoS hardening tests for TransferServer (connection thread cap).
 */

#include "exosend/TransferServer.h"
#include <gtest/gtest.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
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

static SOCKET connectLoopback(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

static void closeSocketIfValid(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

}  // namespace

TEST(TransferServerDoSTest, CapsActiveClientThreads) {
    WsaGuard wsa;
    ASSERT_EQ(wsa.rc, 0);

    TransferServer server(0);
    ASSERT_TRUE(server.start());
    const uint16_t port = server.getTcpPort();
    ASSERT_NE(port, 0);

    std::vector<SOCKET> sockets;
    sockets.reserve(64);

    for (int i = 0; i < 64; ++i) {
        SOCKET s = connectLoopback(port);
        if (s != INVALID_SOCKET) {
            sockets.push_back(s);
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const size_t active = server.getActiveClientThreadCount();
    EXPECT_LE(active, MAX_CONCURRENT_INCOMING_CLIENT_THREADS);

    for (SOCKET& s : sockets) {
        closeSocketIfValid(s);
    }

    server.stop();
}

