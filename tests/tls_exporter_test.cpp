/**
 * @file tls_exporter_test.cpp
 * @brief Tests for RFC 9266 tls-exporter channel binding support.
 *
 * Goal: provide a stable channel-binding primitive to build maximum-security
 * pairing confirmation on top of TLS (prevents pre-pairing MITM when combined
 * with an out-of-band secret).
 */

#include "exosend/TlsSocket.h"
#include "exosend/CertificateManager.h"

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

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace ExoSend;

namespace {

struct WsaGuard {
    int rc = -1;
    WsaGuard() {
        WSADATA wsaData{};
        rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    ~WsaGuard() {
        if (rc == 0) {
            WSACleanup();
        }
    }
};

static std::string makeUniqueTempDir() {
    const auto base = std::filesystem::temp_directory_path();
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();
    const auto dir = base / ("exosend-test-certs-" + std::to_string(pid) + "-" + std::to_string(tid));
    std::filesystem::create_directories(dir);
    return std::filesystem::canonical(dir).string();
}

static void setTestCertDirOrFail() {
    const std::string dir = makeUniqueTempDir();
    ASSERT_EQ(_putenv_s("EXOSEND_CERT_DIR", dir.c_str()), 0);
}

struct SocketPair {
    SOCKET client = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET;
};

static void closeSocketIfValid(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

static SocketPair createConnectedSocketPair(std::string& errorMsg) {
    SocketPair pair{};

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        errorMsg = "socket() failed: " + std::to_string(WSAGetLastError());
        return pair;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        errorMsg = "bind() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(listenSock);
        return pair;
    }

    if (listen(listenSock, 1) == SOCKET_ERROR) {
        errorMsg = "listen() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(listenSock);
        return pair;
    }

    sockaddr_in bound{};
    int boundLen = sizeof(bound);
    if (getsockname(listenSock, reinterpret_cast<sockaddr*>(&bound), &boundLen) == SOCKET_ERROR) {
        errorMsg = "getsockname() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(listenSock);
        return pair;
    }
    const uint16_t port = ntohs(bound.sin_port);

    std::promise<SOCKET> acceptedPromise;
    std::thread acceptThread([&]() {
        SOCKET s = accept(listenSock, nullptr, nullptr);
        acceptedPromise.set_value(s);
    });

    SOCKET clientSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSock == INVALID_SOCKET) {
        errorMsg = "client socket() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(listenSock);
        acceptThread.join();
        return pair;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddr.sin_port = htons(port);

    if (connect(clientSock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        errorMsg = "connect() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(clientSock);
        closeSocketIfValid(listenSock);
        acceptThread.join();
        return pair;
    }

    SOCKET serverSock = acceptedPromise.get_future().get();
    acceptThread.join();
    closeSocketIfValid(listenSock);

    if (serverSock == INVALID_SOCKET) {
        errorMsg = "accept() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(clientSock);
        return pair;
    }

    pair.client = clientSock;
    pair.server = serverSock;
    return pair;
}

static bool isAllZero(const std::array<uint8_t, 32>& v) {
    for (uint8_t b : v) {
        if (b != 0) return false;
    }
    return true;
}

}  // namespace

TEST(TlsProtocolHardeningTest, Tls12OnlyClientIsRejected) {
    WsaGuard wsa;
    ASSERT_EQ(wsa.rc, 0);

    setTestCertDirOrFail();
    std::string certErr;
    ASSERT_TRUE(CertificateManager::ensureCertificateExists(certErr)) << certErr;

    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    initOpenSsl();

    TlsSocket serverTls(pair.server, TlsRole::SERVER);

    std::string serverErr;
    std::promise<bool> serverHandshakeDone;
    std::thread serverThread([&]() {
        const bool ok = serverTls.handshake(serverErr);
        serverHandshakeDone.set_value(ok);
    });

    SSL_CTX* clientCtx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(clientCtx, nullptr);

    ASSERT_EQ(SSL_CTX_set_min_proto_version(clientCtx, TLS1_2_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(clientCtx, TLS1_2_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_cipher_list(clientCtx, TLS_CIPHER_SUITE), 1);

    // For this hardening test we care about protocol negotiation only.
    // Disable certificate verification to avoid unrelated failure modes.
    SSL_CTX_set_verify(clientCtx, SSL_VERIFY_NONE, nullptr);

    const std::string certPath = CertificateManager::getCertFilePath();
    const std::string keyPath = CertificateManager::getKeyFilePath();
    ASSERT_TRUE(CertificateManager::loadCertificate(clientCtx, certPath, keyPath, certErr)) << certErr;

    SSL* clientSsl = SSL_new(clientCtx);
    ASSERT_NE(clientSsl, nullptr);

    ASSERT_EQ(SSL_set_fd(clientSsl, static_cast<int>(pair.client)), 1);

    const int clientRc = SSL_connect(clientSsl);
    const bool clientOk = (clientRc == 1);

    SSL_free(clientSsl);
    SSL_CTX_free(clientCtx);

    const bool serverOk = serverHandshakeDone.get_future().get();
    serverThread.join();

    EXPECT_FALSE(clientOk);
    EXPECT_FALSE(serverOk) << serverErr;

    serverTls.shutdown();

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}

TEST(TlsExporterTest, ChannelBindingMatchesBothSides) {
    WsaGuard wsa;
    ASSERT_EQ(wsa.rc, 0);

    setTestCertDirOrFail();
    std::string certErr;
    ASSERT_TRUE(CertificateManager::ensureCertificateExists(certErr)) << certErr;

    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    initOpenSsl();

    TlsSocket serverTls(pair.server, TlsRole::SERVER);
    TlsSocket clientTls(pair.client, TlsRole::CLIENT);

    std::string serverErr;
    std::promise<bool> serverHandshakeDone;
    std::thread serverThread([&]() {
        const bool ok = serverTls.handshake(serverErr);
        serverHandshakeDone.set_value(ok);
    });

    std::string clientErr;
    const bool clientOk = clientTls.handshake(clientErr);
    const bool serverOk = serverHandshakeDone.get_future().get();
    serverThread.join();

    ASSERT_TRUE(clientOk) << clientErr;
    ASSERT_TRUE(serverOk) << serverErr;

    std::array<uint8_t, 32> clientCb{};
    std::array<uint8_t, 32> serverCb{};
    std::string cbErr;

    ASSERT_TRUE(clientTls.getTlsExporterChannelBinding(clientCb, cbErr)) << cbErr;
    ASSERT_TRUE(serverTls.getTlsExporterChannelBinding(serverCb, cbErr)) << cbErr;

    EXPECT_FALSE(isAllZero(clientCb));
    EXPECT_EQ(clientCb, serverCb);

    clientTls.shutdown();
    serverTls.shutdown();

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}

TEST(TlsFingerprintTest, LocalFingerprintMatchesPeerObservedByOtherSide) {
    WsaGuard wsa;
    ASSERT_EQ(wsa.rc, 0);

    setTestCertDirOrFail();
    std::string certErr;
    ASSERT_TRUE(CertificateManager::ensureCertificateExists(certErr)) << certErr;

    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    initOpenSsl();

    TlsSocket serverTls(pair.server, TlsRole::SERVER);
    TlsSocket clientTls(pair.client, TlsRole::CLIENT);

    std::string serverErr;
    std::promise<bool> serverHandshakeDone;
    std::thread serverThread([&]() {
        const bool ok = serverTls.handshake(serverErr);
        serverHandshakeDone.set_value(ok);
    });

    std::string clientErr;
    const bool clientOk = clientTls.handshake(clientErr);
    const bool serverOk = serverHandshakeDone.get_future().get();
    serverThread.join();

    ASSERT_TRUE(clientOk) << clientErr;
    ASSERT_TRUE(serverOk) << serverErr;

    std::string fpErr;
    const std::string clientLocal = clientTls.getLocalFingerprint(fpErr);
    ASSERT_FALSE(clientLocal.empty()) << fpErr;

    const std::string serverPeer = serverTls.getPeerFingerprint(fpErr);
    ASSERT_FALSE(serverPeer.empty()) << fpErr;

    EXPECT_EQ(clientLocal, serverPeer);

    clientTls.shutdown();
    serverTls.shutdown();

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}
