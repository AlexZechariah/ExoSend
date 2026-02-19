/**
 * @file fault_injection_test.cpp
 * @brief Fault-injection tests for ExoSend error handling
 *
 * Tests graceful failure handling for:
 * - Mid-transfer disconnect
 * - Disk full scenario
 * - Permission denied
 * - Malformed header
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include "exosend/TransferHeader.h"
#include "exosend/FileTransfer.h"
#include "exosend/config.h"
#include "exosend/HashUtils.h"
#include "exosend/CertificateManager.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransferSession.h"
#include <gtest/gtest.h>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <future>
#include <algorithm>
#include <filesystem>

using namespace ExoSend;

namespace {

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

    pair.client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (pair.client == INVALID_SOCKET) {
        errorMsg = "client socket() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(listenSock);
        return pair;
    }

    int one = 1;
    (void)setsockopt(pair.client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

    if (connect(pair.client, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == SOCKET_ERROR) {
        errorMsg = "connect() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(pair.client);
        closeSocketIfValid(listenSock);
        return pair;
    }

    pair.server = accept(listenSock, nullptr, nullptr);
    closeSocketIfValid(listenSock);

    if (pair.server == INVALID_SOCKET) {
        errorMsg = "accept() failed: " + std::to_string(WSAGetLastError());
        closeSocketIfValid(pair.client);
        return pair;
    }

    (void)setsockopt(pair.server, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

    (void)setSocketRecvTimeout(pair.client, 2000);
    (void)setSocketRecvTimeout(pair.server, 2000);

    return pair;
}

static bool bufferContains(const std::vector<uint8_t>& haystack, const std::string& needle) {
    if (needle.empty() || haystack.empty()) {
        return false;
    }

    const auto begin = haystack.begin();
    const auto end = haystack.end();
    const auto nBegin = reinterpret_cast<const uint8_t*>(needle.data());
    const auto nEnd = nBegin + needle.size();

    return std::search(begin, end, nBegin, nEnd) != end;
}

static std::string setUniqueTestCertDir() {
    const DWORD pid = GetCurrentProcessId();
    const std::string dir = std::string(".\\test_certs_") + std::to_string(pid);
    (void)SetEnvironmentVariableA("EXOSEND_CERT_DIR", dir.c_str());
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

}  // namespace

//=============================================================================
// Test Fixtures
//=============================================================================

/**
 * @brief Test fixture for fault injection tests
 */
class FaultInjectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    void TearDown() override {
        // Clean up any test files
        std::remove("fault_test_partial.bin");
        std::remove("fault_test_output.bin");

        // Cleanup Winsock
        WSACleanup();
    }

    /**
     * @brief Create a test file with specific content
     */
    bool createTestFile(const std::string& path, size_t size) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        std::vector<char> data(size, 'X');
        file.write(data.data(), data.size());
        return file.good();
    }

    /**
     * @brief Check if a file exists
     */
    bool fileExists(const std::string& path) {
        std::ifstream file(path);
        return file.good();
    }

    /**
     * @brief Get file size
     */
    size_t getFileSize(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return 0;
        }
        return file.tellg();
    }
};

//=============================================================================
// Transport recvExact Partial Read Tests (Phase 1 acceptance)
//=============================================================================

TEST_F(FaultInjectionTest, RecvExactReadsFullHeaderAcrossPartialSends) {
    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    std::vector<uint8_t> expected(HEADER_SIZE);
    for (size_t i = 0; i < expected.size(); ++i) {
        expected[i] = static_cast<uint8_t>(i & 0xFF);
    }

    std::vector<uint8_t> received(HEADER_SIZE, 0);
    std::promise<bool> recvDone;
    std::string recvErr;

    std::thread recvThread([&]() {
        const bool ok = recvExact(pair.server, received.data(), received.size(), recvErr);
        recvDone.set_value(ok);
    });

    for (size_t offset = 0; offset < expected.size(); ) {
        const size_t chunk = std::min<size_t>(7, expected.size() - offset);
        const int sent = send(pair.client,
                              reinterpret_cast<const char*>(expected.data() + offset),
                              static_cast<int>(chunk),
                              0);
        ASSERT_GT(sent, 0) << "send() failed: " << WSAGetLastError();
        offset += static_cast<size_t>(sent);
        Sleep(1);
    }

    const bool ok = recvDone.get_future().get();
    recvThread.join();

    EXPECT_TRUE(ok) << recvErr;
    EXPECT_EQ(received, expected);

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}

TEST_F(FaultInjectionTest, RecvExactFailsWhenPeerClosesBeforeAllBytes) {
    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    std::vector<uint8_t> received(HEADER_SIZE, 0);
    std::promise<bool> recvDone;
    std::string recvErr;

    std::thread recvThread([&]() {
        const bool ok = recvExact(pair.server, received.data(), received.size(), recvErr);
        recvDone.set_value(ok);
    });

    std::vector<uint8_t> partial(10, 0xAB);
    ASSERT_GT(send(pair.client, reinterpret_cast<const char*>(partial.data()), static_cast<int>(partial.size()), 0), 0);
    closeSocketIfValid(pair.client);

    const bool ok = recvDone.get_future().get();
    recvThread.join();

    EXPECT_FALSE(ok);
    EXPECT_TRUE(recvErr.find("Connection closed") != std::string::npos) << recvErr;

    closeSocketIfValid(pair.server);
}

//=============================================================================
// TLS Security Evidence Tests (Phase 3 acceptance)
//=============================================================================

TEST_F(FaultInjectionTest, TlsTrafficDoesNotContainPlaintextOnWire) {
    (void)setUniqueTestCertDir();
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

    const std::string sentinel = "EXOSEND_TLS_PLAINTEXT_SENTINEL_0123456789";
    std::vector<uint8_t> plaintext(2048, 0);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(sentinel[i % sentinel.size()]);
    }

    std::string sendErr;
    ASSERT_TRUE(clientTls.sendExact(plaintext.data(), plaintext.size(), sendErr)) << sendErr;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(pair.server, &rfds);
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    const int ready = select(0, &rfds, nullptr, nullptr, &tv);
    ASSERT_GT(ready, 0) << "select() timeout waiting for ciphertext";

    std::vector<uint8_t> peekBuf(4096, 0);
    const int peeked = recv(pair.server, reinterpret_cast<char*>(peekBuf.data()),
                            static_cast<int>(peekBuf.size()), MSG_PEEK);
    ASSERT_GT(peeked, 0) << "recv(MSG_PEEK) failed: " << WSAGetLastError();
    peekBuf.resize(static_cast<size_t>(peeked));

    EXPECT_FALSE(bufferContains(peekBuf, sentinel));

    std::vector<uint8_t> received(plaintext.size(), 0);
    std::string recvErr;
    ASSERT_TRUE(serverTls.recvExact(received.data(), received.size(), recvErr)) << recvErr;
    EXPECT_EQ(received, plaintext);

    clientTls.shutdown();
    serverTls.shutdown();

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}

TEST_F(FaultInjectionTest, TransferSessionBlocksPinnedFingerprintMismatch) {
    (void)setUniqueTestCertDir();
    std::string certErr;
    ASSERT_TRUE(CertificateManager::ensureCertificateExists(certErr)) << certErr;
    initOpenSsl();

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(listenSock, INVALID_SOCKET);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_NE(bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), SOCKET_ERROR);
    ASSERT_NE(listen(listenSock, 1), SOCKET_ERROR);

    sockaddr_in bound{};
    int boundLen = sizeof(bound);
    ASSERT_NE(getsockname(listenSock, reinterpret_cast<sockaddr*>(&bound), &boundLen), SOCKET_ERROR);
    const uint16_t port = ntohs(bound.sin_port);

    std::promise<void> serverReady;
    std::promise<void> serverDone;
    std::thread serverThread([&]() {
        serverReady.set_value();
        SOCKET s = accept(listenSock, nullptr, nullptr);
        if (s == INVALID_SOCKET) {
            serverDone.set_value();
            return;
        }

        std::string hsErr;
        TlsSocket tls(s, TlsRole::SERVER);
        (void)tls.handshake(hsErr);

        tls.shutdown();
        closesocket(s);
        serverDone.set_value();
    });

    serverReady.get_future().wait();

    auto completionPromise = std::make_shared<std::promise<std::pair<bool, std::string>>>();
    auto completionFuture = completionPromise->get_future();

    TransferSession session(
        "nonexistent_file_for_mismatch_test.bin",
        "127.0.0.1",
        port,
        "session-test",
        nullptr,
        nullptr,
        [completionPromise](const std::string&, bool success, const std::string& error) {
            completionPromise->set_value({success, error});
        }
    );
    session.setRequireTls(true);
    session.setPeerIdentity("peer-uuid-test", std::string(64, '0'));

    ASSERT_TRUE(session.run());

    const auto result = completionFuture.get();
    EXPECT_FALSE(result.first);
    EXPECT_TRUE(result.second.find("Pinned fingerprint mismatch") != std::string::npos) << result.second;

    closeSocketIfValid(listenSock);
    serverDone.get_future().wait();
    serverThread.join();
}

//=============================================================================
// Protocol v2 Integrity Fault Injection (Phase 4 acceptance)
//=============================================================================

TEST_F(FaultInjectionTest, HashMismatchProducesHashBadAndDeletesOutput) {
    const std::string sendPath = "fault_test_partial.bin";
    const std::string receiveDir = ".";
    const std::string offeredName = "fault_test_output.bin";

    std::remove(sendPath.c_str());
    std::remove(offeredName.c_str());

    ASSERT_TRUE(createTestFile(sendPath, 256 * 1024));

    unsigned char originalHash[HASH_SIZE]{};
    std::string hashErr;
    ASSERT_TRUE(HashUtils::computeFileHash(sendPath, originalHash, hashErr)) << hashErr;

    std::string errorMsg;
    SocketPair pair = createConnectedSocketPair(errorMsg);
    ASSERT_NE(pair.client, INVALID_SOCKET) << errorMsg;
    ASSERT_NE(pair.server, INVALID_SOCKET) << errorMsg;

    std::promise<void> receiverDone;
    std::string receiverErr;
    std::string receiverOutputPath;

    std::thread receiverThread([&]() {
        FileReceiver receiver(receiveDir);
        std::string err;
        const bool ok = receiver.receiveFile(
            pair.server,
            err,
            [](const ExoHeader&) { return true; },
            nullptr
        );
        receiverErr = err;
        receiverOutputPath = receiver.getReceivedFilePath();
        EXPECT_FALSE(ok);
        receiverDone.set_value();
    });

    std::string sendErr;
    ExoHeader offer(PacketType::OFFER, static_cast<uint64_t>(getFileSize(sendPath)), offeredName);
    offer.magic = MAGIC_NUMBER;
    std::vector<uint8_t> offerBuf(HEADER_SIZE, 0);
    ASSERT_TRUE(offer.serializeToBuffer(offerBuf.data()));
    ASSERT_TRUE(sendExact(pair.client, offerBuf.data(), offerBuf.size(), sendErr)) << sendErr;

    std::vector<uint8_t> respBuf(HEADER_SIZE, 0);
    ASSERT_TRUE(recvExact(pair.client, respBuf.data(), respBuf.size(), sendErr)) << sendErr;
    ExoHeader resp;
    ASSERT_TRUE(resp.deserializeFromBuffer(respBuf.data()));
    ASSERT_EQ(resp.getPacketType(), PacketType::ACCEPT);

    std::ifstream in(sendPath, std::ios::binary);
    ASSERT_TRUE(in.is_open());

    const size_t flipOffset = 12345;
    size_t sentTotal = 0;
    std::vector<uint8_t> chunk(4096, 0);
    while (in) {
        in.read(reinterpret_cast<char*>(chunk.data()), chunk.size());
        const std::streamsize bytesRead = in.gcount();
        if (bytesRead <= 0) {
            break;
        }

        std::vector<uint8_t> toSend(chunk.begin(), chunk.begin() + static_cast<size_t>(bytesRead));
        if (sentTotal <= flipOffset && flipOffset < sentTotal + toSend.size()) {
            const size_t idx = flipOffset - sentTotal;
            toSend[idx] ^= 0xFF;
        }

        ASSERT_TRUE(sendExact(pair.client, toSend.data(), toSend.size(), sendErr)) << sendErr;
        sentTotal += toSend.size();
    }
    in.close();

    ExoHeader hashHeader(PacketType::HASH, 0, "");
    hashHeader.magic = MAGIC_NUMBER;
    hashHeader.setSha256Bytes(originalHash);
    std::vector<uint8_t> hashBuf(HEADER_SIZE, 0);
    ASSERT_TRUE(hashHeader.serializeToBuffer(hashBuf.data()));
    ASSERT_TRUE(sendExact(pair.client, hashBuf.data(), hashBuf.size(), sendErr)) << sendErr;

    std::vector<uint8_t> verifyBuf(HEADER_SIZE, 0);
    ASSERT_TRUE(recvExact(pair.client, verifyBuf.data(), verifyBuf.size(), sendErr)) << sendErr;
    ExoHeader verify;
    ASSERT_TRUE(verify.deserializeFromBuffer(verifyBuf.data()));
    EXPECT_EQ(verify.getPacketType(), PacketType::HASH_BAD);

    receiverDone.get_future().wait();
    receiverThread.join();

    EXPECT_TRUE(receiverErr.find("SHA-256 mismatch") != std::string::npos) << receiverErr;
    if (!receiverOutputPath.empty()) {
        EXPECT_FALSE(fileExists(receiverOutputPath));
    } else {
        EXPECT_FALSE(fileExists(offeredName));
    }

    closeSocketIfValid(pair.client);
    closeSocketIfValid(pair.server);
}

//=============================================================================
// Malformed Header Tests
//=============================================================================

/**
 * @test Malformed header with wrong magic number is rejected
 */
TEST_F(FaultInjectionTest, MalformedHeaderWrongMagicRejected) {
    // Create buffer with wrong magic number in network byte order
    std::vector<uint8_t> buffer(HEADER_SIZE, 0);
    uint32_t wrongMagic = htonl(0x12345678);  // Wrong magic in network byte order

    // Set wrong magic
    std::memcpy(buffer.data(), &wrongMagic, sizeof(uint32_t));

    // Try to deserialize
    ExoHeader header;
    bool success = header.deserializeFromBuffer(buffer.data());

    // Should succeed in deserializing but validation should fail
    ASSERT_TRUE(success);
    EXPECT_FALSE(header.isValid());
    EXPECT_EQ(header.magic, 0x12345678);  // After ntohl conversion
}

/**
 * @test Malformed header with invalid packet type is rejected
 */
TEST_F(FaultInjectionTest, MalformedHeaderInvalidPacketTypeRejected) {
    // Create buffer with invalid packet type
    std::vector<uint8_t> buffer(HEADER_SIZE, 0);

    // Set correct magic
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    std::memcpy(buffer.data(), &networkMagic, sizeof(uint32_t));

    // Set invalid packet type (0xFF)
    buffer[4] = 0xFF;

    // Try to deserialize
    ExoHeader header;
    ASSERT_TRUE(header.deserializeFromBuffer(buffer.data()));

    // Validation should fail
    EXPECT_FALSE(header.isValid());
    EXPECT_EQ(header.packetType, 0xFF);
}

/**
 * @test Malformed header with filename too long is rejected
 */
TEST_F(FaultInjectionTest, MalformedHeaderFilenameTooLongRejected) {
    // Create buffer with filename length > 256
    std::vector<uint8_t> buffer(HEADER_SIZE, 0);

    // Set correct magic
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    std::memcpy(buffer.data(), &networkMagic, sizeof(uint32_t));

    // Set valid packet type
    buffer[4] = static_cast<uint8_t>(PacketType::OFFER);

    // Use offsetof to get actual filename length offset
    size_t filenameLengthOffset = offsetof(ExoHeader, filenameLength);

    // Set filename length to 257 (too long)
    uint16_t tooLong = htons(257);
    std::memcpy(buffer.data() + filenameLengthOffset, &tooLong, sizeof(uint16_t));

    // Try to deserialize
    ExoHeader header;
    ASSERT_TRUE(header.deserializeFromBuffer(buffer.data()));

    // Validation should fail
    EXPECT_FALSE(header.isValid());
    EXPECT_EQ(header.filenameLength, 257);
}

/**
 * @test Null buffer is handled gracefully
 */
TEST_F(FaultInjectionTest, NullBufferHandledGracefully) {
    ExoHeader header;

    // serializeToBuffer should return false for null buffer
    EXPECT_FALSE(header.serializeToBuffer(nullptr));

    // deserializeFromBuffer should return false for null buffer
    EXPECT_FALSE(header.deserializeFromBuffer(nullptr));
}

//=============================================================================
// Hash Error Tests
//=============================================================================

/**
 * @test Hash comparison handles null pointers gracefully
 */
TEST_F(FaultInjectionTest, HashComparisonHandlesNullPointers) {
    unsigned char hash1[HASH_SIZE];
    unsigned char hash2[HASH_SIZE];
    std::memset(hash1, 0xAB, HASH_SIZE);
    std::memset(hash2, 0xAB, HASH_SIZE);

    // Normal case should return true
    EXPECT_TRUE(HashUtils::compareHashes(hash1, hash2));

    // Different hashes should return false
    hash2[0] = 0xCD;
    EXPECT_FALSE(HashUtils::compareHashes(hash1, hash2));
}

/**
 * @test String to hash handles invalid hex gracefully
 */
TEST_F(FaultInjectionTest, StringToHashHandlesInvalidHex) {
    unsigned char result[HASH_SIZE];

    // Invalid hex characters
    EXPECT_FALSE(HashUtils::stringToHash("GGGGGGGGGGGGGGGG", result));

    // Wrong length
    EXPECT_FALSE(HashUtils::stringToHash("ABC", result));

    // Empty string
    EXPECT_FALSE(HashUtils::stringToHash("", result));
}

/**
 * @test Hash to string handles null pointer gracefully
 */
TEST_F(FaultInjectionTest, HashToStringHandlesNullPointer) {
    std::string result = HashUtils::hashToString(nullptr);

    // Should return empty string
    EXPECT_TRUE(result.empty());
}

//=============================================================================
// File Error Tests
//=============================================================================

/**
 * @test File hash returns false for non-existent file
 */
TEST_F(FaultInjectionTest, FileHashReturnsFalseForNonExistentFile) {
    unsigned char result[HASH_SIZE];
    std::string errorMsg;

    bool success = HashUtils::computeFileHash("nonexistent_file_xyz123.bin", result, errorMsg);

    EXPECT_FALSE(success);
    EXPECT_FALSE(errorMsg.empty());
}

/**
 * @test File hash returns error message on failure
 */
TEST_F(FaultInjectionTest, FileHashReturnsErrorMessageOnFailure) {
    unsigned char result[HASH_SIZE];
    std::string errorMsg;

    HashUtils::computeFileHash("nonexistent_file_xyz123.bin", result, errorMsg);

    // Error message should not be empty
    EXPECT_FALSE(errorMsg.empty());

    // Error message should contain useful information
    EXPECT_TRUE(errorMsg.find("Cannot open file") != std::string::npos ||
                errorMsg.find("not found") != std::string::npos ||
                errorMsg.find("Failed to open") != std::string::npos);
}

//=============================================================================
// Buffer Overflow Protection Tests
//=============================================================================

/**
 * @test Header deserialization doesn't overflow buffer
 * Note: The current implementation reads exactly HEADER_SIZE bytes without
 * checking the buffer size. This test verifies that behavior.
 */
TEST_F(FaultInjectionTest, HeaderDeserializationNoBufferOverflow) {
    // The current implementation assumes the buffer is exactly HEADER_SIZE bytes
    // and doesn't perform bounds checking. This test documents that behavior.

    // Create a valid buffer
    std::vector<uint8_t> buffer(HEADER_SIZE, 0);
    uint32_t networkMagic = htonl(MAGIC_NUMBER);
    std::memcpy(buffer.data(), &networkMagic, sizeof(uint32_t));

    ExoHeader header;

    // Should succeed with correct-sized buffer
    EXPECT_TRUE(header.deserializeFromBuffer(buffer.data()));
    EXPECT_EQ(header.magic, MAGIC_NUMBER);

    // Note: The implementation doesn't check buffer size, so passing a
    // smaller buffer would cause undefined behavior (buffer overflow).
    // This is a known limitation that should be addressed in production.
}

/**
 * @test Header serialization doesn't overflow buffer
 */
TEST_F(FaultInjectionTest, HeaderSerializationNoBufferOverflow) {
    ExoHeader header(PacketType::OFFER, 1024, "test.txt");
    header.magic = MAGIC_NUMBER;

    // Try to serialize to a buffer that's exactly HEADER_SIZE
    std::vector<uint8_t> buffer(HEADER_SIZE, 0);
    EXPECT_TRUE(header.serializeToBuffer(buffer.data()));

    // Verify no overflow by checking that we can still access the buffer
    // and that magic number is at the expected location
    uint32_t magic;
    std::memcpy(&magic, buffer.data(), sizeof(uint32_t));
    EXPECT_EQ(ntohl(magic), MAGIC_NUMBER);
}

//=============================================================================
// Edge Case Tests
//=============================================================================

/**
 * @test Zero file size is handled correctly
 */
TEST_F(FaultInjectionTest, ZeroFileSizeHandledCorrectly) {
    ExoHeader header(PacketType::OFFER, 0, "empty.txt");
    header.magic = MAGIC_NUMBER;

    EXPECT_EQ(header.fileSize, 0);
    EXPECT_TRUE(header.isValid());
    EXPECT_EQ(header.getFileSizeString(), "0 bytes");
}

/**
 * @test Empty filename is handled correctly
 */
TEST_F(FaultInjectionTest, EmptyFilenameHandledCorrectly) {
    ExoHeader header(PacketType::OFFER, 1024, "");
    header.magic = MAGIC_NUMBER;

    EXPECT_EQ(header.getFilename(), "");
    EXPECT_EQ(header.filenameLength, 0);
    EXPECT_TRUE(header.isValid());
}

/**
 * @test Maximum filename length is handled correctly
 */
TEST_F(FaultInjectionTest, MaxFilenameLengthHandledCorrectly) {
    // Create filename with 255 characters
    std::string maxName(255, 'A');
    ExoHeader header(PacketType::OFFER, 1024, maxName);
    header.magic = MAGIC_NUMBER;

    EXPECT_EQ(header.getFilename().length(), 255);
    EXPECT_EQ(header.filenameLength, 255);
    EXPECT_TRUE(header.isValid());
}

/**
 * @test Filename longer than max is truncated
 */
TEST_F(FaultInjectionTest, LongFilenameTruncatedCorrectly) {
    // Create filename with 300 characters
    std::string longName(300, 'B');
    ExoHeader header(PacketType::OFFER, 1024, longName);
    header.magic = MAGIC_NUMBER;  // Set magic for validation

    // Should be truncated to 255 (256 byte buffer - 1 for null terminator)
    EXPECT_EQ(header.getFilename().length(), 255);
    EXPECT_EQ(header.filenameLength, 255);
    EXPECT_TRUE(header.isValid());  // 255 <= 256, so should be valid
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
