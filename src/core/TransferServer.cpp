/**
 * @file TransferServer.cpp
 * @brief Multi-threaded file transfer server
 */

#include "exosend/TransferServer.h"
#include "exosend/FileTransfer.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"
#include "exosend/UuidGenerator.h"
#include "exosend/Debug.h"
#include "exosend/ThreadSafeLog.h"
#include <ws2tcpip.h>
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <thread>  // For std::this_thread::get_id()
#include <fstream>
#include <iomanip>
#include <chrono>
#include <windows.h>

namespace ExoSend {

//=============================================================================
// Crash logging (trace support)
//=============================================================================

namespace {
    // Thread-safe logging macro - uses ThreadSafeLog for all crash logging
    #define LogTransferCrash(msg) ExoSend::ThreadSafeLog::log(msg)

    void tuneSocketBuffers(SOCKET socket) {
        const int buf = 4 * 1024 * 1024;
        (void)setsockopt(socket, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
    }
} // anonymous namespace

//=============================================================================
// Constructor / Destructor
//=============================================================================

/**
 * @brief Construct transfer server
 * @param port TCP port to listen on
 */
TransferServer::TransferServer(uint16_t port)
    : m_port(port)
    , m_downloadDir(".")  // Default to current directory
    , m_maxIncomingSizeBytes(DEFAULT_MAX_INCOMING_SIZE_BYTES)
    , m_listenSocket(INVALID_SOCKET)
    , m_socketInitialized(false)
    , m_activeSessionCount(0)
    , m_running(false)
    , m_stopRequested(false)
    , m_sessionEventCallback(nullptr)
    , m_incomingConnectionCallback(nullptr)
{
}

//=============================================================================
// TransferServer: Destructor
//=============================================================================

TransferServer::~TransferServer() {
    // Stop server if running
    if (m_running.load()) {
        stop();
    }

    // Clean up socket
    cleanupSocket();
}

//=============================================================================
// TransferServer: start()
//=============================================================================

bool TransferServer::start() {
    // Check if already running
    if (m_running.load()) {
        return false;
    }

    // Initialize listening socket
    if (!initializeSocket()) {
        return false;
    }

    // Reset flags
    m_stopRequested.store(false);
    m_running.store(true);

    // Launch listener thread
    m_listenerThread = std::thread(&TransferServer::listenerThreadFunc, this);

    // Launch cleanup thread
    m_cleanupThread = std::thread(&TransferServer::cleanupThreadFunc, this);

    return true;
}

//=============================================================================
// TransferServer: stop()
//=============================================================================

void TransferServer::stop() {
    // Check if running
    if (!m_running.load()) {
        return;
    }

    LogTransferCrash("=== TransferServer::stop START ===");

    // Signal threads to stop
    m_stopRequested.store(true);
    m_cleanupCv.notify_all();

    // Close listening socket (will interrupt accept())
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    m_socketInitialized = false;
    m_boundTcpPort = 0;

    // Cancel any active client handler threads by shutting down their sockets.
    // This prevents detached threads from running long after stop() returns
    // and ensures the TransferServer object is not destroyed while threads
    // still access its members.
    {
        std::vector<SOCKET> socketsToShutdown;
        {
            std::lock_guard<std::mutex> lock(m_activeClientsMutex);
            socketsToShutdown.reserve(m_activeClientSockets.size());
            for (SOCKET s : m_activeClientSockets) {
                socketsToShutdown.push_back(s);
            }
        }

        for (SOCKET s : socketsToShutdown) {
            (void)shutdown(s, SD_BOTH);
        }
    }

    // Cancel all active sessions
    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        for (auto& pair : m_sessions) {
            if (pair.second) {
                pair.second->cancel();
            }
        }
    }

    // Wait for listener thread
    if (m_listenerThread.joinable()) {
        m_listenerThread.join();
    }

    // Wait for cleanup thread
    if (m_cleanupThread.joinable()) {
        m_cleanupThread.join();
    }

    // Clear all sessions
    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        m_sessions.clear();
        m_activeSessionCount.store(0);
    }

    // Wait for all detached client handler threads to exit.
    {
        std::unique_lock<std::mutex> lock(m_activeClientsCvMutex);
        m_activeClientsCv.wait(lock, [this]() {
            return m_activeClientThreadCount.load(std::memory_order_acquire) == 0;
        });
    }

    // Mark as not running
    m_running.store(false);
    LogTransferCrash("=== TransferServer::stop END ===");
}

//=============================================================================
// TransferServer: getActiveSessionIds()
//=============================================================================

std::vector<std::string> TransferServer::getActiveSessionIds() const {
    std::vector<std::string> ids;

    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    ids.reserve(m_sessions.size());

    for (const auto& pair : m_sessions) {
        if (pair.second && !pair.second->isDone()) {
            ids.push_back(pair.first);
        }
    }

    return ids;
}

//=============================================================================
// TransferServer: getSession()
//=============================================================================

TransferSession* TransferServer::getSession(const std::string& sessionId) const {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end() && it->second && !it->second->isDone()) {
        return it->second.get();
    }

    return nullptr;
}

//=============================================================================
// TransferServer: listenerThreadFunc()
//=============================================================================

void TransferServer::listenerThreadFunc() {
    // Set socket to non-blocking mode for clean shutdown
    u_long mode = 1;  // Non-blocking
    ioctlsocket(m_listenSocket, FIONBIO, &mode);

    while (!m_stopRequested.load()) {
        // Accept incoming connection
        sockaddr_in clientAddr{};
        int addrLen = sizeof(clientAddr);

        SOCKET clientSocket = accept(m_listenSocket,
                                       reinterpret_cast<sockaddr*>(&clientAddr),
                                       &addrLen);

        if (clientSocket == INVALID_SOCKET) {
            int error = WSAGetLastError();

            // Check if we're stopping
            if (m_stopRequested.load()) {
                break;
            }

            // WSAEWOULDBLOCK is expected in non-blocking mode
            if (error == WSAEWOULDBLOCK) {
                // Sleep a bit and try again
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Other error
            continue;
        }

        // Note: Set client socket back to BLOCKING mode
        // (accept() returns a socket that inherits non-blocking mode from listening socket)
        u_long blockingMode = 0;  // 0 = blocking mode
        ioctlsocket(clientSocket, FIONBIO, &blockingMode);

        // Set receive timeout for client socket
        if (!setSocketRecvTimeout(clientSocket, CONNECTION_TIMEOUT_MS)) {
            closesocket(clientSocket);
            continue;
        }

        tuneSocketBuffers(clientSocket);

        // Extract client IP address
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        std::string clientIp(ipStr);

        // IP pre-filter: reject connections from IPs not in the discovery peer list.
        // Defense-in-depth: TLS + ExoSend protocol still authenticate all peers.
        if (m_ipValidator && !m_ipValidator(clientIp)) {
            std::cerr << "[TransferServer] Rejected connection from unknown IP: "
                      << clientIp << " (not in discovery peer list)\n";
            closesocket(clientSocket);
            continue;
        }

        // DoS hardening: per-IP connection rate limiting before spawning threads.
        if (!m_connectionRateLimiter.shouldAccept(clientIp)) {
            closesocket(clientSocket);
            continue;
        }

        // DoS hardening: cap concurrent client handler threads before spawning.
        size_t prev = m_activeClientThreadCount.load(std::memory_order_relaxed);
        while (true) {
            if (prev >= MAX_CONCURRENT_INCOMING_CLIENT_THREADS) {
                closesocket(clientSocket);
                clientSocket = INVALID_SOCKET;
                break;
            }
            if (m_activeClientThreadCount.compare_exchange_weak(
                    prev,
                    prev + 1,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                break;
            }
        }
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_activeClientsMutex);
            m_activeClientSockets.insert(clientSocket);
        }

        // Handle the client in a dedicated thread so the listener is never blocked.
        // Note: Previously handleClient() was called directly on the listener thread,
        // which (a) blocked the listener for the entire transfer duration, and (b) caused
        // ThreadSafeLog to call Qt APIs from a non-Qt thread after the transfer completed,
        // leading to a silent crash with no crash dump.
        std::thread clientThread([this, clientSocket, clientIp]() {
            try {
                this->handleClient(clientSocket, clientIp);
            } catch (const std::exception& e) {
                LogTransferCrash(std::string("=== handleClient: UNCAUGHT EXCEPTION === ") + e.what());
            } catch (...) {
                LogTransferCrash("=== handleClient: UNCAUGHT UNKNOWN EXCEPTION ===");
            }

            {
                std::lock_guard<std::mutex> lock(m_activeClientsMutex);
                m_activeClientSockets.erase(clientSocket);
            }

            m_activeClientThreadCount.fetch_sub(1, std::memory_order_acq_rel);
            m_activeClientsCv.notify_all();
        });
        clientThread.detach();
    }
}

//=============================================================================
// TransferServer: cleanupThreadFunc()
//=============================================================================

void TransferServer::cleanupThreadFunc() {
    while (!m_stopRequested.load()) {
        // Wait for cleanup interval or stop signal.
        std::unique_lock<std::mutex> waitLock(m_cleanupCvMutex);
        m_cleanupCv.wait_for(
            waitLock,
            std::chrono::milliseconds(SESSION_CLEANUP_INTERVAL_MS),
            [this]() { return m_stopRequested.load(); }
        );
        waitLock.unlock();

        // Check if we're stopping
        if (m_stopRequested.load()) {
            break;
        }

        // Remove completed sessions
        std::vector<std::string> toRemove;

        {
            std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);

            for (auto& pair : m_sessions) {
                // Note: Only remove sessions that are done AND have no pending callbacks
                if (pair.second && pair.second->isDone()) {
                    // Check reference count - only remove if no callbacks are pending
                    std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                    auto refIt = m_sessionRefCounts.find(pair.first);
                    if (refIt == m_sessionRefCounts.end() || refIt->second <= 0) {
                        toRemove.push_back(pair.first);
                    }
                }
            }

            // Remove completed sessions and their reference counts
            for (const std::string& sessionId : toRemove) {
                m_sessions.erase(sessionId);
                // Also remove from reference count map
                {
                    std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                    m_sessionRefCounts.erase(sessionId);
                }
            }

            // Update count
            size_t activeCount = 0;
            for (const auto& pair : m_sessions) {
                if (pair.second && !pair.second->isDone()) {
                    activeCount++;
                }
            }
            m_activeSessionCount.store(activeCount);
        }
    }
}

//=============================================================================
// TransferServer: handleClient()
//=============================================================================

void TransferServer::handleClient(SOCKET clientSocket, const std::string& clientIp) {
    // Step 0: Enforce TLS for v0.2.0+ transfers
    std::string tlsError;
    TlsSocket tls(clientSocket, TlsRole::SERVER);
    if (!tls.handshake(tlsError)) {
        closesocket(clientSocket);
        return;
    }

    TlsTransportStream stream(tls);

    std::string fpError;
    const std::string peerFingerprint = tls.getPeerFingerprint(fpError);

    // Step 1: Receive and parse ExoHeader over TLS
    std::vector<uint8_t> headerBuffer(HEADER_SIZE);
    std::string headerError;
    if (!stream.recvExact(headerBuffer.data(), HEADER_SIZE, headerError)) {
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    ExoHeader offerHeader;
    if (!offerHeader.deserializeFromBuffer(headerBuffer.data())) {
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // Validate header (protocol gate)
    if (!offerHeader.isValid()) {
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // Secure pairing handshake (PAIR_REQ / PAIR_RESP)
    if (offerHeader.getPacketType() == PacketType::PAIR_REQ) {
        const std::string clientUuid = offerHeader.getSenderUuid();

        std::string localFpErr;
        const std::string serverFingerprint = tls.getLocalFingerprint(localFpErr);

        std::array<uint8_t, 32> exporter{};
        std::string exporterErr;
        const bool exporterOk = tls.getTlsExporterChannelBinding(exporter, exporterErr);

        const auto clientTag = offerHeader.getSha256Bytes();

        std::array<uint8_t, 32> serverTag{};
        std::string pairingErr;
        const bool accepted = (m_incomingPairingCallback &&
                               !m_localDeviceUuid.empty() &&
                               !clientUuid.empty() &&
                               !peerFingerprint.empty() &&
                               !serverFingerprint.empty() &&
                               exporterOk &&
                               m_incomingPairingCallback(
                                   clientIp,
                                   clientUuid,
                                   peerFingerprint,
                                   m_localDeviceUuid,
                                   serverFingerprint,
                                   exporter,
                                   clientTag,
                                   serverTag,
                                   pairingErr
                               ));

        if (!accepted) {
            uint8_t rejectBuffer[HEADER_SIZE];
            ExoHeader rejectHeader(PacketType::REJECT, 0, "");
            (void)rejectHeader.serializeToBuffer(rejectBuffer);
            std::string rejectError;
            (void)stream.sendExact(rejectBuffer, HEADER_SIZE, rejectError);
            stream.shutdown();
            closesocket(clientSocket);
            return;
        }

        uint8_t respBuffer[HEADER_SIZE];
        ExoHeader respHeader(PacketType::PAIR_RESP, 0, "");
        respHeader.setSenderUuid(m_localDeviceUuid);
        respHeader.setSha256Bytes(serverTag.data());
        (void)respHeader.serializeToBuffer(respBuffer);
        std::string respError;
        (void)stream.sendExact(respBuffer, HEADER_SIZE, respError);

        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // File transfer path starts with OFFER.
    if (offerHeader.getPacketType() != PacketType::OFFER) {
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // Reject oversized offers early (DoS mitigation)
    if (m_maxIncomingSizeBytes > 0 && offerHeader.fileSize > m_maxIncomingSizeBytes) {
        uint8_t rejectBuffer[HEADER_SIZE];
        ExoHeader rejectHeader(PacketType::REJECT, 0, "");
        (void)rejectHeader.serializeToBuffer(rejectBuffer);
        std::string rejectError;
        (void)stream.sendExact(rejectBuffer, HEADER_SIZE, rejectError);
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    std::string filename = offerHeader.getFilename();

    // Enforce session limit after TLS handshake and offer receive.
    if (m_activeSessionCount.load() >= MAX_CONCURRENT_TRANSFERS) {
        uint8_t busyBuffer[HEADER_SIZE];
        ExoHeader busyHeader(PacketType::BUSY, 0, "");
        (void)busyHeader.serializeToBuffer(busyBuffer);
        std::string busyError;
        (void)stream.sendExact(busyBuffer, HEADER_SIZE, busyError);
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // Step 2: Create pending session ID for tracking
    std::string tempSessionId = "pending_" + UuidGenerator::generate();

    // Step 3: Create PendingConnection with promise/future
    auto pendingConn = std::make_unique<PendingConnection>(clientSocket, clientIp, offerHeader);
    std::future<bool> acceptFuture = pendingConn->acceptPromise.get_future();

    {
        std::lock_guard<std::mutex> lock(m_pendingConnectionsMutex);
        m_pendingConnections[tempSessionId] = std::move(pendingConn);
    }

    // Step 4: Call callback with tempSessionId - this will show dialog and WAIT for result
    bool accepted = false;
    if (m_incomingConnectionCallback) {
        accepted = m_incomingConnectionCallback(clientIp, offerHeader, tempSessionId, peerFingerprint);
    }

    // Step 5: Clean up pending connection
    {
        std::lock_guard<std::mutex> lock(m_pendingConnectionsMutex);
        m_pendingConnections.erase(tempSessionId);
    }

    // Step 6: Handle user's decision
    if (!accepted) {
        // User rejected - send REJECT
        uint8_t rejectBuffer[HEADER_SIZE];
        ExoHeader rejectHeader(PacketType::REJECT, 0, "");
        rejectHeader.serializeToBuffer(rejectBuffer);
        std::string rejectError;
        (void)stream.sendExact(rejectBuffer, HEADER_SIZE, rejectError);
        stream.shutdown();
        closesocket(clientSocket);
        return;
    }

    // Step 7: User accepted - send ACCEPT
    uint8_t acceptBuffer[HEADER_SIZE];
    ExoHeader acceptHeader(PacketType::ACCEPT, 0, "");
    acceptHeader.serializeToBuffer(acceptBuffer);
    std::string acceptError;
    (void)stream.sendExact(acceptBuffer, HEADER_SIZE, acceptError);

    // Step 8: Create session and store in m_sessions map
    // Note: Store session in map instead of local variable to prevent
    // premature destruction while Qt event queue still has pending callbacks
    auto session = createSession(clientSocket, clientIp);

    if (!session) {
        closesocket(clientSocket);
        return;
    }

    // Get session ID BEFORE moving into map
    const std::string sessionId = session->getSessionId();

    // Store session in m_sessions map and increment counter
    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        m_sessions[sessionId] = std::move(session);  // Move ownership into map
        m_activeSessionCount.fetch_add(1);           // Increment counter
    }

    // Get pointer from map for use
    TransferSession* sessionPtr = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            sessionPtr = it->second.get();
        }
    }

    if (!sessionPtr) {
        closesocket(clientSocket);
        return;
    }

    // Note: Increment reference count while using the pointer in handleClient.
    // This prevents the cleanup thread from deleting the session while we are working with it.
    {
        std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
        m_sessionRefCounts[sessionId]++;
    }

    // Store filename
    {
        std::lock_guard<std::mutex> lock(m_pendingTransfersMutex);
        m_pendingFilenames[sessionId] = filename;
    }

    // Update status to NEGOTIATING before starting transfer
    if (m_sessionEventCallback) {
        m_sessionEventCallback(sessionId, SessionStatus::NEGOTIATING);
    }

    // Run transfer (pass the pre-received header to avoid double-receive)
    // Note: Wrap in try-catch to prevent unhandled exceptions from
    // crashing the worker thread (which would call std::terminate)
    std::string errorMsg;
    bool success = false;

    try {
        success = sessionPtr->runIncomingTransfer(stream, offerHeader, errorMsg);
    } catch (const std::exception& e) {
        errorMsg = std::string("Exception during transfer: ") + e.what();
        success = false;
        LogTransferCrash("=== handleClient: EXCEPTION in runIncomingTransfer ===");
        LogTransferCrash(std::string("  Exception: ") + e.what());
    } catch (...) {
        errorMsg = "Unknown exception during transfer";
        success = false;
        LogTransferCrash("=== handleClient: UNKNOWN EXCEPTION in runIncomingTransfer ===");
    }

    // Gracefully shutdown TLS after transfer completes.
    stream.shutdown();

    // Trace: Log after runIncomingTransfer
    LogTransferCrash("=== handleClient: runIncomingTransfer returned ===");
    LogTransferCrash("  Success: " + std::string(success ? "true" : "false"));

    // Note: Call completion callback here (not in runIncomingTransfer)
    // This is now the ONLY way the UI is notified of completion/failure.
    // Removed redundant m_sessionEventCallback(status) to prevent double-firing.
    LogTransferCrash("=== handleClient: Calling completion callback ===");

    try {
        sessionPtr->triggerCompletionCallback(success, errorMsg);
    } catch (const std::exception& e) {
        LogTransferCrash(std::string("=== handleClient: EXCEPTION in triggerCompletionCallback: ") + e.what());
    } catch (...) {
        LogTransferCrash("=== handleClient: UNKNOWN EXCEPTION in triggerCompletionCallback ===");
    }

    LogTransferCrash("=== handleClient: Completion callback done ===");

    // Note: Reduced delay since Qt events are now processed synchronously
    // The QTimer::singleShot deferral has been removed, so events complete before
    // this point. Kept as minimal safety margin (50ms instead of 500ms).
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::this_thread::yield();

    // Note: Close the socket after transfer completes
    // The socket is owned by handleClient() and must be closed before returning
    // This prevents socket leaks that cause crashes and undefined behavior
    // Note: Call shutdown() before closesocket for graceful socket closure
    int shutdownResult = shutdown(clientSocket, SD_BOTH);
    if (shutdownResult == SOCKET_ERROR) {
        int wsaError = WSAGetLastError();
        LogTransferCrash("=== shutdown() failed: WSA " + std::to_string(wsaError));
    }
    closesocket(clientSocket);

    // Trace: Log after closesocket
    LogTransferCrash("=== handleClient: closesocket completed ===");

    // Clean up pending filename (notification handled by completion callback)
    {
        std::lock_guard<std::mutex> lock(m_pendingTransfersMutex);
        m_pendingFilenames.erase(sessionId);
    }

    // Trace: Log at end of handleClient
    LogTransferCrash("=== handleClient: Returning ===");

    // Note: Decrement reference count after handleClient completes
    // This allows the cleanup thread to remove the session when ref count reaches 0
    {
        std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
        auto refIt = m_sessionRefCounts.find(sessionId);
        if (refIt != m_sessionRefCounts.end()) {
            refIt->second--;
            LogTransferCrash("=== handleClient: Ref count decremented ===");
            LogTransferCrash("  Session ID: " + sessionId);
            LogTransferCrash("  New Ref Count: " + std::to_string(refIt->second));
        } else {
            LogTransferCrash("=== handleClient: WARNING - Session not in ref count map ===");
            LogTransferCrash("  Session ID: " + sessionId);
        }
    }
}

//=============================================================================
// TransferServer: sendBusyResponse()
//=============================================================================

void TransferServer::sendBusyResponse(SOCKET socket) {
    // Create BUSY header
    ExoHeader busyHeader(PacketType::BUSY, 0, "");

    // Serialize to network byte order
    uint8_t buffer[HEADER_SIZE];
    busyHeader.serializeToBuffer(buffer);

    // Send response
    std::string errorMsg;
    (void)sendExact(socket, buffer, HEADER_SIZE, errorMsg);
}

//=============================================================================
// TransferServer: initializeSocket()
//=============================================================================

bool TransferServer::initializeSocket() {
    // Initialize Winsock. TransferServer now starts before DiscoveryService (v0.3
    // startup order), so it must own its own WSAStartup rather than relying on
    // DiscoveryService to have initialized Winsock first.
    // Ref: https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[TransferServer] WSAStartup failed: " << WSAGetLastError() << "\n";
        return false;
    }

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        std::cerr << "[TransferServer] socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return false;
    }
    m_socketInitialized = true;

    // SO_EXCLUSIVEADDRUSE: prevents port hijacking and gives authoritative
    // bind-failure semantics. MUST be set BEFORE bind(). Replaces SO_REUSEADDR
    // which allows port hijacking on Windows.
    // Ref: https://learn.microsoft.com/windows/win32/winsock/so-exclusiveaddruse
    BOOL exclusive = TRUE;
    if (setsockopt(m_listenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive),
                   sizeof(exclusive)) == SOCKET_ERROR) {
        std::cerr << "[TransferServer] SO_EXCLUSIVEADDRUSE failed: "
                  << WSAGetLastError() << "\n";
        WSACleanup();
        cleanupSocket();
        return false;
    }

    // Bind to port 0: OS assigns a free ephemeral port (49152-65535 on Windows).
    sockaddr_in serverAddr{};
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(0);

    if (bind(m_listenSocket,
             reinterpret_cast<const sockaddr*>(&serverAddr),
             sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[TransferServer] bind(port=0) failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        cleanupSocket();
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN_VALUE) == SOCKET_ERROR) {
        std::cerr << "[TransferServer] listen() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        cleanupSocket();
        return false;
    }

    // Read back the OS-assigned port via getsockname().
    // Ref: https://learn.microsoft.com/windows/win32/api/winsock/nf-winsock-getsockname
    sockaddr_in boundAddr{};
    int addrLen = sizeof(boundAddr);
    if (getsockname(m_listenSocket,
                    reinterpret_cast<sockaddr*>(&boundAddr), &addrLen) == SOCKET_ERROR) {
        std::cerr << "[TransferServer] getsockname() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        cleanupSocket();
        return false;
    }

    m_boundTcpPort = ntohs(boundAddr.sin_port);
    std::cout << "[TransferServer] Listening on dynamically assigned TCP port "
              << m_boundTcpPort << "\n";
    return true;
}

//=============================================================================
// TransferServer: cleanupSocket()
//=============================================================================

void TransferServer::cleanupSocket() {
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    m_socketInitialized = false;
    m_boundTcpPort = 0;
}

//=============================================================================
// TransferServer: getPendingFilename()
//=============================================================================

std::string TransferServer::getPendingFilename(const std::string& sessionId) const
{
    std::lock_guard<std::mutex> lock(m_pendingTransfersMutex);
    auto it = m_pendingFilenames.find(sessionId);
    if (it != m_pendingFilenames.end()) {
        return it->second;
    }
    return "";
}

//=============================================================================
// TransferServer: createSession()
//=============================================================================

std::unique_ptr<TransferSession> TransferServer::createSession(
    SOCKET socket, const std::string& clientIp) {

    // Create session with callbacks
    auto session = std::make_unique<TransferSession>(
        socket,
        m_downloadDir,
        // Status callback
        [this](const std::string& sessionId, SessionStatus status) {
            // Note: Increment ref count before callback to prevent cleanup
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]++;
            }

            if (m_stopRequested.load()) {
                // Decrement before returning
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
                return;
            }
            if (m_sessionEventCallback) {
                m_sessionEventCallback(sessionId, status);
            }

            // Note: Decrement ref count after callback
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
            }
        },
        // Progress callback (forward to user)
        [this](const std::string& sessionId,
                uint64_t transferred,
                uint64_t total,
                double percentage) {
            // Note: Increment ref count before callback
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]++;
            }

            if (m_stopRequested.load()) {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
                return;
            }
            if (m_sessionEventCallback) {
                // For progress, we use the same callback but the user
                // can distinguish by checking the session status
                // (progress updates happen during TRANSFERRING state)
                m_sessionEventCallback(sessionId, SessionStatus::TRANSFERRING);
            }

            // Note: Decrement ref count after callback
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
            }
        },
        // Completion callback
        [this](const std::string& sessionId,
                bool success,
                const std::string& errorMessage) {
            // Note: Increment ref count before callback
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]++;
            }

            size_t newCount = m_activeSessionCount.fetch_sub(1) - 1;
            (void)newCount;  // Suppress unused variable warning

            if (m_stopRequested.load()) {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
                return;
            }

            if (m_sessionEventCallback) {
                SessionStatus status = success ?
                    SessionStatus::COMPLETED : SessionStatus::FAILED;

                m_sessionEventCallback(sessionId, status);
            }

            // Note: Decrement ref count after callback
            {
                std::lock_guard<std::mutex> refLock(m_sessionRefCountMutex);
                m_sessionRefCounts[sessionId]--;
            }

            // Trace: Log after ref count decrement
            LogTransferCrash("=== Completion callback: Ref count decremented ===");
            LogTransferCrash("  Session ID: " + sessionId);
        }
    );

    return session;
}

}  // namespace ExoSend
