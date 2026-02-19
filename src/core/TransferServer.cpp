/**
 * @file TransferServer.cpp
 * @brief Multi-threaded file transfer server
 */

#include "exosend/TransferServer.h"
#include "exosend/FileTransfer.h"
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

        // Extract client IP address
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        std::string clientIp(ipStr);

        // Check session limit
        if (m_activeSessionCount.load() >= MAX_CONCURRENT_TRANSFERS) {
            // Send BUSY response
            sendBusyResponse(clientSocket);
            closesocket(clientSocket);
            continue;
        }

        // Handle the client in a dedicated thread so the listener is never blocked.
        // Note: Previously handleClient() was called directly on the listener thread,
        // which (a) blocked the listener for the entire transfer duration, and (b) caused
        // ThreadSafeLog to call Qt APIs from a non-Qt thread after the transfer completed,
        // leading to a silent crash with no crash dump.
        std::thread clientThread(&TransferServer::handleClient, this, clientSocket, clientIp);
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
    // Step 1: Receive and parse ExoHeader
    std::vector<uint8_t> headerBuffer(HEADER_SIZE);
    int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(headerBuffer.data()),
                              HEADER_SIZE, 0);

    if (bytesReceived != HEADER_SIZE) {
        closesocket(clientSocket);
        return;
    }

    // Deserialize header from network byte order
    ExoHeader offerHeader;
    std::memcpy(&offerHeader, headerBuffer.data(), sizeof(ExoHeader));
    offerHeader.magic = ntohl(offerHeader.magic);
    offerHeader.fileSize = ntohll(offerHeader.fileSize);
    offerHeader.filenameLength = ntohs(offerHeader.filenameLength);

    // Validate header
    if (!offerHeader.isValid() || offerHeader.getPacketType() != PacketType::OFFER) {
        closesocket(clientSocket);
        return;
    }

    std::string filename = offerHeader.getFilename();

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
        accepted = m_incomingConnectionCallback(clientIp, offerHeader, tempSessionId);
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
        send(clientSocket, reinterpret_cast<const char*>(rejectBuffer), HEADER_SIZE, 0);
        closesocket(clientSocket);
        return;
    }

    // Step 7: User accepted - send ACCEPT
    uint8_t acceptBuffer[HEADER_SIZE];
    ExoHeader acceptHeader(PacketType::ACCEPT, 0, "");
    acceptHeader.serializeToBuffer(acceptBuffer);
    send(clientSocket, reinterpret_cast<const char*>(acceptBuffer), HEADER_SIZE, 0);

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
        success = sessionPtr->runIncomingTransfer(clientSocket, offerHeader, errorMsg);
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
    send(socket, reinterpret_cast<const char*>(buffer), HEADER_SIZE, 0);
}

//=============================================================================
// TransferServer: initializeSocket()
//=============================================================================

bool TransferServer::initializeSocket() {
    // Create socket
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        return false;
    }

    m_socketInitialized = true;

    // Set SO_REUSEADDR to allow quick restart
    int reuseAddr = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuseAddr), sizeof(reuseAddr));

    // Bind to port
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(m_port);

    if (bind(m_listenSocket, reinterpret_cast<const sockaddr*>(&serverAddr),
             sizeof(serverAddr)) == SOCKET_ERROR) {
        cleanupSocket();
        return false;
    }

    // Start listening
    if (listen(m_listenSocket, SOMAXCONN_VALUE) == SOCKET_ERROR) {
        cleanupSocket();
        return false;
    }

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
