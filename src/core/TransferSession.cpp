/**
 * @file TransferSession.cpp
 * @brief File transfer session with state management
 */

#define NOMINMAX
#include "exosend/TransferSession.h"
#include "exosend/PeerInfo.h"
#include "exosend/UuidGenerator.h"
#include "exosend/FileTransfer.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"
#include "exosend/Debug.h"
#include "exosend/ThreadSafeLog.h"
#include <iostream>
#include <ws2tcpip.h>
#include <system_error>
#include <thread>  // For std::this_thread::get_id()
#include <fstream>
#include <iomanip>
#include <chrono>

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
// Helper Functions
//=============================================================================

/**
 * @brief Generate unique session ID
 * @return Random session ID string with "sess_" prefix
 */
std::string TransferSession::generateSessionId() {
    // Delegate to centralized UUID generator with prefix
    return UuidGenerator::generateWithPrefix("sess_");
}

//=============================================================================
// Helper: ThrottledProgress Implementation
//=============================================================================

ThrottledProgress::ThrottledProgress(const std::string& sessionId,
                                     SessionProgressCallback callback)
    : m_sessionId(sessionId)
    , m_callback(callback)
    , m_lastUpdate(std::chrono::steady_clock::time_point::min())
{
}

void ThrottledProgress::operator()(uint64_t bytesTransferred,
                                    uint64_t totalBytes,
                                    double percentage) {
    if (!m_callback) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_lastUpdate).count();

    // Only callback if at least PROGRESS_THROTTLE_MS have elapsed
    if (elapsed >= PROGRESS_THROTTLE_MS) {
        m_callback(m_sessionId, bytesTransferred, totalBytes, percentage);
        m_lastUpdate = now;
    }
}

//=============================================================================
// TransferSession: INCOMING Constructor
//=============================================================================

TransferSession::TransferSession(SOCKET socket,
                                  const std::string& downloadDir,
                                  SessionStatusCallback statusCb,
                                  SessionProgressCallback progressCb,
                                  SessionCompletionCallback completionCb)
    : m_sessionId(generateSessionId())
    , m_type(SessionType::INCOMING)
    , m_status(SessionStatus::IDLE)
    , m_downloadDir(downloadDir)
    , m_peerIpAddress()
    , m_peerPort(0)
    , m_bytesTransferred(0)
    , m_totalBytes(0)
    , m_sha256Hash()
    , m_isRunning(false)
    , m_cancelRequested(false)
    , m_statusCallback(statusCb)
    , m_progressCallback(progressCb)
    , m_completionCallback(completionCb)
    , m_lastProgressUpdate(std::chrono::steady_clock::time_point::min())
    , m_outgoingSocket(INVALID_SOCKET)
    , m_ownsSocket(false)
{
    // Extract IP address from socket for INCOMING sessions
    sockaddr_in clientAddr{};
    int addrLen = sizeof(clientAddr);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen) == 0) {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        m_peerIpAddress = ipStr;
        m_peerPort = ntohs(clientAddr.sin_port);
    }
}

//=============================================================================
// TransferSession: OUTGOING Constructor
//=============================================================================

TransferSession::TransferSession(const std::string& filePath,
                                  const std::string& peerIpAddress,
                                  uint16_t peerPort,
                                  const std::string& sessionId,
                                  SessionStatusCallback statusCb,
                                  SessionProgressCallback progressCb,
                                  SessionCompletionCallback completionCb)
    : m_sessionId(sessionId.empty() ? generateSessionId() : sessionId)
    , m_type(SessionType::OUTGOING)
    , m_status(SessionStatus::IDLE)
    , m_filePath(filePath)
    , m_downloadDir()
    , m_peerIpAddress(peerIpAddress)
    , m_peerPort(peerPort)
    , m_bytesTransferred(0)
    , m_totalBytes(0)
    , m_sha256Hash()
    , m_isRunning(false)
    , m_cancelRequested(false)
    , m_statusCallback(statusCb)
    , m_progressCallback(progressCb)
    , m_completionCallback(completionCb)
    , m_lastProgressUpdate(std::chrono::steady_clock::time_point::min())
    , m_outgoingSocket(INVALID_SOCKET)
    , m_ownsSocket(true)
{
}

//=============================================================================
// TransferSession: Destructor
//=============================================================================

TransferSession::~TransferSession() {
    // Note: Destructors must NEVER throw exceptions
    // If an exception escapes during stack unwinding, std::terminate() is called
    // which kills the process silently without crash dumps
    try {
        // Cancel if still running
        if (m_isRunning.load()) {
            cancel();
        }

        // Wait for worker thread to finish
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }

        // Close socket if we own it
        if (m_ownsSocket && m_outgoingSocket != INVALID_SOCKET) {
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
        }
    } catch (...) {
        // Swallow ALL exceptions - destructor must complete without throwing
        // If we need to log, use thread-safe logging that won't throw
    }
}

//=============================================================================
// TransferSession: Move Constructor and Assignment
//=============================================================================

TransferSession::TransferSession(TransferSession&& other) noexcept
    : m_sessionId(std::move(other.m_sessionId))
    , m_type(other.m_type)
    , m_status(other.m_status.load())
    , m_filePath(std::move(other.m_filePath))
    , m_downloadDir(std::move(other.m_downloadDir))
    , m_peerIpAddress(std::move(other.m_peerIpAddress))
    , m_peerPort(other.m_peerPort)
    , m_bytesTransferred(other.m_bytesTransferred.load())
    , m_totalBytes(other.m_totalBytes.load())
    , m_sha256Hash(std::move(other.m_sha256Hash))
    , m_isRunning(other.m_isRunning.load())
    , m_cancelRequested(other.m_cancelRequested.load())
    , m_statusCallback(std::move(other.m_statusCallback))
    , m_progressCallback(std::move(other.m_progressCallback))
    , m_completionCallback(std::move(other.m_completionCallback))
    , m_lastProgressUpdate(other.m_lastProgressUpdate)
    , m_outgoingSocket(other.m_outgoingSocket)
    , m_ownsSocket(other.m_ownsSocket)
{
    other.m_outgoingSocket = INVALID_SOCKET;
    other.m_ownsSocket = false;
}

TransferSession& TransferSession::operator=(TransferSession&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        if (m_isRunning.load()) {
            cancel();
        }
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
        if (m_ownsSocket && m_outgoingSocket != INVALID_SOCKET) {
            closesocket(m_outgoingSocket);
        }

        // Move from other
        m_sessionId = std::move(other.m_sessionId);
        m_type = other.m_type;
        m_status.store(other.m_status.load());
        m_filePath = std::move(other.m_filePath);
        m_downloadDir = std::move(other.m_downloadDir);
        m_peerIpAddress = std::move(other.m_peerIpAddress);
        m_peerPort = other.m_peerPort;
        m_bytesTransferred.store(other.m_bytesTransferred.load());
        m_totalBytes.store(other.m_totalBytes.load());
        m_sha256Hash = std::move(other.m_sha256Hash);
        m_isRunning.store(other.m_isRunning.load());
        m_cancelRequested.store(other.m_cancelRequested.load());
        m_statusCallback = std::move(other.m_statusCallback);
        m_progressCallback = std::move(other.m_progressCallback);
        m_completionCallback = std::move(other.m_completionCallback);
        m_lastProgressUpdate = other.m_lastProgressUpdate;
        m_outgoingSocket = other.m_outgoingSocket;
        m_ownsSocket = other.m_ownsSocket;

        other.m_outgoingSocket = INVALID_SOCKET;
        other.m_ownsSocket = false;
    }
    return *this;
}

//=============================================================================
// TransferSession: run()
//=============================================================================

bool TransferSession::run() {
    // Check if already running
    if (m_isRunning.load()) {
        return false;
    }

    // Check if already completed
    SessionStatus currentStatus = m_status.load();
    if (currentStatus == SessionStatus::COMPLETED ||
        currentStatus == SessionStatus::FAILED ||
        currentStatus == SessionStatus::CANCELLED ||
        currentStatus == SessionStatus::BUSY) {
        return false;
    }

    // Mark as running
    m_isRunning.store(true);
    m_cancelRequested.store(false);

    // Start worker thread
    m_workerThread = std::thread(&TransferSession::workerThreadFunc, this);

    return true;
}

//=============================================================================
// TransferSession: cancel()
//=============================================================================

void TransferSession::cancel() {
    // Signal cancellation
    m_cancelRequested.store(true);

    // Close socket to interrupt blocking operations
    if (m_ownsSocket && m_outgoingSocket != INVALID_SOCKET) {
        closesocket(m_outgoingSocket);
        m_outgoingSocket = INVALID_SOCKET;
    }

    // Update status
    SessionStatus expected = SessionStatus::IDLE;
    if (m_status.compare_exchange_strong(expected, SessionStatus::CANCELLED)) {
        setStatus(SessionStatus::CANCELLED);
    }
}

//=============================================================================
// TransferSession: Worker Thread Function
//=============================================================================

void TransferSession::workerThreadFunc() {
    std::string errorMsg;

    try {
        if (m_type == SessionType::INCOMING) {
            // For INCOMING sessions, the socket should be passed separately
            // since we can't store it in the constructor (moved from accept())
            // This is handled by TransferServer which calls runIncomingTransfer()
            setStatus(SessionStatus::FAILED);
            errorMsg = "Internal error: INCOMING session must use runIncomingTransfer()";
        } else {
            // OUTGOING session
            bool success = runOutgoingTransfer(errorMsg);
            if (success) {
                setStatus(SessionStatus::COMPLETED);
            } else {
                setStatus(m_cancelRequested.load() ?
                          SessionStatus::CANCELLED : SessionStatus::FAILED);
            }
        }
    } catch (const std::exception& e) {
        errorMsg = e.what();
        setStatus(SessionStatus::FAILED);
    } catch (...) {
        errorMsg = "Unknown exception";
        setStatus(SessionStatus::FAILED);
    }

    // Mark as not running
    m_isRunning.store(false);

    // Call completion callback
    if (m_completionCallback) {
        bool success = (m_status.load() == SessionStatus::COMPLETED);
        m_completionCallback(m_sessionId, success, errorMsg);
    }
}

//=============================================================================
// TransferSession: runIncomingTransfer() - for INCOMING sessions
//=============================================================================

bool TransferSession::runIncomingTransfer(TransportStream& stream, const ExoHeader& preReceivedHeader, std::string& errorMsg) {
    // NOTE: Don't call setStatus() here - it triggers GUI callbacks from non-Qt thread
    // The TransferServer will handle status updates in the proper thread context

    try {
        // Create FileReceiver
        FileReceiver receiver(m_downloadDir);

        // Create throttled progress callback
        ThrottledProgress throttled(m_sessionId, m_progressCallback);

        // Receive file (pass pre-received header to avoid protocol mismatch)
        bool success = receiver.receiveFile(
            stream,
            preReceivedHeader,  // Pass the already-received header
            errorMsg,
            // Accept callback: automatically accept incoming transfers
            [this](const ExoHeader& header) -> bool {
                m_totalBytes.store(header.fileSize);
                m_filePath = header.getFilename();
                return true;
            },
            // Progress callback
            [this, &throttled](uint64_t transferred, uint64_t total, double pct) {
                m_bytesTransferred.store(transferred);
                m_totalBytes.store(total);
                throttled(transferred, total, pct);
            }
        );

        // Update status atomically without triggering callbacks
        m_status.store(success ? SessionStatus::COMPLETED : SessionStatus::FAILED);

        if (success) {
            m_sha256Hash = receiver.getSha256Hash();
        }

        // NOTE: Completion callback is now called by handleClient() after this function returns
        // This prevents double callback and race conditions
        LogTransferCrash("=== runIncomingTransfer: Returning, callback will be called by handleClient ===");
        LogTransferCrash("  Success: " + std::string(success ? "true" : "false"));

        return success;
    } catch (const std::exception& e) {
        errorMsg = std::string("FileReceiver exception: ") + e.what();
        m_status.store(SessionStatus::FAILED);
        LogTransferCrash("=== runIncomingTransfer: EXCEPTION ===");
        LogTransferCrash(std::string("  Exception: ") + e.what());
        return false;
    } catch (...) {
        errorMsg = "Unknown exception in runIncomingTransfer";
        m_status.store(SessionStatus::FAILED);
        LogTransferCrash("=== runIncomingTransfer: UNKNOWN EXCEPTION ===");
        return false;
    }
}

//=============================================================================
// TransferSession: runOutgoingTransfer() - for OUTGOING sessions
//=============================================================================

bool TransferSession::runOutgoingTransfer(std::string& errorMsg) {
    try {
        setStatus(SessionStatus::NEGOTIATING);

        // Create socket
        m_outgoingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_outgoingSocket == INVALID_SOCKET) {
            errorMsg = "Failed to create socket: WSAGetLastError() = " +
                       std::to_string(WSAGetLastError());
            return false;
        }

        // Set receive timeout
        if (!setSocketRecvTimeout(m_outgoingSocket, CONNECTION_TIMEOUT_MS)) {
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
            return false;
        }

        // Connect to peer
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(m_peerPort);

        if (inet_pton(AF_INET, m_peerIpAddress.c_str(), &serverAddr.sin_addr) <= 0) {
            errorMsg = "Invalid IP address: " + m_peerIpAddress;
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
            return false;
        }

        int connectResult = connect(m_outgoingSocket, reinterpret_cast<sockaddr*>(&serverAddr),
                                   sizeof(serverAddr));

        if (connectResult == SOCKET_ERROR) {
            int wsaError = WSAGetLastError();
            errorMsg = "Failed to connect to " + m_peerIpAddress + ":" +
                       std::to_string(m_peerPort) +
                       " (WSAGetLastError() = " + std::to_string(wsaError) + ")";
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
            return false;
        }

        tuneSocketBuffers(m_outgoingSocket);

        // Create throttled progress callback
        ThrottledProgress throttled(m_sessionId, m_progressCallback);

        bool success = false;

        if (m_requireTls) {
            // TLS handshake and pin verification
            TlsSocket tls(m_outgoingSocket, TlsRole::CLIENT);
            if (!tls.handshake(errorMsg)) {
                closesocket(m_outgoingSocket);
                m_outgoingSocket = INVALID_SOCKET;
                return false;
            }

            std::string fpError;
            const std::string peerFp = tls.getPeerFingerprint(fpError);
            if (!m_expectedPeerFingerprintSha256Hex.empty()) {
                if (peerFp.empty() || peerFp != m_expectedPeerFingerprintSha256Hex) {
                    errorMsg = "Pinned fingerprint mismatch for peer '" + m_peerUuid +
                               "'. Expected=" + m_expectedPeerFingerprintSha256Hex +
                               " Actual=" + (peerFp.empty() ? "<empty>" : peerFp);
                    closesocket(m_outgoingSocket);
                    m_outgoingSocket = INVALID_SOCKET;
                    return false;
                }
            } else {
                errorMsg = "Unpaired peer '" + m_peerUuid + "' (no pinned fingerprint). Peer fingerprint=" +
                           (peerFp.empty() ? "<empty>" : peerFp);
                closesocket(m_outgoingSocket);
                m_outgoingSocket = INVALID_SOCKET;
                return false;
            }

            setStatus(SessionStatus::TRANSFERRING);

            TlsTransportStream stream(tls);
            FileSender sender(m_filePath, m_localDeviceUuid);

            success = sender.sendFile(
                stream,
                errorMsg,
                [this, &throttled](uint64_t transferred, uint64_t total, double pct) {
                    m_bytesTransferred.store(transferred);
                    m_totalBytes.store(total);
                    throttled(transferred, total, pct);
                }
            );

            if (success) {
                m_sha256Hash = sender.getSha256Hash();
            }

            stream.shutdown();
        } else {
            setStatus(SessionStatus::TRANSFERRING);

            PlainSocketStream stream(m_outgoingSocket);
            FileSender sender(m_filePath, m_localDeviceUuid);

            success = sender.sendFile(
                stream,
                errorMsg,
                [this, &throttled](uint64_t transferred, uint64_t total, double pct) {
                    m_bytesTransferred.store(transferred);
                    m_totalBytes.store(total);
                    throttled(transferred, total, pct);
                }
            );

            if (success) {
                m_sha256Hash = sender.getSha256Hash();
            }
        }

        // Close socket
        closesocket(m_outgoingSocket);
        m_outgoingSocket = INVALID_SOCKET;

        return success;

    } catch (const std::exception& e) {
        errorMsg = e.what();
        // Clean up socket
        if (m_outgoingSocket != INVALID_SOCKET) {
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
        }
        return false;
    } catch (...) {
        errorMsg = "Unknown exception in runOutgoingTransfer";
        // Clean up socket
        if (m_outgoingSocket != INVALID_SOCKET) {
            closesocket(m_outgoingSocket);
            m_outgoingSocket = INVALID_SOCKET;
        }
        return false;
    }
}

//=============================================================================
// TransferSession: setStatus()
//=============================================================================

void TransferSession::setStatus(SessionStatus status) {
    m_status.store(status);
    if (m_statusCallback) {
        m_statusCallback(m_sessionId, status);
    }
}

//=============================================================================
// Public API: Trigger Completion Callback (External Call)
//=============================================================================

/**
 * @brief Trigger the completion callback from external code
 *
 * This method is called by TransferServer::handleClient() AFTER runIncomingTransfer
 * returns. This prevents double callback issues where the callback might be called
 * from both runIncomingTransfer (which previously called it) and handleClient.
 *
 * The callback is now only called once, from the top-level function that controls
 * the session lifecycle.
 */
void TransferSession::triggerCompletionCallback(bool success, const std::string& errorMessage) {
    if (m_completionCallback) {
        m_completionCallback(m_sessionId, success, errorMessage);
    }
}

}  // namespace ExoSend
