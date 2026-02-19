/**
 * @file TransferSession.h
 * @brief File transfer session with state management
 */

#pragma once

#include "config.h"
#include "TransferHeader.h"
#include "FileTransfer.h"
#include "HashUtils.h"
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>
#include <mutex>
#include <winsock2.h>

namespace ExoSend {

//=============================================================================
// Session Type and Status Enums
//=============================================================================

/**
 * @brief Type of transfer session
 */
enum class SessionType : uint8_t {
    INCOMING,  ///< Receiving a file from a peer
    OUTGOING   ///< Sending a file to a peer
};

/**
 * @brief Status of a transfer session
 */
enum class SessionStatus : uint8_t {
    IDLE,         ///< Session created, not started
    NEGOTIATING,  ///< Exchanging headers
    TRANSFERRING, ///< Transferring file data
    COMPLETED,    ///< Transfer completed successfully
    FAILED,       ///< Transfer failed
    CANCELLED,    ///< Transfer was cancelled
    BUSY          ///< Peer is busy, cannot accept transfer
};

/**
 * @brief Convert SessionStatus to string
 * @param status Session status
 * @return Human-readable status string
 */
inline std::string sessionStatusToString(SessionStatus status) {
    switch (status) {
        case SessionStatus::IDLE:         return "Idle";
        case SessionStatus::NEGOTIATING:  return "Negotiating";
        case SessionStatus::TRANSFERRING: return "Transferring";
        case SessionStatus::COMPLETED:    return "Completed";
        case SessionStatus::FAILED:       return "Failed";
        case SessionStatus::CANCELLED:    return "Cancelled";
        case SessionStatus::BUSY:         return "Busy";
        default:                          return "Unknown";
    }
}

//=============================================================================
// Callback Types
//=============================================================================

/**
 * @brief Status callback function type
 *
 * Called when the session status changes.
 *
 * @param sessionId Unique session identifier
 * @param status New session status
 */
using SessionStatusCallback = std::function<void(const std::string& sessionId,
                                                  SessionStatus status)>;

/**
 * @brief Progress callback function type
 *
 * Called during file transfer to report progress.
 * Throttled to ~50ms intervals to prevent queue saturation.
 *
 * @param sessionId Unique session identifier
 * @param bytesTransferred Total bytes transferred so far
 * @param totalBytes Total file size
 * @param percentage Transfer percentage (0-100)
 */
using SessionProgressCallback = std::function<void(const std::string& sessionId,
                                                     uint64_t bytesTransferred,
                                                     uint64_t totalBytes,
                                                     double percentage)>;

/**
 * @brief Completion callback function type
 *
 * Called when the session completes (success, failure, or cancelled).
 *
 * @param sessionId Unique session identifier
 * @param success True if transfer succeeded
 * @param errorMessage Error message if failed (empty if success)
 */
using SessionCompletionCallback = std::function<void(const std::string& sessionId,
                                                       bool success,
                                                       const std::string& errorMessage)>;

//=============================================================================
// TransferSession Class
//=============================================================================

/**
 * @class TransferSession
 * @brief Wraps a single file transfer operation with threading support
 *
 * This class manages a single file transfer (either incoming or outgoing)
 * running on a dedicated thread. It wraps the FileSender or FileReceiver
 * classes from Phase 2 and adds:
 *
 * - Thread management (dedicated thread per session)
 * - Progress throttling (50ms intervals)
 * - Status reporting via callbacks
 * - Cancellation support
 * - RAII resource management
 *
 * Thread Safety:
 * - getStatus() is thread-safe (uses atomic)
 * - cancel() is thread-safe
 * - Other methods are not thread-safe (call before run())
 *
 * Usage:
 * @code
 * // Incoming session
 * auto session = std::make_unique<TransferSession>(
 *     clientSocket,
 *     SessionType::INCOMING,
 *     statusCallback,
 *     progressCallback,
 *     completionCallback
 * );
 * session->run();
 *
 * // Outgoing session
 * auto session = std::make_unique<TransferSession>(
 *     filePath,
 *     peerIpAddress,
 *     peerPort,
 *     statusCallback,
 *     progressCallback,
 *     completionCallback
 * );
 * session->run();
 * @endcode
 */
class TransferSession {
public:
    //=========================================================================
    // Constructors for INCOMING sessions
    //=========================================================================

    /**
     * @brief Constructor for incoming file transfer
     * @param socket Connected TCP socket from accept()
     * @param downloadDir Directory where received files will be saved
     * @param statusCb Optional status callback
     * @param progressCb Optional progress callback
     * @param completionCb Optional completion callback
     *
     * Creates a session for receiving a file. The socket must already
     * be connected (from accept()). The session will use FileReceiver
     * internally to handle the transfer.
     */
    TransferSession(SOCKET socket,
                    const std::string& downloadDir,
                    SessionStatusCallback statusCb = nullptr,
                    SessionProgressCallback progressCb = nullptr,
                    SessionCompletionCallback completionCb = nullptr);

    //=========================================================================
    // Constructors for OUTGOING sessions
    //=========================================================================

    /**
     * @brief Constructor for outgoing file transfer
     * @param filePath Path to the file to send
     * @param peerIpAddress IP address of the peer
     * @param peerPort TCP port of the peer
     * @param sessionId Optional session ID (if empty, will generate new one)
     * @param statusCb Optional status callback
     * @param progressCb Optional progress callback
     * @param completionCb Optional completion callback
     *
     * Creates a session for sending a file. The session will connect
     * to the peer and use FileSender internally to handle the transfer.
     *
     * If sessionId is provided, it will be used instead of generating
     * a new one. This is important for GUI updates to work correctly.
     */
    TransferSession(const std::string& filePath,
                    const std::string& peerIpAddress,
                    uint16_t peerPort,
                    const std::string& sessionId = "",
                    SessionStatusCallback statusCb = nullptr,
                    SessionProgressCallback progressCb = nullptr,
                    SessionCompletionCallback completionCb = nullptr);

    /**
     * @brief Destructor
     *
     * If the session is still running, it will be cancelled.
     * The destructor waits for the worker thread to join.
     */
    ~TransferSession();

    // Prevent copying
    TransferSession(const TransferSession&) = delete;
    TransferSession& operator=(const TransferSession&) = delete;

    // Allow moving
    TransferSession(TransferSession&&) noexcept;
    TransferSession& operator=(TransferSession&&) noexcept;

    //=========================================================================
    // Session Control Methods
    //=========================================================================

    /**
     * @brief Run the transfer session
     * @return true if session started successfully
     *
     * Starts the transfer on a dedicated thread.
     * For INCOMING sessions: Uses FileReceiver to accept and receive file.
     * For OUTGOING sessions: Connects to peer and uses FileSender.
     *
     * This method returns immediately after starting the thread.
     * Use getStatus() to check progress, or wait for completion callback.
     */
    bool run();

    /**
     * @brief Cancel the transfer session
     *
     * Signals the session to cancel. If the transfer is in progress,
     * the socket will be closed to interrupt blocking operations.
     * The worker thread will exit and clean up resources.
     *
     * Thread-safe: Can be called from any thread.
     */
    void cancel();

    /**
     * @brief Run incoming transfer (FileReceiver wrapper)
     * @param socket Connected socket from accept()
     * @param errorMsg Output error message
     * @return true if successful
     *
     * This method is used by TransferServer for INCOMING sessions.
     * It must be called directly with the socket parameter, as INCOMING
     * sessions don't store the socket (it's moved from accept()).
     */
    bool runIncomingTransfer(SOCKET socket, const ExoHeader& preReceivedHeader, std::string& errorMsg);

    //=========================================================================
    // Status Query Methods
    //=========================================================================

    /**
     * @brief Get the current session status
     * @return Current status
     *
     * Thread-safe: Can be called from any thread.
     */
    SessionStatus getStatus() const { return m_status.load(); }

    /**
     * @brief Get the session type
     * @return INCOMING or OUTGOING
     */
    SessionType getType() const { return m_type; }

    /**
     * @brief Get the unique session ID
     * @return Session ID string
     */
    const std::string& getSessionId() const { return m_sessionId; }

    /**
     * @brief Get the file path
     * @return For INCOMING: destination path; for OUTGOING: source path
     */
    const std::string& getFilePath() const { return m_filePath; }

    /**
     * @brief Get the peer IP address
     * @return Peer IP address
     */
    const std::string& getPeerIpAddress() const { return m_peerIpAddress; }

    /**
     * @brief Get the peer port
     * @return Peer TCP port
     */
    uint16_t getPeerPort() const { return m_peerPort; }

    /**
     * @brief Get the number of bytes transferred
     * @return Bytes transferred (0 if not started)
     */
    uint64_t getBytesTransferred() const { return m_bytesTransferred; }

    /**
     * @brief Get the total file size
     * @return File size in bytes (0 if not known yet)
     */
    uint64_t getTotalBytes() const { return m_totalBytes; }

    /**
     * @brief Get the SHA-256 hash of the file
     * @return Hexadecimal hash string (empty if not computed yet)
     */
    const std::string& getSha256Hash() const { return m_sha256Hash; }

    /**
     * @brief Check if the session is running
     * @return true if the worker thread is active
     */
    bool isRunning() const { return m_isRunning.load(); }

    /**
     * @brief Check if the session is completed (success, failed, or cancelled)
     * @return true if the session has reached a terminal state
     */
    bool isDone() const {
        SessionStatus status = m_status.load();
        return status == SessionStatus::COMPLETED ||
               status == SessionStatus::FAILED ||
               status == SessionStatus::CANCELLED ||
               status == SessionStatus::BUSY;
    }

    /**
     * @brief Trigger the completion callback
     * @param success True if transfer succeeded
     * @param errorMessage Error message if failed (empty if success)
     *
     * This method allows external code (TransferServer) to trigger the completion
     * callback after runIncomingTransfer returns. This prevents double callback
     * issues where the callback might be called from both runIncomingTransfer
     * and the calling function.
     */
    void triggerCompletionCallback(bool success, const std::string& errorMessage);

private:
    //=========================================================================
    // Private Methods
    //=========================================================================

    /**
     * @brief Main worker thread function
     */
    void workerThreadFunc();

    /**
     * @brief Run outgoing transfer (FileSender wrapper)
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool runOutgoingTransfer(std::string& errorMsg);

    /**
     * @brief Generate a unique session ID
     * @return Unique ID string
     */
    static std::string generateSessionId();

    /**
     * @brief Set session status and call callback
     * @param status New status
     */
    void setStatus(SessionStatus status);

    //=========================================================================
    // Member Variables
    //=========================================================================

    // Identity
    std::string m_sessionId;           ///< Unique session identifier
    SessionType m_type;                ///< INCOMING or OUTGOING
    std::atomic<SessionStatus> m_status;  ///< Current session status

    // Connection info
    std::string m_filePath;            ///< Source (outgoing) or dest (incoming)
    std::string m_downloadDir;         ///< Download directory (incoming only)
    std::string m_peerIpAddress;       ///< Peer IP address
    uint16_t m_peerPort;               ///< Peer TCP port

    // Progress tracking
    std::atomic<uint64_t> m_bytesTransferred;  ///< Bytes transferred
    std::atomic<uint64_t> m_totalBytes;         ///< Total file size
    std::string m_sha256Hash;          ///< SHA-256 hash (hex string)

    // Thread management
    std::thread m_workerThread;        ///< Worker thread
    std::atomic<bool> m_isRunning;     ///< Thread is running
    std::atomic<bool> m_cancelRequested;  ///< Cancel requested

    // Callbacks
    SessionStatusCallback m_statusCallback;
    SessionProgressCallback m_progressCallback;
    SessionCompletionCallback m_completionCallback;

    // Progress throttling
    std::chrono::steady_clock::time_point m_lastProgressUpdate;
    std::mutex m_progressMutex;        ///< Protects progress throttling state

    // For OUTGOING sessions: socket created by session
    SOCKET m_outgoingSocket;           ///< Socket for outgoing connections
    bool m_ownsSocket;                 ///< Whether we need to close the socket
};

//=============================================================================
// Helper Classes
//=============================================================================

/**
 * @class ThrottledProgress
 * @brief Wraps a progress callback with throttling
 *
 * This helper class throttles progress callbacks to prevent
 * queue saturation (e.g., Qt event loop in Phase 4).
 * Callbacks are only invoked if at least PROGRESS_THROTTLE_MS
 * have elapsed since the last callback.
 */
class ThrottledProgress {
public:
    /**
     * @brief Constructor
     * @param sessionId Session ID for callbacks
     * @param callback The underlying progress callback
     */
    ThrottledProgress(const std::string& sessionId,
                      SessionProgressCallback callback);

    /**
     * @brief Call the progress callback (with throttling)
     * @param bytesTransferred Total bytes transferred so far
     * @param totalBytes Total file size
     * @param percentage Transfer percentage (0-100)
     */
    void operator()(uint64_t bytesTransferred,
                    uint64_t totalBytes,
                    double percentage);

private:
    std::string m_sessionId;
    SessionProgressCallback m_callback;
    std::chrono::steady_clock::time_point m_lastUpdate;
    std::mutex m_mutex;
};

}  // namespace ExoSend
