/**
 * @file TransferServer.h
 * @brief Multi-threaded file transfer server
 */

#pragma once

#include "config.h"
#include "TransferSession.h"
#include "PeerInfo.h"
#include <string>
#include <unordered_map>
#include <memory>
#include <thread>
#include <atomic>
#include <shared_mutex>
#include <vector>
#include <winsock2.h>
#include <future>
#include <mutex>
#include <condition_variable>
#include <cstdint>

namespace ExoSend {

//=============================================================================
// Callback Types
//=============================================================================

/**
 * @brief Session event callback function type
 *
 * Called when a session event occurs (started, completed, failed, etc.)
 *
 * @param sessionId Unique session identifier
 * @param status New session status
 */
using SessionEventCallback = std::function<void(const std::string& sessionId,
                                                 SessionStatus status)>;

/**
 * @brief Pending connection awaiting user acceptance decision
 */
struct PendingConnection {
    SOCKET socket;
    std::string clientIp;
    ExoHeader offerHeader;
    std::promise<bool> acceptPromise;

    PendingConnection(SOCKET s, const std::string& ip, const ExoHeader& header)
        : socket(s), clientIp(ip), offerHeader(header) {}
};

/**
 * @brief Incoming connection callback function type
 *
 * Called when a new incoming connection is accepted.
 * Allows the application to decide whether to accept the transfer.
 *
 * @param clientIp IP address of the connecting client
 * @param header The offer header received from the client
 * @param pendingSessionId Temporary session ID for tracking this pending connection
 * @return true to accept the transfer, false to reject
 */
using IncomingConnectionCallback = std::function<bool(const std::string& clientIp,
                                                        const ExoHeader& header,
                                                        const std::string& pendingSessionId,
                                                        const std::string& peerFingerprintSha256Hex)>;

//=============================================================================
// TransferServer Class
//=============================================================================

/**
 * @class TransferServer
 * @brief TCP server that accepts incoming file transfer connections
 *
 * This class manages a TCP listening socket that accepts incoming
 * connection requests from peers. For each accepted connection,
 * it spawns a TransferSession to handle the file transfer.
 *
 * Architecture:
 * - Single listener thread that accepts connections
 * - One cleanup thread that removes completed sessions
 * - Multiple TransferSession objects (one per active transfer)
 * - Session limit enforcement (MAX_CONCURRENT_TRANSFERS)
 *
 * Thread Safety:
 * - getActiveSessionCount() is thread-safe (atomic)
 * - getActiveSessionIds() is thread-safe (uses shared_mutex)
 * - start() and stop() are NOT thread-safe (call from same thread)
 *
 * Usage:
 * @code
 * TransferServer server(9999);
 * server.setSessionEventCallback([](const std::string& id, SessionStatus status) {
 *     std::cout << "Session " << id << " status: " << (int)status << "\n";
 * });
 *
 * if (server.start()) {
 *     // Server is running, accepting connections
 *     // ...
 *     server.stop();
 * }
 * @endcode
 */
class TransferServer {
public:
    /**
     * @brief Constructor
     * @param port TCP port to listen on (default: 9999)
     *
     * Creates a TransferServer that will listen on the specified port.
     * The server is not started until start() is called.
     */
    explicit TransferServer(uint16_t port = TCP_PORT_DEFAULT);

    /**
     * @brief Destructor
     *
     * Stops the server if running and cleans up all resources.
     */
    ~TransferServer();

    // Prevent copying
    TransferServer(const TransferServer&) = delete;
    TransferServer& operator=(const TransferServer&) = delete;

    // Prevent moving (server has unique resources)
    TransferServer(TransferServer&&) = delete;
    TransferServer& operator=(TransferServer&&) = delete;

    //=========================================================================
    // Server Control Methods
    //=========================================================================

    /**
     * @brief Start the transfer server
     * @return true if server started successfully
     *
     * Creates TCP socket, binds to configured port, and starts listening.
     * Launches listener thread and cleanup thread.
     *
     * @return true if successful, false if socket creation/bind failed
     */
    bool start();

    /**
     * @brief Stop the transfer server
     *
     * Signals all threads to stop, closes the listening socket,
     * cancels all active sessions, and waits for threads to join.
     */
    void stop();

    /**
     * @brief Check if the server is currently running
     * @return true if server is running
     */
    bool isRunning() const { return m_running.load(); }

    //=========================================================================
    // Session Query Methods
    //=========================================================================

    /**
     * @brief Get the number of active sessions
     * @return Current active session count
     *
     * Thread-safe: Can be called from any thread.
     */
    size_t getActiveSessionCount() const { return m_activeSessionCount.load(); }

    /**
     * @brief Get a list of active session IDs
     * @return Vector of session IDs
     *
     * Thread-safe: Can be called from any thread.
     * Uses shared_lock for concurrent read access.
     */
    std::vector<std::string> getActiveSessionIds() const;

    /**
     * @brief Get a session by ID
     * @param sessionId Session ID to look up
     * @return Pointer to session (or nullptr if not found)
     *
     * Thread-safe: Can be called from any thread.
     * Uses shared_lock for concurrent read access.
     *
     * Note: The pointer is valid only while the session is active.
     * Do not store the pointer across session lifecycle changes.
     */
    TransferSession* getSession(const std::string& sessionId) const;

    //=========================================================================
    // Configuration Methods
    //=========================================================================

    /**
     * @brief Set the download directory for incoming files
     * @param downloadDir Directory path
     *
     * This directory will be used for all incoming file transfers.
     */
    void setDownloadDir(const std::string& downloadDir) {
        m_downloadDir = downloadDir;
    }

    /**
     * @brief Set maximum allowed incoming offer size (bytes)
     *
     * Offers larger than this are rejected before prompting the user.
     */
    void setMaxIncomingSizeBytes(uint64_t bytes) { m_maxIncomingSizeBytes = bytes; }

    /**
     * @brief Get the download directory
     * @return Current download directory
     */
    const std::string& getDownloadDir() const { return m_downloadDir; }

    /**
     * @brief Set the session event callback
     * @param callback Function to call on session events
     *
     * The callback will be invoked when a session's status changes.
     */
    void setSessionEventCallback(SessionEventCallback callback) {
        m_sessionEventCallback = callback;
    }

    /**
     * @brief Set the incoming connection callback
     * @param callback Function to call on incoming connections
     *
     * The callback can inspect the offer header and decide whether
     * to accept or reject the incoming transfer.
     */
    void setIncomingConnectionCallback(IncomingConnectionCallback callback) {
        m_incomingConnectionCallback = callback;
    }

    /**
     * @brief Get the listening port
     * @return TCP port number
     */
    uint16_t getPort() const { return m_port; }

    /**
     * @brief Get pending transfer filename by session ID
     * @param sessionId Session ID to look up
     * @return Filename (or empty string if not found)
     *
     * This is used by MainWindow to retrieve the filename for incoming
     * transfers during the TRANSFERRING event update.
     */
    std::string getPendingFilename(const std::string& sessionId) const;

private:
    //=========================================================================
    // Private Methods
    //=========================================================================

    /**
     * @brief Listener thread function
     *
     * Runs the accept() loop, accepting incoming connections
     * and spawning TransferSession objects for each client.
     */
    void listenerThreadFunc();

    /**
     * @brief Cleanup thread function
     *
     * Periodically scans the sessions map and removes
     * completed/failed/cancelled sessions.
     */
    void cleanupThreadFunc();

    /**
     * @brief Handle a client connection
     * @param clientSocket Connected client socket
     * @param clientIp IP address of the client
     *
     * Creates a TransferSession for the incoming connection
     * and adds it to the sessions map.
     */
    void handleClient(SOCKET clientSocket, const std::string& clientIp);

    /**
     * @brief Send BUSY response to client
     * @param socket Client socket
     */
    void sendBusyResponse(SOCKET socket);

    /**
     * @brief Initialize the listening socket
     * @return true if successful
     */
    bool initializeSocket();

    /**
     * @brief Close the listening socket and cleanup
     */
    void cleanupSocket();

    /**
     * @brief Create a TransferSession for incoming transfer
     * @param socket Client socket
     * @param clientIp Client IP address
     * @return Unique pointer to new session
     */
    std::unique_ptr<TransferSession> createSession(SOCKET socket,
                                                     const std::string& clientIp);

    //=========================================================================
    // Member Variables
    //=========================================================================

    // Configuration
    uint16_t m_port;              ///< TCP listening port
    std::string m_downloadDir;    ///< Download directory for incoming files
    uint64_t m_maxIncomingSizeBytes; ///< Maximum allowed incoming offer size (bytes)

    // Socket
    SOCKET m_listenSocket;        ///< Listening socket
    bool m_socketInitialized;     ///< Whether socket needs cleanup

    // Threads
    std::thread m_listenerThread;   ///< Accepts incoming connections
    std::thread m_cleanupThread;    ///< Cleans up completed sessions

    // Sessions (thread-safe)
    mutable std::shared_mutex m_sessionsMutex;  ///< Protects m_sessions
    std::unordered_map<std::string, std::unique_ptr<TransferSession>> m_sessions;
    std::atomic<size_t> m_activeSessionCount;   ///< Fast access to count

    // Session reference tracking to prevent premature cleanup
    // Note: Prevents cleanup thread from removing sessions that have pending callbacks
    mutable std::mutex m_sessionRefCountMutex;
    std::unordered_map<std::string, int> m_sessionRefCounts;  ///< sessionId -> ref count

    // Control flags
    std::atomic<bool> m_running;        ///< Server is running
    std::atomic<bool> m_stopRequested;  ///< Request threads to stop
    std::condition_variable m_cleanupCv; ///< Wakes cleanup thread during shutdown
    std::mutex m_cleanupCvMutex;         ///< Protects m_cleanupCv wait

    // Callbacks
    SessionEventCallback m_sessionEventCallback;
    IncomingConnectionCallback m_incomingConnectionCallback;

    // Pending transfer info (thread-safe)
    // Stores filename for each session before TransferSession is created
    // This allows MainWindow to retrieve the filename during TRANSFERRING event
    mutable std::mutex m_pendingTransfersMutex;
    std::unordered_map<std::string, std::string> m_pendingFilenames;  // sessionId -> filename

    // Pending connections (thread-safe)
    // Stores connections awaiting user acceptance decision
    mutable std::mutex m_pendingConnectionsMutex;
    std::unordered_map<std::string, std::unique_ptr<PendingConnection>> m_pendingConnections;  // tempSessionId -> PendingConnection
};

}  // namespace ExoSend
