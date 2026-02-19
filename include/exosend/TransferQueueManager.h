/**
 * @file TransferQueueManager.h
 * @brief Queued file transfer management with worker threads
 */

#pragma once

#include "config.h"
#include "TransferSession.h"
#include "PeerInfo.h"
#include <string>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

namespace ExoSend {

//=============================================================================
// TransferRequest Structure
//=============================================================================

/**
 * @struct TransferRequest
 * @brief Represents a pending outgoing transfer request
 *
 * This structure contains all the information needed to initiate
 * an outgoing file transfer to a peer.
 */
struct TransferRequest {
    std::string filePath;         ///< Path to the file to send
    std::string peerUuid;         ///< UUID of the target peer
    std::string peerIpAddress;    ///< IP address of the target peer
    uint16_t peerPort;            ///< TCP port of the target peer
    uint8_t priority;             ///< Priority level (0=low, 1=normal, 2=high)
    std::string requestId;        ///< Unique request identifier

    /**
     * @brief Default constructor
     */
    TransferRequest()
        : peerPort(0)
        , priority(1)  // Default to normal priority
    {
    }

    /**
     * @brief Constructor with parameters
     */
    TransferRequest(const std::string& file,
                    const std::string& uuid,
                    const std::string& ip,
                    uint16_t port,
                    uint8_t prio = 1)
        : filePath(file)
        , peerUuid(uuid)
        , peerIpAddress(ip)
        , peerPort(port)
        , priority(prio)
    {
    }
};

//=============================================================================
// Comparison for Priority Queue
//=============================================================================

/**
 * @brief Compare two transfer requests by priority (higher first)
 */
struct TransferRequestCompare {
    bool operator()(const TransferRequest& a, const TransferRequest& b) const {
        return a.priority < b.priority;  // Lower value = lower priority
    }
};

//=============================================================================
// Callback Types
//=============================================================================

/**
 * @brief Request completion callback
 *
 * Called when a transfer request completes (success or failure)
 *
 * @param requestId Unique request identifier
 * @param success True if transfer succeeded
 * @param sessionId Session ID (for tracking)
 * @param errorMessage Error message if failed
 */
using RequestCompletionCallback = std::function<void(
    const std::string& requestId,
    bool success,
    const std::string& sessionId,
    const std::string& errorMessage
)>;

//=============================================================================
// TransferQueueManager Class
//=============================================================================

/**
 * @class TransferQueueManager
 * @brief Manages outgoing transfer queue with bounded concurrency
 *
 * This class manages a queue of outgoing file transfer requests and
 * processes them with a configurable maximum concurrency limit.
 *
 * Architecture:
 * - Worker thread pool (size = maxConcurrent)
 * - Priority queue for requests
 * - Bounded concurrency using semaphore pattern
 * - Thread-safe queue operations
 *
 * Thread Safety:
 * - enqueue() and cancel() are thread-safe
 * - getQueueSize() and getActiveCount() are thread-safe
 * - start() and stop() are NOT thread-safe
 *
 * Usage:
 * @code
 * TransferQueueManager queue(3);  // Max 3 concurrent transfers
 * queue.setCompletionCallback([](const std::string& id, bool success, ...) {
 *     std::cout << "Request " << id << " completed: " << success << "\n";
 * });
 *
 * if (queue.start()) {
 *     // Enqueue some transfers
 *     std::string reqId1 = queue.enqueue(request1);
 *     std::string reqId2 = queue.enqueue(request2);
 *
 *     // ...
 *
 *     queue.stop();
 * }
 * @endcode
 */
class TransferQueueManager {
public:
    /**
     * @brief Constructor
     * @param maxConcurrent Maximum number of concurrent transfers
     *
     * Creates a queue manager with the specified concurrency limit.
     * The manager is not started until start() is called.
     */
    explicit TransferQueueManager(size_t maxConcurrent = MAX_CONCURRENT_TRANSFERS);

    /**
     * @brief Destructor
     *
     * Stops the queue manager if running and cleans up all resources.
     */
    ~TransferQueueManager();

    // Prevent copying
    TransferQueueManager(const TransferQueueManager&) = delete;
    TransferQueueManager& operator=(const TransferQueueManager&) = delete;

    // Prevent moving
    TransferQueueManager(TransferQueueManager&&) = delete;
    TransferQueueManager& operator=(TransferQueueManager&&) = delete;

    //=========================================================================
    // Queue Manager Control Methods
    //=========================================================================

    /**
     * @brief Start the queue manager
     * @return true if started successfully
     *
     * Spawns worker threads and begins processing queued requests.
     */
    bool start();

    /**
     * @brief Stop the queue manager
     *
     * Signals all workers to stop, waits for threads to join,
     * and cancels all active transfers.
     */
    void stop();

    /**
     * @brief Check if the queue manager is running
     * @return true if running
     */
    bool isRunning() const { return m_running.load(); }

    //=========================================================================
    // Queue Operations
    //=========================================================================

    /**
     * @brief Enqueue a transfer request
     * @param request The transfer request
     * @return Unique request ID (empty if failed)
     *
     * Adds the request to the queue and notifies a worker thread.
     * Thread-safe: Can be called from any thread.
     */
    std::string enqueue(const TransferRequest& request);

    /**
     * @brief Cancel a queued or active request
     * @param requestId Request ID to cancel
     * @return true if request was cancelled
     *
     * If the request is still queued, it will be removed.
     * If the request is active, the transfer session will be cancelled.
     * Thread-safe: Can be called from any thread.
     */
    bool cancel(const std::string& requestId);

    //=========================================================================
    // Query Methods
    //=========================================================================

    /**
     * @brief Get the current queue size (pending requests)
     * @return Number of requests waiting to be processed
     *
     * Thread-safe: Can be called from any thread.
     */
    size_t getQueueSize() const;

    /**
     * @brief Get the number of active transfers
     * @return Current number of active transfers
     *
     * Thread-safe: Can be called from any thread.
     */
    size_t getActiveCount() const { return m_activeCount.load(); }

    //=========================================================================
    // Configuration Methods
    //=========================================================================

    /**
     * @brief Set the completion callback
     * @param callback Function to call on request completion
     */
    void setCompletionCallback(RequestCompletionCallback callback) {
        m_completionCallback = callback;
    }

    /**
     * @brief Set the download directory for incoming files (not used by queue)
     * @param downloadDir Directory path
     *
     * Note: This is for future use when queue handles bidirectional transfers.
     * Currently, the queue only handles outgoing transfers.
     */
    void setDownloadDir(const std::string& downloadDir) {
        m_downloadDir = downloadDir;
    }

    /**
     * @brief Set status callback for session events
     * @param callback Function to call when session status changes
     *
     * This callback will be forwarded to all outgoing sessions created
     * by the queue manager, allowing GUI updates for transfer progress.
     */
    void setStatusCallback(SessionStatusCallback callback) {
        m_statusCallback = std::move(callback);
    }

    /**
     * @brief Set progress callback for transfer progress
     * @param callback Function to call when transfer progress updates
     */
    void setProgressCallback(SessionProgressCallback callback) {
        m_progressCallback = std::move(callback);
    }

private:
    //=========================================================================
    // Private Methods
    //=========================================================================

    /**
     * @brief Worker thread function
     * @param workerIndex Index of this worker (0-based)
     *
     * Each worker thread waits for requests in the queue and processes them.
     * When a request is dequeued, the worker checks the concurrency limit
     * and either processes the request or re-queues it.
     */
    void workerThreadFunc(size_t workerIndex);

    /**
     * @brief Process a transfer request
     * @param request The request to process
     * @return true if transfer succeeded
     *
     * Creates a TransferSession and runs the outgoing transfer.
     */
    bool processRequest(const TransferRequest& request);

    /**
     * @brief Generate a unique request ID
     * @return Unique ID string
     */
    static std::string generateRequestId();

    /**
     * @brief Remove a request from the queue by ID
     * @param requestId Request ID to remove
     * @return true if found and removed
     *
     * Must be called with m_queueMutex locked.
     */
    bool removeFromQueue(const std::string& requestId);

    /**
     * @brief Check if a request has been cancelled
     * @param requestId Request ID to check
     * @return true if request was cancelled
     *
     * Thread-safe: Can be called from any thread.
     */
    bool isCancelled(const std::string& requestId) const;

    //=========================================================================
    // Member Variables
    //=========================================================================

    // Queue configuration
    size_t m_maxConcurrent;        ///< Maximum concurrent transfers

    // Priority queue for efficient transfer ordering by priority
    std::priority_queue<TransferRequest, std::vector<TransferRequest>,
                       TransferRequestCompare> m_queue;

    // Track cancelled requests for O(1) cancellation check
    std::unordered_set<std::string> m_cancelledRequests;

    // Active transfers
    std::unordered_map<std::string, std::unique_ptr<TransferSession>> m_activeSessions;
    std::unordered_map<std::string, TransferRequest> m_activeRequests;

    // Thread safety
    mutable std::mutex m_queueMutex;    ///< Protects queue and active maps
    std::condition_variable m_queueCV;  ///< Notifies workers of new requests

    // Worker threads
    std::vector<std::thread> m_workerThreads;

    // Control flags
    std::atomic<bool> m_running;        ///< Queue manager is running
    std::atomic<bool> m_stopRequested;  ///< Request workers to stop
    std::atomic<size_t> m_activeCount;  ///< Current active transfer count

    // Configuration
    std::string m_downloadDir;          ///< Download directory (for future use)

    // Session event callbacks (for GUI updates)
    SessionStatusCallback m_statusCallback;
    SessionProgressCallback m_progressCallback;

    // Callbacks
    RequestCompletionCallback m_completionCallback;
};

}  // namespace ExoSend
