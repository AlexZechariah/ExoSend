/**
 * @file TransferQueueManager.cpp
 * @brief Queued file transfer management with worker threads
 */

#include "exosend/TransferQueueManager.h"
#include "exosend/UuidGenerator.h"
#include <iostream>
#include <algorithm>

namespace ExoSend {

//=============================================================================
// Constructor / Destructor
//=============================================================================

/**
 * @brief Construct queue manager
 * @param maxConcurrent Maximum concurrent transfers
 */
TransferQueueManager::TransferQueueManager(size_t maxConcurrent, RequestRunner runner)
    : m_maxConcurrent(maxConcurrent)
    , m_running(false)
    , m_stopRequested(false)
    , m_activeCount(0)
    , m_downloadDir(".")
    , m_localDeviceUuid()
    , m_completionCallback(nullptr)
    , m_requestRunner(std::move(runner))
{
}

//=============================================================================
// Helper Functions
//=============================================================================

/**
 * @brief Generate unique request ID
 * @return Random request ID string with "req_" prefix
 */
std::string TransferQueueManager::generateRequestId() {
    // Delegate to centralized UUID generator with prefix
    return UuidGenerator::generateWithPrefix("req_");
}

//=============================================================================
// Destructor
//=============================================================================

TransferQueueManager::~TransferQueueManager() {
    // Stop queue manager if running
    if (m_running.load()) {
        stop();
    }
}

//=============================================================================
// TransferQueueManager: start()
//=============================================================================

bool TransferQueueManager::start() {
    // Check if already running
    if (m_running.load()) {
        return false;
    }

    // Reset flags
    m_stopRequested.store(false);
    m_running.store(true);

    // Spawn worker threads
    m_workerThreads.reserve(m_maxConcurrent);
    for (size_t i = 0; i < m_maxConcurrent; ++i) {
        m_workerThreads.emplace_back(&TransferQueueManager::workerThreadFunc, this, i);
    }

    return true;
}

//=============================================================================
// TransferQueueManager: stop()
//=============================================================================

void TransferQueueManager::stop() {
    // Check if running
    if (!m_running.load()) {
        return;
    }

    // Signal workers to stop
    m_stopRequested.store(true);

    // Notify all workers
    m_queueCV.notify_all();

    // Cancel all active sessions
    std::unordered_map<std::string, std::unique_ptr<TransferSession>> sessionsToDestroy;
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        for (auto& pair : m_activeSessions) {
            if (pair.second) {
                pair.second->cancel();
            }
        }
        sessionsToDestroy.swap(m_activeSessions);
        m_activeRequests.clear();
        m_activeCount.store(0);
    }

    // Wait for worker threads
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_workerThreads.clear();

    // Clear queue
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        while (!m_queue.empty()) {
            m_queue.pop();
        }
        m_cancelledRequests.clear();
    }

    // Mark as not running
    m_running.store(false);
}

//=============================================================================
// TransferQueueManager: enqueue()
//=============================================================================

std::string TransferQueueManager::enqueue(const TransferRequest& request) {
    // Generate unique request ID
    std::string requestId = generateRequestId();

    // Create request with ID
    TransferRequest req = request;
    req.requestId = requestId;

    // Add to queue
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_queue.push(req);
    }

    // Notify one worker
    m_queueCV.notify_one();

    return requestId;
}

//=============================================================================
// TransferQueueManager: cancel()
//=============================================================================

bool TransferQueueManager::cancel(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(m_queueMutex);

    // First, try to remove from queue
    if (removeFromQueue(requestId)) {
        return true;
    }

    // If not in queue, check active sessions
    auto it = m_activeSessions.find(requestId);
    if (it != m_activeSessions.end() && it->second) {
        // Cancel the session
        it->second->cancel();
        return true;
    }

    return false;
}

//=============================================================================
// TransferQueueManager: getQueueSize()
//=============================================================================

size_t TransferQueueManager::getQueueSize() const {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    return m_queue.size();
}

//=============================================================================
// TransferQueueManager: workerThreadFunc()
//=============================================================================

void TransferQueueManager::workerThreadFunc(size_t workerIndex) {
    (void)workerIndex;  // Unused parameter

    while (!m_stopRequested.load()) {
        TransferRequest request;

        // Wait for request
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // Wait for queue to have items or stop requested
            m_queueCV.wait(lock, [&] {
                return !m_queue.empty() || m_stopRequested.load();
            });

            // Check if we're stopping
            if (m_stopRequested.load()) {
                break;
            }

            // Get request from queue
            if (m_queue.empty()) {
                continue;
            }

            request = m_queue.top();
            m_queue.pop();

            // Check if request was cancelled
            if (isCancelled(request.requestId)) {
                m_cancelledRequests.erase(request.requestId);
                continue;
            }

            // Increment active count
            m_activeCount.fetch_add(1);

            // Add to active requests map
            m_activeRequests[request.requestId] = request;
        }

        // Process the request (outside lock)
        std::string sessionId;
        std::string requestError;
        bool success = processRequest(request, sessionId, requestError);

        // Update active count
        m_activeCount.fetch_sub(1);

        // Remove from active map
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_activeRequests.erase(request.requestId);
        }

        // Notify completion callback
        if (m_completionCallback) {
            m_completionCallback(request.requestId, success, sessionId, requestError);
        }

        // Notify next worker (there might be room now)
        m_queueCV.notify_one();
    }
}

//=============================================================================
// TransferQueueManager: processRequest()
//=============================================================================

bool TransferQueueManager::processRequest(const TransferRequest& request, std::string& sessionId, std::string& errorMessage) {
    auto errorMsg = std::make_shared<std::string>();

    try {
        if (m_requestRunner) {
            std::string runnerError;
            const bool ok = m_requestRunner(request, sessionId, runnerError);
            if (!ok) {
                *errorMsg = runnerError;
            }
            errorMessage = *errorMsg;
            return ok;
        }

        std::mutex doneMutex;
        std::condition_variable doneCv;
        bool done = false;
        bool ok = false;
        std::string completionError;

        // Create OUTGOING TransferSession
        auto session = std::make_unique<TransferSession>(
            request.filePath,
            request.peerIpAddress,
            request.peerPort,
            // Use requestId as sessionId to ensure GUI updates work
            request.requestId,
            // Status callback - forward to GUI
            m_statusCallback,
            // Progress callback - forward to GUI
            m_progressCallback,
            // Completion callback
            [errorMsg, &doneMutex, &doneCv, &done, &ok, &sessionId, &completionError](
                const std::string& completedSessionId, bool success, const std::string& error) {
                if (!success) {
                    *errorMsg = error;
                }

                {
                    std::lock_guard<std::mutex> lock(doneMutex);
                    done = true;
                    ok = success;
                    sessionId = completedSessionId;
                    completionError = error;
                }
                doneCv.notify_one();
            }
        );

        session->setRequireTls(true);
        session->setLocalDeviceUuid(m_localDeviceUuid);
        session->setPeerIdentity(request.peerUuid, request.peerPinnedFingerprintSha256Hex);

        sessionId = session->getSessionId();

        // Add to active sessions map (for cancellation)
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_activeSessions[request.requestId] = std::move(session);
        }

        // Get session pointer
        TransferSession* sessionPtr = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            auto it = m_activeSessions.find(request.requestId);
            if (it != m_activeSessions.end()) {
                sessionPtr = it->second.get();
            }
        }

        if (!sessionPtr) {
            errorMessage = "Failed to resolve active session pointer";
            return false;
        }

        // Start the transfer
        if (!sessionPtr->run()) {
            completionError = "Failed to start transfer session";
            *errorMsg = completionError;
            errorMessage = *errorMsg;
            return false;
        }

        // Wait for completion
        {
            std::unique_lock<std::mutex> lock(doneMutex);
            doneCv.wait(lock, [&] { return done || m_stopRequested.load(); });
        }

        // Remove from active sessions map after completion
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_activeSessions.erase(request.requestId);
        }

        errorMessage = completionError.empty() ? *errorMsg : completionError;
        return ok;

    } catch (const std::exception& e) {
        *errorMsg = e.what();
        errorMessage = *errorMsg;
        return false;
    } catch (...) {
        *errorMsg = "Unknown exception";
        errorMessage = *errorMsg;
        return false;
    }
}

//=============================================================================
// TransferQueueManager: removeFromQueue()
//=============================================================================

bool TransferQueueManager::removeFromQueue(const std::string& requestId) {
    // O(1) cancellation: Add to cancelled set for worker to skip
    // The actual removal happens when worker pops the request
    m_cancelledRequests.insert(requestId);
    return true;
}

bool TransferQueueManager::isCancelled(const std::string& requestId) const {
    return m_cancelledRequests.count(requestId) > 0;
}

}  // namespace ExoSend
