/**
 * @file queue_manager_test.cpp
 * @brief Unit tests for TransferQueueManager concurrency and completion accounting
 */

#include "exosend/TransferQueueManager.h"
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

using namespace ExoSend;

TEST(TransferQueueManagerTest, ConcurrencyIsBoundedAndCompletionHasSessionId) {
    std::atomic<int> currentActive{0};
    std::atomic<int> maxActive{0};

    auto runner = [&](const TransferRequest& request, std::string& sessionId, std::string& error) -> bool {
        (void)error;

        const int now = currentActive.fetch_add(1) + 1;
        int prevMax = maxActive.load();
        while (now > prevMax && !maxActive.compare_exchange_weak(prevMax, now)) {
        }

        sessionId = "sess_" + request.requestId;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        currentActive.fetch_sub(1);
        return true;
    };

    TransferQueueManager queue(2, runner);

    std::mutex doneMutex;
    std::condition_variable doneCv;
    int completed = 0;

    queue.setCompletionCallback([&](const std::string& requestId,
                                    bool success,
                                    const std::string& sessionId,
                                    const std::string& errorMessage) {
        (void)requestId;
        (void)errorMessage;
        EXPECT_TRUE(success);
        EXPECT_FALSE(sessionId.empty());
        std::lock_guard<std::mutex> lock(doneMutex);
        completed++;
        doneCv.notify_one();
    });

    ASSERT_TRUE(queue.start());

    constexpr int kRequests = 10;
    for (int i = 0; i < kRequests; ++i) {
        TransferRequest req;
        req.filePath = "dummy";
        req.peerUuid = "peer";
        req.peerIpAddress = "127.0.0.1";
        req.peerPort = 9999;
        req.priority = 1;
        const std::string id = queue.enqueue(req);
        EXPECT_FALSE(id.empty());
    }

    {
        std::unique_lock<std::mutex> lock(doneMutex);
        const bool allDone = doneCv.wait_for(lock, std::chrono::seconds(10), [&] { return completed == kRequests; });
        EXPECT_TRUE(allDone);
    }

    queue.stop();

    EXPECT_LE(maxActive.load(), 2);
}

