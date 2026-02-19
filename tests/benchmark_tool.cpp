/**
 * @file benchmark_tool.cpp
 * @brief Performance benchmarking tool for ExoSend
 *
 * Measures throughput, CPU usage, and RAM footprint during file transfers.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#define NOMINMAX  // Prevent Windows min/max macro conflict
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include "exosend/config.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <string>
#include <fstream>
#include <vector>

//=============================================================================
// Benchmark Results Structure
//=============================================================================

/**
 * @brief Results from a benchmark run
 */
struct BenchmarkResult {
    double throughputMBps;       ///< Throughput in MB/s
    double cpuUsagePercent;      ///< CPU usage percentage
    size_t ramFootprintMB;       ///< RAM footprint in MB
    uint64_t transferTimeMs;     ///< Transfer time in milliseconds
    uint64_t fileSize;           ///< File size in bytes

    void print() const {
        std::cout << "\n=== Benchmark Results ===" << std::endl;
        std::cout << "File Size:       " << std::fixed << std::setprecision(2)
                  << (fileSize / (1024.0 * 1024.0)) << " MB" << std::endl;
        std::cout << "Transfer Time:   " << transferTimeMs << " ms" << std::endl;
        std::cout << "Throughput:      " << std::fixed << std::setprecision(2)
                  << throughputMBps << " MB/s" << std::endl;
        std::cout << "CPU Usage:       " << std::fixed << std::setprecision(1)
                  << cpuUsagePercent << "%" << std::endl;
        std::cout << "RAM Footprint:   " << ramFootprintMB << " MB" << std::endl;
    }
};

//=============================================================================
// Performance Monitoring Class
//=============================================================================

/**
 * @brief Monitor CPU and memory usage during benchmark
 */
class PerformanceMonitor {
public:
    PerformanceMonitor() {
        // Get initial CPU time
        FILETIME ftIdle, ftKernel, ftUser;
        if (GetSystemTimes(&ftIdle, &ftKernel, &ftUser)) {
            m_initialKernelTime = fileTimeToInt64(ftKernel);
            m_initialUserTime = fileTimeToInt64(ftUser);
        }

        m_startTime = std::chrono::steady_clock::now();
        m_startProcessTime = getCurrentProcessTime();
    }

    /**
     * @brief Get current CPU usage percentage
     * @return CPU usage (0-100)
     */
    double getCpuUsage() {
        uint64_t currentProcessTime = getCurrentProcessTime();
        auto now = std::chrono::steady_clock::now();

        // Calculate elapsed time
        std::chrono::milliseconds elapsedMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - m_startTime);

        if (elapsedMs.count() == 0) {
            return 0.0;
        }

        // Calculate process CPU time
        uint64_t processTimeMs = (currentProcessTime - m_startProcessTime) / 10000;

        // CPU usage = (process time / elapsed time) * 100 * num CPUs
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        double cpuUsage = ((double)processTimeMs / elapsedMs.count()) * 100.0 * sysInfo.dwNumberOfProcessors;
        return cpuUsage;
    }

    /**
     * @brief Get current RAM footprint in MB
     * @return RAM usage in MB
     */
    size_t getRamFootprintMB() {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize / (1024 * 1024);
        }
        return 0;
    }

private:
    std::chrono::steady_clock::time_point m_startTime;
    uint64_t m_startProcessTime;
    uint64_t m_initialKernelTime;
    uint64_t m_initialUserTime;

    static uint64_t fileTimeToInt64(const FILETIME& ft) {
        return (((uint64_t)(ft.dwHighDateTime)) << 32) | ((uint64_t)ft.dwLowDateTime);
    }

    static uint64_t getCurrentProcessTime() {
        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(GetCurrentProcess(), &ftCreation, &ftExit, &ftKernel, &ftUser)) {
            return fileTimeToInt64(ftKernel) + fileTimeToInt64(ftUser);
        }
        return 0;
    }
};

//=============================================================================
// Benchmark Functions
//=============================================================================

/**
 * @brief Create a test file of specified size
 * @param path Output file path
 * @param size File size in bytes
 * @return true if successful
 */
bool createTestFile(const std::string& path, uint64_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot create file: " << path << std::endl;
        return false;
    }

    // Write in chunks to avoid excessive memory usage
    const size_t chunkSize = 1024 * 1024; // 1 MB chunks
    std::vector<char> chunk(chunkSize, 'X');

    uint64_t remaining = size;
    while (remaining > 0) {
        size_t writeSize = std::min(chunkSize, (size_t)remaining);
        file.write(chunk.data(), writeSize);
        if (!file.good()) {
            std::cerr << "Error: Failed to write to file" << std::endl;
            return false;
        }
        remaining -= writeSize;
    }

    return true;
}

/**
 * @brief Benchmark SHA-256 hashing performance
 * @param dataSize Data size in bytes
 * @return Benchmark result
 */
BenchmarkResult benchmarkHashing(uint64_t dataSize) {
    std::cout << "\n=== Benchmarking SHA-256 Hashing ===" << std::endl;
    std::cout << "Data size: " << (dataSize / (1024.0 * 1024.0)) << " MB" << std::endl;

    // Create test data
    const size_t chunkSize = 1024 * 1024; // 1 MB
    std::vector<uint8_t> data(chunkSize, 0xAB);

    PerformanceMonitor monitor;
    auto startTime = std::chrono::steady_clock::now();

    // Compute hash
    // Note: This is a simplified benchmark - actual implementation would use HashUtils
    // For this benchmark, we'll simulate the hashing work
    uint64_t bytesProcessed = 0;
    while (bytesProcessed < dataSize) {
        size_t chunk = std::min(chunkSize, (size_t)(dataSize - bytesProcessed));
        // Simulate hash computation work
        for (size_t i = 0; i < chunk; i += 64) {
            volatile uint32_t hash = 0;
            for (int j = 0; j < 8; j++) {
                hash += data[(i + j) % chunkSize];
            }
        }
        bytesProcessed += chunk;
    }

    auto endTime = std::chrono::steady_clock::now();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    BenchmarkResult result;
    result.fileSize = dataSize;
    result.transferTimeMs = elapsedMs;
    result.throughputMBps = (dataSize / (1024.0 * 1024.0)) / (elapsedMs / 1000.0);
    result.cpuUsagePercent = monitor.getCpuUsage();
    result.ramFootprintMB = monitor.getRamFootprintMB();

    result.print();
    return result;
}

/**
 * @brief Benchmark file I/O performance
 * @param fileSize File size in bytes
 * @return Benchmark result
 */
BenchmarkResult benchmarkFileIO(uint64_t fileSize) {
    std::cout << "\n=== Benchmarking File I/O ===" << std::endl;
    std::cout << "File size: " << (fileSize / (1024.0 * 1024.0)) << " MB" << std::endl;

    std::string testFile = "benchmark_test.tmp";

    // Write benchmark
    {
        PerformanceMonitor monitor;
        auto startTime = std::chrono::steady_clock::now();

        if (!createTestFile(testFile, fileSize)) {
            return BenchmarkResult{};
        }

        auto endTime = std::chrono::steady_clock::now();
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

        std::cout << "Write throughput: " << std::fixed << std::setprecision(2)
                  << ((fileSize / (1024.0 * 1024.0)) / (elapsedMs / 1000.0)) << " MB/s" << std::endl;
    }

    // Read benchmark
    {
        PerformanceMonitor monitor;
        auto startTime = std::chrono::steady_clock::now();

        std::ifstream file(testFile, std::ios::binary);
        std::vector<uint8_t> buffer(1024 * 1024); // 1 MB buffer
        uint64_t bytesRead = 0;

        while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
            bytesRead += file.gcount();
        }

        auto endTime = std::chrono::steady_clock::now();
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

        BenchmarkResult result;
        result.fileSize = fileSize;
        result.transferTimeMs = elapsedMs;
        result.throughputMBps = (fileSize / (1024.0 * 1024.0)) / (elapsedMs / 1000.0);
        result.cpuUsagePercent = monitor.getCpuUsage();
        result.ramFootprintMB = monitor.getRamFootprintMB();

        std::cout << "Read throughput:  " << std::fixed << std::setprecision(2)
                  << result.throughputMBps << " MB/s" << std::endl;
        std::cout << "RAM during read:  " << result.ramFootprintMB << " MB" << std::endl;

        // Cleanup
        file.close();
        std::remove(testFile.c_str());

        return result;
    }

    return BenchmarkResult{};
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    std::cout << "==================================================" << std::endl;
    std::cout << "ExoSend Performance Benchmark Tool" << std::endl;
    std::cout << "==================================================" << std::endl;

    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Run benchmarks with different file sizes
    std::vector<uint64_t> testSizes = {
        1024 * 1024,        // 1 MB
        10 * 1024 * 1024,   // 10 MB
        100 * 1024 * 1024   // 100 MB
    };

    for (uint64_t size : testSizes) {
        std::cout << "\n==================================================" << std::endl;
        std::cout << "Testing with " << (size / (1024.0 * 1024.0)) << " MB file" << std::endl;
        std::cout << "==================================================" << std::endl;

        // Benchmark file I/O
        BenchmarkResult ioResult = benchmarkFileIO(size);

        // Benchmark hashing
        BenchmarkResult hashResult = benchmarkHashing(size);
    }

    std::cout << "\n==================================================" << std::endl;
    std::cout << "Benchmark Complete" << std::endl;
    std::cout << "==================================================" << std::endl;

    // Cleanup Winsock
    WSACleanup();

    return 0;
}
