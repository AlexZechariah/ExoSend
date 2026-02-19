/**
 * @file file_receive_test.cpp
 * @brief CLI tool to test receiving files over ExoSend protocol
 *
 * Usage:
 *   file_receive_test.exe <port> <download_dir>
 *
 * Example:
 *   file_receive_test.exe 9999 C:\\Users\\Alex\\Downloads
 */

#include "exosend/FileTransfer.h"
#include "exosend/config.h"

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <csignal>
#include <algorithm>
#include <sstream>
#include <ws2tcpip.h>

// Undefine Windows macros that conflict with std::left, std::right, etc.
#ifdef left
#undef left
#endif
#ifdef right
#undef right
#endif

using namespace ExoSend;

// Global flag for graceful shutdown
static volatile bool g_running = true;

/**
 * @brief Signal handler for Ctrl+C
 */
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n\nShutdown signal received. Stopping server...\n";
        g_running = false;
    }
}

/**
 * @brief Print usage information
 */
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <port> <download_dir>\n";
    std::cout << "\nArguments:\n";
    std::cout << "  port         TCP port to listen on (e.g., 9999)\n";
    std::cout << "  download_dir Directory where received files will be saved\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << programName << " 9999 C:\\Users\\Alex\\Downloads\n";
}

/**
 * @brief Format bytes to human-readable string
 */
std::string formatBytes(uint64_t bytes) {
    const double KB = 1024.0;
    const double MB = 1024.0 * 1024.0;
    const double GB = 1024.0 * 1024.0 * 1024.0;

    std::ostringstream oss;
    if (bytes >= GB) {
        oss << std::fixed << std::setprecision(2) << (bytes / GB) << " GB";
    } else if (bytes >= MB) {
        oss << std::fixed << std::setprecision(2) << (bytes / MB) << " MB";
    } else if (bytes >= KB) {
        oss << std::fixed << std::setprecision(2) << (bytes / KB) << " KB";
    } else {
        oss << bytes << " bytes";
    }
    return oss.str();
}

/**
 * @brief Format speed to human-readable string
 */
std::string formatSpeed(double bytesPerSecond) {
    const double KB = 1024.0;
    const double MB = 1024.0 * 1024.0;
    const double GB = 1024.0 * 1024.0 * 1024.0;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytesPerSecond >= GB) {
        oss << (bytesPerSecond / GB) << " GB/s";
    } else if (bytesPerSecond >= MB) {
        oss << (bytesPerSecond / MB) << " MB/s";
    } else if (bytesPerSecond >= KB) {
        oss << (bytesPerSecond / KB) << " KB/s";
    } else {
        oss << bytesPerSecond << " bytes/s";
    }
    return oss.str();
}

/**
 * @brief Prompt user for accept/reject decision
 */
bool promptUser(const ExoHeader& header) {
    std::cout << "\n===========================================\n";
    std::cout << "Incoming File Transfer Request\n";
    std::cout << "===========================================\n";
    std::cout << "  File Name: " << header.getFilename() << "\n";
    std::cout << "  File Size: " << header.getFileSizeString() << "\n";
    std::cout << "  SHA-256:   (will be computed during transfer)\n";
    std::cout << "\n";

    while (true) {
        std::cout << "Accept this file? (y/n): ";
        std::string response;
        std::getline(std::cin, response);

        // Convert to lowercase
        std::transform(response.begin(), response.end(),
                       response.begin(), ::tolower);

        if (response == "y" || response == "yes") {
            return true;
        } else if (response == "n" || response == "no") {
            return false;
        }

        std::cout << "Please enter 'y' or 'n'.\n";
    }
}

int main(int argc, char* argv[]) {
    std::cout << "===========================================\n";
    std::cout << "ExoSend File Receive Test (Phase 2)\n";
    std::cout << "===========================================\n\n";

    // Parse command-line arguments
    if (argc != 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string portStr = argv[1];
    std::string downloadDir = argv[2];

    // Parse port
    uint16_t port = 0;
    try {
        port = static_cast<uint16_t>(std::stoul(portStr));
    } catch (...) {
        std::cerr << "Error: Invalid port number: " << portStr << "\n";
        return 1;
    }

    std::cout << "Configuration:\n";
    std::cout << "  Listen Port:   " << port << "\n";
    std::cout << "  Download Dir:  " << downloadDir << "\n\n";

    // Set up signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error: WSAStartup failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    // Create socket
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        std::cerr << "Error: socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    // Allow address reuse
    int reuseAddr = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuseAddr), sizeof(reuseAddr));

    // Bind socket
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&serverAddr),
             sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error: bind() failed: " << WSAGetLastError() << "\n";
        std::cerr << "Make sure port " << port << " is not already in use.\n";
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    // Listen for connections
    if (listen(listenSock, SOMAXCONN_VALUE) == SOCKET_ERROR) {
        std::cerr << "Error: listen() failed: " << WSAGetLastError() << "\n";
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    std::cout << "Server started on port " << port << "\n";
    std::cout << "Waiting for incoming connections...\n";
    std::cout << "(Press Ctrl+C to stop)\n\n";

    // Accept connection loop
    while (g_running) {
        // Set socket to non-blocking mode for checking g_running
        u_long mode = 1;  // Non-blocking
        ioctlsocket(listenSock, FIONBIO, &mode);

        // Try to accept connection (non-blocking)
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock,
                                    reinterpret_cast<sockaddr*>(&clientAddr),
                                    &clientAddrLen);

        if (clientSock == INVALID_SOCKET) {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                // No connection pending, wait a bit
                Sleep(100);
                continue;
            } else {
                std::cerr << "Error: accept() failed: " << error << "\n";
                break;
            }
        }

        // Connection accepted!
        // Set back to blocking mode
        mode = 0;  // Blocking
        ioctlsocket(clientSock, FIONBIO, &mode);

        // Get client IP address
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));

        std::cout << "\n===========================================\n";
        std::cout << "Connection received from: " << clientIP << ":"
                  << ntohs(clientAddr.sin_port) << "\n";
        std::cout << "===========================================\n\n";

        // Create file receiver
        FileReceiver receiver(downloadDir);

        // Variables for progress tracking
        auto startTime = std::chrono::steady_clock::now();
        uint64_t lastProgressUpdate = 0;

        // Progress callback
        auto progressCallback = [&](uint64_t bytesTransferred, uint64_t totalBytes,
                                    double percentage) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - startTime).count();

            // Update display every ~100ms
            if (elapsed - lastProgressUpdate >= 100 || bytesTransferred == totalBytes) {
                lastProgressUpdate = elapsed;

                // Calculate speed
                double speed = (elapsed > 0) ?
                    (static_cast<double>(bytesTransferred) / (elapsed / 1000.0)) : 0.0;

                // Calculate ETA
                uint64_t remaining = totalBytes - bytesTransferred;
                int etaSeconds = (speed > 0) ?
                    static_cast<int>(remaining / speed) : 0;

                // Print progress
                std::cout << "\r[";
                int barWidth = 40;
                int filled = static_cast<int>(barWidth * percentage / 100.0);
                for (int i = 0; i < barWidth; ++i) {
                    std::cout << (i < filled ? "=" : " ");
                }
                std::cout << "] " << std::fixed << std::setprecision(1) << percentage
                          << "% (" << formatBytes(bytesTransferred) << " / "
                          << formatBytes(totalBytes) << ") "
                          << formatSpeed(speed) << " ETA: "
                          << etaSeconds / 60 << ":"
                          << std::setw(2) << std::setfill('0')
                          << (etaSeconds % 60) << "    ";
                std::cout << std::flush;
            }
        };

        // Receive file
        std::string errorMsg;
        bool success = receiver.receiveFile(clientSock, errorMsg,
                                             promptUser, progressCallback);

        std::cout << "\n\n";  // New line after progress bar

        // Close socket
        closesocket(clientSock);

        // Check result
        if (!success) {
            std::cerr << "Error: " << errorMsg << "\n";
            std::cerr << "File transfer failed.\n";
            std::cout << "\nWaiting for next connection...\n";
            continue;
        }

        // Calculate statistics
        auto endTime = std::chrono::steady_clock::now();
        auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        double avgSpeed = (totalTime > 0) ?
            (static_cast<double>(receiver.getReceivedFileSize()) /
             (totalTime / 1000.0)) : 0.0;

        // Display success
        std::cout << "===========================================\n";
        std::cout << "File received successfully!\n";
        std::cout << "===========================================\n\n";
        std::cout << "Transfer Statistics:\n";
        std::cout << "  File Name:    " << receiver.getReceivedFileName() << "\n";
        std::cout << "  Saved To:     " << receiver.getReceivedFilePath() << "\n";
        std::cout << "  File Size:    " << formatBytes(receiver.getReceivedFileSize()) << "\n";
        std::cout << "  Time Taken:   " << std::fixed << std::setprecision(2)
                  << (totalTime / 1000.0) << " seconds\n";
        std::cout << "  Average Speed:" << formatSpeed(avgSpeed) << "\n";
        std::cout << "  SHA-256 Hash: " << receiver.getSha256Hash() << "\n\n";

        std::cout << "Waiting for next connection...\n";
    }

    // Cleanup
    closesocket(listenSock);
    WSACleanup();

    std::cout << "\nServer stopped.\n";
    return 0;
}
