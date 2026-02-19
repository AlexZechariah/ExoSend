/**
 * @file file_send_test.cpp
 * @brief CLI tool to test sending files over ExoSend protocol
 *
 * Usage:
 *   file_send_test.exe <ip_address> <port> <file_path>
 *
 * Example:
 *   file_send_test.exe 127.0.0.1 9999 C:\\Users\\Alex\\test.txt
 */

#include "exosend/FileTransfer.h"
#include "exosend/config.h"

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
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

/**
 * @brief Print usage information
 */
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <ip_address> <port> <file_path>\n";
    std::cout << "\nArguments:\n";
    std::cout << "  ip_address  IP address of the receiver (e.g., 127.0.0.1)\n";
    std::cout << "  port        TCP port to connect to (e.g., 9999)\n";
    std::cout << "  file_path   Path to the file to send\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << programName << " 127.0.0.1 9999 C:\\Users\\Alex\\test.txt\n";
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

int main(int argc, char* argv[]) {
    std::cout << "===========================================\n";
    std::cout << "ExoSend File Send Test (Phase 2)\n";
    std::cout << "===========================================\n\n";

    // Parse command-line arguments
    if (argc != 4) {
        printUsage(argv[0]);
        return 1;
    }

    std::string ipAddress = argv[1];
    std::string portStr = argv[2];
    std::string filePath = argv[3];

    // Parse port
    uint16_t port = 0;
    try {
        port = static_cast<uint16_t>(std::stoul(portStr));
    } catch (...) {
        std::cerr << "Error: Invalid port number: " << portStr << "\n";
        return 1;
    }

    std::cout << "Configuration:\n";
    std::cout << "  Target IP:   " << ipAddress << "\n";
    std::cout << "  Target Port: " << port << "\n";
    std::cout << "  File:        " << filePath << "\n\n";

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error: WSAStartup failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Error: socket() failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    // Connect to server
    std::cout << "Connecting to " << ipAddress << ":" << port << "...\n";

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Error: Invalid IP address: " << ipAddress << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error: connect() failed: " << WSAGetLastError() << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected successfully!\n\n";

    // Create file sender
    FileSender sender(filePath);

    // Display file info
    std::cout << "File Information:\n";
    std::cout << "  Name:  " << sender.getFileName() << "\n";
    std::cout << "  Size:  " << formatBytes(sender.getFileSize()) << "\n\n";

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

    // Send file
    std::cout << "Sending file...\n";
    std::string errorMsg;
    bool success = sender.sendFile(sock, errorMsg, progressCallback);

    std::cout << "\n\n";  // New line after progress bar

    // Close socket
    closesocket(sock);
    WSACleanup();

    // Check result
    if (!success) {
        std::cerr << "Error: " << errorMsg << "\n";
        return 1;
    }

    // Calculate statistics
    auto endTime = std::chrono::steady_clock::now();
    auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();

    double avgSpeed = (totalTime > 0) ?
        (static_cast<double>(sender.getFileSize()) / (totalTime / 1000.0)) : 0.0;

    // Display success
    std::cout << "===========================================\n";
    std::cout << "File sent successfully!\n";
    std::cout << "===========================================\n\n";
    std::cout << "Transfer Statistics:\n";
    std::cout << "  File Name:    " << sender.getFileName() << "\n";
    std::cout << "  File Size:    " << formatBytes(sender.getFileSize()) << "\n";
    std::cout << "  Time Taken:   " << std::fixed << std::setprecision(2)
              << (totalTime / 1000.0) << " seconds\n";
    std::cout << "  Average Speed:" << formatSpeed(avgSpeed) << "\n";
    std::cout << "  SHA-256 Hash: " << sender.getSha256Hash() << "\n\n";

    std::cout << "You can verify the file on the receiver side using the hash.\n";

    return 0;
}
