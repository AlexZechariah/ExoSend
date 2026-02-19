/**
 * @file echo_client.cpp
 * @brief Simple TCP echo client for testing
 *
 * This client connects to localhost:9999 and sends a "Hello ExoSend" message.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>

#pragma comment(lib, "Ws2_32.lib")

// Constants from config
constexpr uint16_t SERVER_PORT = 9999;
constexpr const char* MESSAGE = "Hello ExoSend";

/**
 * @brief Print WSA error message
 * @param function Name of the function that failed
 */
void printError(const char* function) {
    std::cerr << "ERROR: " << function << " failed (WSA error: " << WSAGetLastError() << ")\n";
}

/**
 * @brief Entry point for echo client
 * @param argc Argument count
 * @param argv Argument values (server_ip [port])
 * @return Exit code (0 on success)
 *
 * Initializes Winsock, connects to server, sends message.
 *
 * Usage: echo_client.exe <server_ip> [port]
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <server_ip> [port]\n";
        std::cout << "Example: " << argv[0] << " 127.0.0.1 9999\n";
        return 1;
    }

    const char* serverIp = argv[1];
    uint16_t serverPort = (argc >= 3) ? static_cast<uint16_t>(std::stoi(argv[2])) : SERVER_PORT;

    std::cout << "=== ExoSend Echo Client ===\n";
    std::cout << "Connecting to " << serverIp << ":" << serverPort << "\n\n";

    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << "\n";
        return 1;
    }
    std::cout << "[+] Winsock initialized\n";

    // Create a socket for connecting to server
    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        printError("socket");
        WSACleanup();
        return 1;
    }
    std::cout << "[+] Socket created\n";

    // Setup the server address structure
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);
    serverAddr.sin_port = htons(serverPort);

    // Connect to server
    std::cout << "[+] Connecting to server...\n";
    result = connect(connectSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printError("connect");
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "[+] Connected to " << serverIp << ":" << serverPort << "\n";

    // Send message
    std::string message(MESSAGE);
    size_t messageLen = message.length();

    std::cout << "\nSending message: \"" << message << "\"\n";
    result = send(connectSocket, message.c_str(), static_cast<int>(messageLen), 0);
    if (result == SOCKET_ERROR) {
        printError("send");
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] Sent " << result << " bytes\n";
    std::cout << "[+] Message delivered successfully\n";

    // Cleanup
    result = shutdown(connectSocket, SD_SEND);
    if (result == SOCKET_ERROR) {
        printError("shutdown");
    }

    closesocket(connectSocket);
    WSACleanup();

    std::cout << "\n[+] Client shutdown complete\n";
    return 0;
}
