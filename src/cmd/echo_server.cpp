/**
 * @file echo_server.cpp
 * @brief Simple TCP echo server for testing
 *
 * This server binds to an OS-assigned port (or a port supplied on the command line)
 * and prints any received messages.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <cstdint>

#pragma comment(lib, "Ws2_32.lib")

// Default port: 0 means OS assigns an ephemeral port.
// Specify a port on the command line: echo_server.exe 0.0.0.0 <port>
constexpr uint16_t SERVER_PORT = 0;
constexpr size_t BUFFER_SIZE = 4096;
constexpr int BACKLOG = SOMAXCONN;

/**
 * @brief Print WSA error message
 * @param function Name of the function that failed
 */
void printError(const char* function) {
    std::cerr << "ERROR: " << function << " failed (WSA error: " << WSAGetLastError() << ")\n";
}

/**
 * @brief Entry point for echo server
 * @param argc Argument count
 * @param argv Argument values ([bind_ip] port)
 * @return Exit code (0 on success)
 *
 * Initializes Winsock, creates listening socket, accepts one client,
 * receives and prints messages.
 *
 * Usage: echo_server.exe [bind_ip] [port]
 *   bind_ip: IP to bind to (default: 0.0.0.0 for all interfaces)
 *   port: Port to listen on (default: 9999)
 */
int main(int argc, char* argv[]) {
    const char* bindIp = (argc >= 2) ? argv[1] : "0.0.0.0";
    uint16_t bindPort = (argc >= 3) ? static_cast<uint16_t>(std::stoi(argv[2])) : SERVER_PORT;

    std::cout << "=== ExoSend Echo Server ===\n";
    std::cout << "Starting TCP server on " << bindIp << ":" << bindPort << "\n\n";

    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << "\n";
        return 1;
    }
    std::cout << "[+] Winsock initialized\n";

    // Create a socket for listening
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printError("socket");
        WSACleanup();
        return 1;
    }
    std::cout << "[+] Socket created\n";

    // Setup the server address structure
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    if (InetPtonA(AF_INET, bindIp, &serverAddr.sin_addr) != 1) {
        std::cerr << "ERROR: Invalid bind IP address: " << bindIp << "\n";
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    serverAddr.sin_port = htons(bindPort);

    // Bind the socket
    result = bind(listenSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printError("bind");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "[+] Socket bound to " << bindIp << ":" << bindPort << "\n";

    // Listen for incoming connections
    result = listen(listenSocket, BACKLOG);
    if (result == SOCKET_ERROR) {
        printError("listen");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "[+] Server listening...\n";
    std::cout << "\nWaiting for client connection...\n";

    // Accept a client socket
    sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    SOCKET clientSocket = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);
    if (clientSocket == INVALID_SOCKET) {
        printError("accept");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // Get client IP address
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    std::cout << "\n[+] Client connected from: " << clientIP << ":" << ntohs(clientAddr.sin_port) << "\n";
    std::cout << "Waiting for message...\n\n";

    // Receive data until the client closes the connection
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    std::string fullMessage;

    do {
        bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            fullMessage += buffer;
            std::cout << "Received " << bytesReceived << " bytes\n";
        } else if (bytesReceived == 0) {
            std::cout << "\n[+] Connection closed by client\n";
        } else {
            printError("recv");
            break;
        }
    } while (bytesReceived > 0);

    // Print the complete received message
    if (!fullMessage.empty()) {
        std::cout << "\n=== Complete Message ===\n";
        std::cout << fullMessage << "\n";
        std::cout << "======================\n";
    }

    // Cleanup
    closesocket(clientSocket);
    closesocket(listenSocket);
    WSACleanup();

    std::cout << "\n[+] Server shutdown complete\n";
    return 0;
}
