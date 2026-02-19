/**
 * @file server_test.cpp
 * @brief Comprehensive CLI test tool for Phase 3 Multi-threaded Transfer Server
 *
 * This tool combines:
 * - DiscoveryService (UDP peer discovery)
 * - TransferServer (TCP file transfer server)
 * - CLI interface for testing
 *
 * Usage:
 *   server_test.exe [--port PORT] [--download-dir DIR] [--name NAME]
 */

#include "exosend/DiscoveryService.h"
#include "exosend/TransferServer.h"
#include "exosend/TransferQueueManager.h"
#include "exosend/config.h"
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <iomanip>
#include <sstream>

using namespace ExoSend;

//=============================================================================
// Global Variables for Signal Handling
//=============================================================================

static std::atomic<bool> g_running(true);
static DiscoveryService* g_discovery = nullptr;
static TransferServer* g_server = nullptr;

//=============================================================================
// Signal Handler
//=============================================================================

void signalHandler(int signal) {
    (void)signal;
    std::cout << "\n[INFO] Shutting down gracefully...\n";
    g_running.store(false);

    // Stop services
    if (g_server) {
        g_server->stop();
    }
    if (g_discovery) {
        g_discovery->stop();
    }
}

//=============================================================================
// Helper Functions
//=============================================================================

/**
 * @brief Format file size for display
 */
std::string formatFileSize(uint64_t size) {
    const double KB = 1024.0;
    const double MB = 1024.0 * 1024.0;
    const double GB = 1024.0 * 1024.0 * 1024.0;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    if (size >= GB) {
        oss << (size / GB) << " GB";
    } else if (size >= MB) {
        oss << (size / MB) << " MB";
    } else if (size >= KB) {
        oss << (size / KB) << " KB";
    } else {
        oss << size << " bytes";
    }

    return oss.str();
}

/**
 * @brief Display session status
 */
void displaySessionStatus(const std::string& sessionId, SessionStatus status) {
    std::cout << "[SESSION] " << sessionId << " -> "
              << sessionStatusToString(status) << "\n";
}

//=============================================================================
// Main Function
//=============================================================================

int main(int argc, char* argv[]) {
    // Parse command line arguments
    uint16_t port = TCP_PORT_DEFAULT;
    std::string downloadDir = ".";
    std::string displayName;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--download-dir" && i + 1 < argc) {
            downloadDir = argv[++i];
        } else if (arg == "--name" && i + 1 < argc) {
            displayName = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  --port PORT         TCP port to listen on (default: " << TCP_PORT_DEFAULT << ")\n"
                      << "  --download-dir DIR  Directory for received files (default: current directory)\n"
                      << "  --name NAME         Display name for discovery (default: hostname)\n"
                      << "  --help, -h          Show this help message\n";
            return 0;
        }
    }

    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    //=========================================================================
    // Banner
    //=========================================================================

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  ExoSend Phase 3 Server Test Tool\n";
    std::cout << "========================================\n";
    std::cout << "Port: " << port << "\n";
    std::cout << "Download Directory: " << downloadDir << "\n";
    std::cout << "Max Concurrent Transfers: " << MAX_CONCURRENT_TRANSFERS << "\n";
    std::cout << "========================================\n\n";

    //=========================================================================
    // Create Discovery Service
    //=========================================================================

    std::cout << "[INFO] Starting Discovery Service...\n";

    DiscoveryService discovery;
    g_discovery = &discovery;

    if (!displayName.empty()) {
        discovery.setDisplayName(displayName);
    }
    discovery.setTcpPort(port);

    if (!discovery.start()) {
        std::cerr << "[ERROR] Failed to start Discovery Service\n";
        return 1;
    }

    std::cout << "[INFO] Discovery Service started on UDP port " << DISCOVERY_PORT_DEFAULT << "\n";
    std::cout << "[INFO] Device UUID: " << discovery.getUuid() << "\n";
    std::cout << "[INFO] Display Name: " << discovery.getDisplayName() << "\n\n";

    //=========================================================================
    // Create Transfer Server
    //=========================================================================

    std::cout << "[INFO] Starting Transfer Server...\n";

    TransferServer server(port);
    g_server = &server;

    server.setDownloadDir(downloadDir);

    // Set session event callback
    server.setSessionEventCallback([](const std::string& sessionId, SessionStatus status) {
        displaySessionStatus(sessionId, status);
    });

    // Set incoming connection callback with user prompt
    server.setIncomingConnectionCallback([](const std::string& clientIp,
                                              const ExoHeader& header,
                                              const std::string& pendingSessionId) -> bool {
        std::cout << "[INCOMING] Connection from " << clientIp << "\n";
        std::cout << "[INCOMING] File: " << header.getFilename()
                  << " (" << formatFileSize(header.fileSize) << ")\n";

        // Prompt user for acceptance
        std::cout << "\nAccept this transfer? (y/n): ";
        std::string response;
        std::getline(std::cin, response);

        if (response == "y" || response == "Y" || response == "yes") {
            std::cout << "[INCOMING] Transfer accepted\n";
            return true;
        } else {
            std::cout << "[INCOMING] Transfer rejected\n";
            return false;
        }
    });

    if (!server.start()) {
        std::cerr << "[ERROR] Failed to start Transfer Server\n";
        discovery.stop();
        return 1;
    }

    std::cout << "[INFO] Transfer Server started on TCP port " << port << "\n\n";

    //=========================================================================
    // Optional: Create Queue Manager (for future testing)
    //=========================================================================

    std::cout << "[INFO] Transfer Queue Manager available for outgoing transfers\n";
    std::cout << "[INFO] (Outgoing queue not activated in this test tool)\n\n";

    //=========================================================================
    // Main Loop
    //=========================================================================

    std::cout << "[INFO] Server is running. Press Ctrl+C to stop.\n\n";
    std::cout << "Commands:\n";
    std::cout << "  p    - Show peers\n";
    std::cout << "  s    - Show sessions\n";
    std::cout << "  h    - Show help\n";
    std::cout << "  Ctrl+C - Exit\n\n";

    // Command input thread
    std::thread inputThread([&]() {
        std::string line;
        while (g_running.load()) {
            std::cout << "> ";
            std::cout.flush();

            if (!std::getline(std::cin, line)) {
                break;
            }

            if (line.empty()) {
                continue;
            }

            char cmd = line[0];
            switch (cmd) {
                case 'p':
                case 'P': {
                    // Show peers
                    auto peers = discovery.getPeers();
                    std::cout << "\n--- Discovered Peers (" << peers.size() << ") ---\n";
                    for (const auto& peer : peers) {
                        std::cout << "  UUID: " << peer.uuid << "\n";
                        std::cout << "  Name: " << peer.displayName << "\n";
                        std::cout << "  IP: " << peer.ipAddress << ":" << peer.tcpPort << "\n";
                        std::cout << "  Last Seen: "
                                  << std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::steady_clock::now() - peer.lastSeen).count()
                                  << "s ago\n\n";
                    }
                    break;
                }

                case 's':
                case 'S': {
                    // Show sessions
                    auto sessionIds = server.getActiveSessionIds();
                    std::cout << "\n--- Active Sessions (" << sessionIds.size() << ") ---\n";
                    for (const auto& sessionId : sessionIds) {
                        TransferSession* session = server.getSession(sessionId);
                        if (session) {
                            std::cout << "  ID: " << sessionId << "\n";
                            std::cout << "  Status: " << (int)session->getStatus() << "\n";
                            std::cout << "  Type: " << (session->getType() == SessionType::INCOMING ? "INCOMING" : "OUTGOING") << "\n";
                            std::cout << "  Progress: " << session->getBytesTransferred()
                                      << " / " << session->getTotalBytes() << " bytes\n\n";
                        }
                    }
                    break;
                }

                case 'h':
                case 'H':
                    std::cout << "\nCommands:\n";
                    std::cout << "  p    - Show peers\n";
                    std::cout << "  s    - Show sessions\n";
                    std::cout << "  h    - Show help\n";
                    std::cout << "  Ctrl+C - Exit\n\n";
                    break;

                default:
                    std::cout << "Unknown command: " << cmd << " (type 'h' for help)\n";
                    break;
            }
        }
    });

    // Wait for running flag
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    //=========================================================================
    // Cleanup
    //=========================================================================

    std::cout << "\n[INFO] Stopping services...\n";

    if (inputThread.joinable()) {
        inputThread.join();
    }

    server.stop();
    discovery.stop();

    std::cout << "[INFO] Services stopped.\n";
    std::cout << "[INFO] Exiting.\n";

    return 0;
}
