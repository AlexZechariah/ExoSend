/**
 * @file discovery_test.cpp
 * @brief CLI test harness for DiscoveryService
 *
 * Displays discovered peers in real-time with a console interface.
 * Used to validate UDP broadcast discovery functionality.
 */

#include "exosend/DiscoveryService.h"
#include "exosend/config.h"

#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <csignal>
#include <atomic>

// Global flag for graceful shutdown
std::atomic<bool> g_running(true);

/**
 * @brief Signal handler for Ctrl+C
 */
void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n\nReceived interrupt signal. Shutting down...\n";
        g_running = false;
    }
}

/**
 * @brief Format duration as human-readable string
 * @param ms Duration in milliseconds
 * @return Formatted string (e.g., "5s ago", "2m ago")
 */
std::string formatDuration(int64_t ms) {
    if (ms < 1000) {
        return std::to_string(ms) + "ms ago";
    } else if (ms < 60000) {
        return std::to_string(ms / 1000) + "s ago";
    } else if (ms < 3600000) {
        int minutes = static_cast<int>(ms / 60000);
        int seconds = static_cast<int>((ms % 60000) / 1000);
        return std::to_string(minutes) + "m " + std::to_string(seconds) + "s ago";
    } else {
        int hours = static_cast<int>(ms / 3600000);
        int minutes = static_cast<int>((ms % 3600000) / 60000);
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m ago";
    }
}

/**
 * @brief Print the current peer list to console
 * @param service The discovery service to query
 */
void printPeerList(const ExoSend::DiscoveryService& service) {
    auto peers = service.getPeers();

    // Print header
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << "         Discovered Peers (" << peers.size() << ")\n";
    std::cout << "==============================================\n";

    if (peers.empty()) {
        std::cout << "\n  No peers discovered yet.\n";
        std::cout << "  (Listening on UDP port " << service.getBoundDiscoveryPort()
                  << " from pool [41000,42100,43210,43500,45100,46000,46100,47100,47500,48100])\n";
    } else {
        // Calculate column widths
        const int nameWidth = 20;
        const int ipWidth = 15;
        const int portWidth = 6;

        // Print table header
        std::cout << "\n  " << std::left
                 << std::setw(nameWidth) << "Display Name"
                 << std::setw(ipWidth) << "IP Address"
                 << std::setw(portWidth) << "Port"
                 << "Last Seen\n";
        std::cout << "  " << std::string(nameWidth + ipWidth + portWidth + 20, '-') << "\n";

        // Get current time
        auto now = std::chrono::steady_clock::now();

        // Print each peer
        for (const auto& peer : peers) {
            std::cout << "  " << std::left
                     << std::setw(nameWidth) << peer.displayName.substr(0, nameWidth - 1)
                     << std::setw(ipWidth) << peer.ipAddress
                     << std::setw(portWidth) << peer.tcpPort;

            // Calculate time since last seen
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - peer.lastSeen
            );
            std::cout << formatDuration(elapsed.count()) << "\n";
        }
    }

    std::cout << "==============================================\n";
    std::cout << "Local UUID: " << service.getUuid() << "\n";
    std::cout << "Local Name: " << service.getDisplayName() << "\n";
    std::cout << "Local Port: " << service.getTcpPort() << "\n";
    std::cout << "==============================================\n";
    std::cout << "\nPress Ctrl+C to exit...\n";
}

/**
 * @brief Main entry point
 */
int main(int argc, char* argv[]) {
    std::cout << "==============================================\n";
    std::cout << "     ExoSend Discovery Test (Phase 1)        \n";
    std::cout << "==============================================\n\n";

    // Parse command line arguments (optional)
    std::string customName;
    uint16_t customPort = ExoSend::TCP_PORT_DEFAULT;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--name" && i + 1 < argc) {
            customName = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            customPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --name <name>   Set custom display name\n";
            std::cout << "  --port <port>   Set custom TCP port (default: " << ExoSend::TCP_PORT_DEFAULT << ")\n";
            std::cout << "  --help          Show this help message\n";
            return 0;
        }
    }

    // Set up signal handler for graceful shutdown
    std::signal(SIGINT, signalHandler);

    // Create discovery service
    ExoSend::DiscoveryService service;

    // Apply custom settings if provided
    if (!customName.empty()) {
        service.setDisplayName(customName);
    }
    if (customPort != ExoSend::TCP_PORT_DEFAULT) {
        service.setTcpPort(customPort);
    }

    // Start the service
    std::cout << "Starting discovery service...\n";
    if (!service.start()) {
        std::cerr << "Failed to start discovery service!\n";
        return 1;
    }

    std::cout << "\nDiscovery service started successfully!\n";
    std::cout << "Broadcast interval: " << ExoSend::DISCOVERY_INTERVAL_MS << "ms\n";
    std::cout << "Peer timeout: " << ExoSend::PEER_TIMEOUT_MS << "ms\n";

    // Main loop - update display every 2 seconds
    int updateCounter = 0;
    while (g_running) {
        // Print peer list
        printPeerList(service);

        // Wait before next update
        std::this_thread::sleep_for(std::chrono::seconds(2));
        ++updateCounter;
    }

    // Stop the service
    std::cout << "\nStopping discovery service...\n";
    service.stop();

    std::cout << "\nDiscovery test completed successfully!\n";
    return 0;
}
