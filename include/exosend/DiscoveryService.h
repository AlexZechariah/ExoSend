/**
 * @file DiscoveryService.h
 * @brief UDP broadcast peer discovery service
 */

#pragma once

#include "PeerInfo.h"
#include "config.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <winsock2.h>

namespace ExoSend {

/**
 * @class DiscoveryService
 * @brief UDP broadcast discovery service for ExoSend
 *
 * This service handles automatic peer discovery on the local network using
 * UDP broadcast beacons. It transmits a JSON beacon every 2 seconds and
 * listens for beacons from other peers.
 *
 * Thread Safety:
 * - All public methods are thread-safe
 * - Peer table access is protected by mutex
 * - Uses RAII for socket management
 */
class DiscoveryService {
public:
    /**
     * @brief Constructor - initializes discovery service
     */
    DiscoveryService();

    /**
     * @brief Destructor - ensures clean shutdown
     */
    ~DiscoveryService();

    // Prevent copying (service manages unique resources)
    DiscoveryService(const DiscoveryService&) = delete;
    DiscoveryService& operator=(const DiscoveryService&) = delete;

    // Allow moving
    DiscoveryService(DiscoveryService&&) noexcept;
    DiscoveryService& operator=(DiscoveryService&&) noexcept;

    /**
     * @brief Start the discovery service
     * @return true if started successfully, false otherwise
     *
     * Creates UDP socket, enables broadcast, and launches worker threads:
     * - Transmitter thread (broadcasts beacons every 2s)
     * - Listener thread (receives beacons)
     * - Garbage collector thread (removes stale peers)
     */
    bool start();

    /**
     * @brief Stop the discovery service
     *
     * Signals all threads to stop and waits for them to join.
     * Closes the UDP socket.
     */
    void stop();

    /**
     * @brief Check if the service is currently running
     * @return true if service is running
     */
    bool isRunning() const { return m_running.load(); }

    /**
     * @brief Get a thread-safe copy of current peers
     * @return Vector of all discovered peers
     */
    std::vector<PeerInfo> getPeers() const;

    /**
     * @brief Set the display name for this instance
     * @param name Human-readable device name
     */
    void setDisplayName(const std::string& name);

    /**
     * @brief Set the TCP port where this instance accepts transfers
     * @param port TCP port number
     */
    void setTcpPort(uint16_t port);

    /**
     * @brief Get the display name
     * @return Current display name
     */
    const std::string& getDisplayName() const { return m_displayName; }

    /**
     * @brief Get the device UUID
     * @return UUID string
     */
    const std::string& getUuid() const { return m_uuid; }

    /**
     * @brief Get the TCP port
     * @return TCP port number
     */
    uint16_t getTcpPort() const { return m_tcpPort; }

private:
    /**
     * @brief Transmitter thread function
     *
     * Broadcasts JSON beacon every DISCOVERY_INTERVAL_MS.
     * Runs until m_stopRequested is set.
     */
    void transmitterThreadFunc();

    /**
     * @brief Listener thread function
     *
     * Blocks in recvfrom() waiting for incoming beacons.
     * Parses JSON and updates peer table.
     * Runs until m_stopRequested is set.
     */
    void listenerThreadFunc();

    /**
     * @brief Garbage collector thread function
     *
     * Removes peers that haven't been seen in PEER_TIMEOUT_MS.
     * Runs every GC_INTERVAL_MS until m_stopRequested is set.
     */
    void gcThreadFunc();

    /**
     * @brief Generate JSON beacon for transmission
     * @return JSON string containing device info
     */
    std::string generateBeaconJson() const;

    /**
     * @brief Get local IP address
     * @return Local IP address string
     *
     * Note: For Phase 1, this may return 127.0.0.1
     * Future phases will implement proper adapter enumeration.
     */
    std::string getLocalIpAddress() const;

    /**
     * @brief Get list of subnet broadcast addresses for all interfaces
     * @return Vector of broadcast address strings
     *
     * Enumerates all network interfaces and calculates the subnet-specific
     * broadcast address for each. Also includes the limited broadcast
     * (255.255.255.255) for compatibility.
     */
    std::vector<std::string> getBroadcastAddresses() const;

    /**
     * @brief Generate a random UUID for this instance
     * @return UUID string
     *
     * Note: Phase 1 uses random generation.
     * Phase 4 will persist UUID to config file.
     */
    std::string generateUuid() const;

    /**
     * @brief Parse incoming JSON beacon and update peer table
     * @param json JSON string from beacon
     * @param senderIp IP address of the sender
     */
    void parseBeacon(const std::string& json, const std::string& senderIp);

    /**
     * @brief Initialize Winsock and create UDP socket
     * @return true if successful
     */
    bool initializeSocket();

    /**
     * @brief Close the UDP socket and cleanup Winsock
     */
    void cleanupSocket();

    /**
     * @brief Broadcast goodbye beacon before shutdown
     *
     * Sends goodbye beacon multiple times to ensure reliable delivery.
     * This provides immediate peer departure notification instead of
     * waiting for the timeout period.
     */
    void broadcastGoodbye();

    // Member variables

    // Identity
    std::string m_displayName;     ///< Human-readable name
    std::string m_uuid;            ///< Unique device identifier
    uint16_t m_tcpPort;            ///< TCP port for transfers

    // Socket handle (SOCKET from winsock2.h)
    SOCKET m_udpSocket;
    bool m_socketInitialized;      ///< Track if Winsock/socket need cleanup

    // Peer table (thread-safe)
    mutable std::mutex m_peerMutex;  ///< Protects m_peers
    std::unordered_map<std::string, PeerInfo> m_peers;  ///< UUID -> PeerInfo

    // Worker threads
    std::thread m_transmitterThread;
    std::thread m_listenerThread;
    std::thread m_gcThread;

    // Control flags
    std::atomic<bool> m_running;       ///< Service is running
    std::atomic<bool> m_stopRequested; ///< Request threads to stop
    std::condition_variable m_stopCv;  ///< Wakes periodic worker threads on stop
    std::mutex m_stopCvMutex;          ///< Protects m_stopCv waits
};

}  // namespace ExoSend
