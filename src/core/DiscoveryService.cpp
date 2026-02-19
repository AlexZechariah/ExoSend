/**
 * @file DiscoveryService.cpp
 * @brief Implementation of UDP broadcast discovery service
 *
 * Handles automatic peer discovery on the local network using
 * UDP broadcast beacons with JSON payloads.
 */

#include "exosend/DiscoveryService.h"
#include "exosend/config.h"
#include "exosend/PeerInfo.h"
#include "exosend/ThreadSafeLog.h"
#include "exosend/UuidGenerator.h"

#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <sstream>
#include <random>
#include <iomanip>
#include <algorithm>
#include <windows.h>

// Undefine Windows macros that conflict with std::left, std::right, etc.
#ifdef left
#undef left
#endif
#ifdef right
#undef right
#endif

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Use nlohmann::json for convenience
using json = nlohmann::json;

namespace ExoSend {

namespace {
    #define LogDiscovery(msg) ExoSend::ThreadSafeLog::log(msg)
}

// Define SOCKET_HANDLE as the actual Windows SOCKET type
#undef SOCKET_HANDLE
#define SOCKET_HANDLE SOCKET

//=============================================================================
// Constructor / Destructor
//=============================================================================

DiscoveryService::DiscoveryService()
    : m_displayName("Unknown")
    , m_uuid(generateUuid())
    , m_tcpPort(TCP_PORT_DEFAULT)
    , m_udpSocket(INVALID_SOCKET)
    , m_socketInitialized(false)
    , m_running(false)
    , m_stopRequested(false) {
    // Try to get hostname for display name
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        m_displayName = hostname;
    }
}

DiscoveryService::~DiscoveryService() {
    stop();
}

DiscoveryService::DiscoveryService(DiscoveryService&& other) noexcept
    : m_displayName(std::move(other.m_displayName))
    , m_uuid(std::move(other.m_uuid))
    , m_tcpPort(other.m_tcpPort)
    , m_udpSocket(other.m_udpSocket)
    , m_socketInitialized(other.m_socketInitialized)
    , m_peers(std::move(other.m_peers))
    , m_transmitterThread(std::move(other.m_transmitterThread))
    , m_listenerThread(std::move(other.m_listenerThread))
    , m_gcThread(std::move(other.m_gcThread))
    , m_running(other.m_running.load())
    , m_stopRequested(other.m_stopRequested.load()) {
    // Mark moved-from object as invalid
    other.m_udpSocket = INVALID_SOCKET;
    other.m_socketInitialized = false;
    other.m_running = false;
    other.m_stopRequested = true;
}

DiscoveryService& DiscoveryService::operator=(DiscoveryService&& other) noexcept {
    if (this != &other) {
        // Clean up current resources
        stop();

        // Move from other
        m_displayName = std::move(other.m_displayName);
        m_uuid = std::move(other.m_uuid);
        m_tcpPort = other.m_tcpPort;
        m_udpSocket = other.m_udpSocket;
        m_socketInitialized = other.m_socketInitialized;
        m_peers = std::move(other.m_peers);
        m_transmitterThread = std::move(other.m_transmitterThread);
        m_listenerThread = std::move(other.m_listenerThread);
        m_gcThread = std::move(other.m_gcThread);
        m_running = other.m_running.load();
        m_stopRequested = other.m_stopRequested.load();

        // Mark moved-from object as invalid
        other.m_udpSocket = INVALID_SOCKET;
        other.m_socketInitialized = false;
        other.m_running = false;
        other.m_stopRequested = true;
    }
    return *this;
}

//=============================================================================
// Public Methods
//=============================================================================

bool DiscoveryService::start() {
    if (m_running.load()) {
        return false;
    }

    // Initialize socket
    if (!initializeSocket()) {
        return false;
    }

    // Set running flag
    m_running = true;
    m_stopRequested = false;

    // Launch worker threads
    try {
        m_transmitterThread = std::thread(&DiscoveryService::transmitterThreadFunc, this);
        m_listenerThread = std::thread(&DiscoveryService::listenerThreadFunc, this);
        m_gcThread = std::thread(&DiscoveryService::gcThreadFunc, this);
    } catch (const std::exception& e) {
        m_running = false;
        cleanupSocket();
        return false;
    }

    return true;
}

void DiscoveryService::stop() {
    if (!m_running.load()) {
        return;
    }

    LogDiscovery("=== DiscoveryService::stop START ===");

    // NEW: Broadcast goodbye beacon BEFORE stopping threads
    // This ensures peers are notified immediately
    if (m_udpSocket != INVALID_SOCKET) {
        broadcastGoodbye();
    }

    // Signal threads to stop
    m_stopRequested = true;
    m_running = false;
    m_stopCv.notify_all();

    // Note: Shutdown socket BEFORE joining threads
    // This causes recvfrom() to return with error, unblocking listener thread
    // which is blocked in a blocking recvfrom() call
    if (m_udpSocket != INVALID_SOCKET) {
        shutdown(m_udpSocket, SD_BOTH);      // Unblock recvfrom
        closesocket(m_udpSocket);           // Close socket
        m_udpSocket = INVALID_SOCKET;       // Mark as closed
    }

    // Now joins will complete quickly (listener was blocked in recvfrom)
    if (m_transmitterThread.joinable()) {
        m_transmitterThread.join();
    }
    if (m_listenerThread.joinable()) {
        m_listenerThread.join();
    }
    if (m_gcThread.joinable()) {
        m_gcThread.join();
    }

    // Cleanup is now safe (socket may already be closed)
    cleanupSocket();
    LogDiscovery("=== DiscoveryService::stop END ===");
}

std::vector<PeerInfo> DiscoveryService::getPeers() const {
    std::vector<PeerInfo> peers;
    std::lock_guard<std::mutex> lock(m_peerMutex);
    peers.reserve(m_peers.size());
    for (const auto& pair : m_peers) {
        peers.push_back(pair.second);
    }
    return peers;
}

void DiscoveryService::setDisplayName(const std::string& name) {
    m_displayName = name;
}

void DiscoveryService::setTcpPort(uint16_t port) {
    m_tcpPort = port;
}

//=============================================================================
// Private Thread Functions
//=============================================================================

void DiscoveryService::transmitterThreadFunc() {
    // Get all broadcast addresses at startup
    std::vector<std::string> broadcastAddresses = getBroadcastAddresses();

    while (!m_stopRequested.load()) {
        // Generate and send beacon
        std::string beacon = generateBeaconJson();

        // Send to each broadcast address
        for (const auto& broadcastIp : broadcastAddresses) {
            sockaddr_in broadcastAddr;
            broadcastAddr.sin_family = AF_INET;
            broadcastAddr.sin_port = htons(DISCOVERY_PORT_DEFAULT);
            inet_pton(AF_INET, broadcastIp.c_str(), &broadcastAddr.sin_addr);

            sendto(
                m_udpSocket,
                beacon.c_str(),
                static_cast<int>(beacon.length()),
                0,
                reinterpret_cast<sockaddr*>(&broadcastAddr),
                sizeof(broadcastAddr)
            );
        }

        // Wait for discovery interval or stop signal.
        std::unique_lock<std::mutex> waitLock(m_stopCvMutex);
        m_stopCv.wait_for(
            waitLock,
            std::chrono::milliseconds(DISCOVERY_INTERVAL_MS),
            [this]() { return m_stopRequested.load(); }
        );
    }
}

void DiscoveryService::listenerThreadFunc() {
    char buffer[MAX_BEACON_SIZE];
    sockaddr_in senderAddr;
    int senderAddrLen = sizeof(senderAddr);

    while (!m_stopRequested.load()) {
        // Receive beacon (blocking call)
        int bytesReceived = recvfrom(
            m_udpSocket,
            buffer,
            MAX_BEACON_SIZE - 1,
            0,
            reinterpret_cast<sockaddr*>(&senderAddr),
            &senderAddrLen
        );

        if (bytesReceived == SOCKET_ERROR) {
            int error = WSAGetLastError();
            // Handle socket shutdown/errors gracefully
            if (error == WSAEINTR ||           // Interrupted
                error == WSAESHUTDOWN ||       // Shutdown initiated
                error == WSAECONNABORTED ||    // Connection aborted
                error == WSAENOTCONN ||       // Not connected
                error == WSAECONNRESET) {     // Connection reset
                // Socket was closed or shutdown, exit gracefully
                break;
            }
            continue;
        }

        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';

            // Get sender IP address
            char senderIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &senderAddr.sin_addr, senderIp, INET_ADDRSTRLEN);

            // Parse the beacon
            try {
                parseBeacon(std::string(buffer, bytesReceived), senderIp);
            } catch (const json::parse_error&) {
                // Ignore JSON parse errors
            } catch (const std::exception&) {
                // Ignore beacon parsing errors
            }
        }
    }
}

void DiscoveryService::gcThreadFunc() {
    while (!m_stopRequested.load()) {
        // Wait for GC interval or stop signal.
        std::unique_lock<std::mutex> waitLock(m_stopCvMutex);
        m_stopCv.wait_for(
            waitLock,
            std::chrono::milliseconds(GC_INTERVAL_MS),
            [this]() { return m_stopRequested.load(); }
        );

        if (m_stopRequested.load()) {
            break;
        }

        waitLock.unlock();

        // Remove timed-out peers
        std::lock_guard<std::mutex> lock(m_peerMutex);

        auto it = m_peers.begin();
        while (it != m_peers.end()) {
            if (it->second.isTimedOut(PEER_TIMEOUT_MS)) {
                it = m_peers.erase(it);
            } else {
                ++it;
            }
        }
    }
}

//=============================================================================
// Private Helper Methods
//=============================================================================

std::string DiscoveryService::generateBeaconJson() const {
    json beacon;
    beacon["protocol_id"] = PROTOCOL_ID;
    beacon["beacon_type"] = BEACON_TYPE_ANNOUNCE;  // Explicit beacon type
    beacon["device_uuid"] = m_uuid;
    beacon["display_name"] = m_displayName;
    beacon["os_platform"] = OS_PLATFORM;
    beacon["tcp_port"] = m_tcpPort;

    return beacon.dump();
}

std::string DiscoveryService::getLocalIpAddress() const {
    // Use GetAdaptersAddresses for proper adapter enumeration on Windows
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;

    // Allocate buffer for adapter addresses
    for (int attempt = 0; attempt < 3; attempt++) {
        pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(new char[outBufLen]);

        DWORD dwRetVal = GetAdaptersAddresses(
            AF_INET,  // IPv4 only
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            pAddresses,
            &outBufLen
        );

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            delete[] reinterpret_cast<char*>(pAddresses);
            pAddresses = nullptr;
            continue;
        }

        if (dwRetVal == NO_ERROR) {
            break;
        }

        delete[] reinterpret_cast<char*>(pAddresses);
        pAddresses = nullptr;
        return LOCALHOST_IP;
    }

    if (!pAddresses) {
        return LOCALHOST_IP;
    }

    // Priority order for adapter selection:
    // 1. VMnet1 (Host-Only network) - 192.168.83.x
    // 2. Bridged adapter on physical network
    // 3. Any other non-loopback adapter
    std::string bestIp;
    int bestPriority = -1;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;

        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, buf, INET_ADDRSTRLEN);
                std::string ip(buf);

                // Skip loopback
                if (ip == "127.0.0.1") {
                    pUnicast = pUnicast->Next;
                    continue;
                }

                // Determine adapter priority
                int priority = 0;

                // Check adapter description for VMware adapters
                // Note: Description may be char* or wchar_t* depending on UNICODE macro
                std::string adapterName;
                std::wstring wAdapterName;
                if (pCurrAddresses->Description) {
                    // Convert Description to wstring for comparison
                    size_t len = wcslen(reinterpret_cast<const wchar_t*>(pCurrAddresses->Description));
                    wAdapterName.assign(reinterpret_cast<const wchar_t*>(pCurrAddresses->Description), len);
                    // Also get narrow string version for other uses
                    size_t converted = 0;
                    size_t descLen = len * 4 + 1;  // Worst case for UTF-8
                    adapterName.resize(descLen);
                    wcstombs_s(&converted, &adapterName[0], descLen, reinterpret_cast<const wchar_t*>(pCurrAddresses->Description), _TRUNCATE);
                    adapterName.resize(converted - 1);  // Remove null terminator
                }
                std::wstring friendlyName;
                if (pCurrAddresses->FriendlyName) {
                    friendlyName = pCurrAddresses->FriendlyName;
                }

                // Priority 1: VMware Host-Only (VMnet1)
                if (wAdapterName.find(L"VMnet1") != std::wstring::npos ||
                    friendlyName.find(L"VMnet1") != std::wstring::npos) {
                    priority = 100;
                }
                // Priority 2: Other VMware adapters (VMnet8 for NAT, etc.)
                else if (wAdapterName.find(L"VMnet") != std::wstring::npos ||
                         friendlyName.find(L"VMnet") != std::wstring::npos) {
                    priority = 50;
                }
                // Priority 3: Ethernet adapters (likely bridged)
                else if (pCurrAddresses->IfType == IF_TYPE_ETHERNET_CSMACD) {
                    priority = 75;
                }
                // Priority 0: Everything else (Wi-Fi, etc.)

                // Select highest priority adapter
                if (priority > bestPriority) {
                    bestIp = ip;
                    bestPriority = priority;
                }
            }
            pUnicast = pUnicast->Next;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    delete[] reinterpret_cast<char*>(pAddresses);

    return bestIp.empty() ? LOCALHOST_IP : bestIp;
}

std::vector<std::string> DiscoveryService::getBroadcastAddresses() const {
    std::vector<std::string> broadcastAddresses;

    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;

    // Allocate buffer for adapter addresses
    for (int attempt = 0; attempt < 3; attempt++) {
        pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(new char[outBufLen]);

        DWORD dwRetVal = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            pAddresses,
            &outBufLen
        );

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            delete[] reinterpret_cast<char*>(pAddresses);
            pAddresses = nullptr;
            continue;
        }

        if (dwRetVal == NO_ERROR) {
            break;
        }

        delete[] reinterpret_cast<char*>(pAddresses);
        pAddresses = nullptr;
        return broadcastAddresses;
    }

    if (!pAddresses) {
        // Fallback to limited broadcast
        broadcastAddresses.push_back("255.255.255.255");
        return broadcastAddresses;
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;

        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, buf, INET_ADDRSTRLEN);

                std::string ip(buf);

                // Skip loopback
                if (ip == "127.0.0.1") {
                    pUnicast = pUnicast->Next;
                    continue;
                }

                // Calculate subnet broadcast address
                // broadcast = (ip & mask) | ~mask
                uint32_t ipAddr = ntohl(addr->sin_addr.s_addr);
                uint8_t prefixLength = pUnicast->OnLinkPrefixLength;

                if (prefixLength > 0 && prefixLength < 32) {
                    uint32_t mask = ~(0xFFFFFFFF >> prefixLength);
                    uint32_t networkAddr = ipAddr & mask;
                    uint32_t broadcastAddr = networkAddr | (~mask);

                    sockaddr_in broadcastSockAddr;
                    broadcastSockAddr.sin_family = AF_INET;
                    broadcastSockAddr.sin_addr.s_addr = htonl(broadcastAddr);

                    char broadcastBuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &broadcastSockAddr.sin_addr, broadcastBuf, INET_ADDRSTRLEN);

                    broadcastAddresses.push_back(std::string(broadcastBuf));
                }
            }
            pUnicast = pUnicast->Next;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    delete[] reinterpret_cast<char*>(pAddresses);

    // Also include limited broadcast for compatibility
    broadcastAddresses.push_back("255.255.255.255");

    return broadcastAddresses;
}

std::string DiscoveryService::generateUuid() const {
    // Delegate to centralized UUID generator
    return UuidGenerator::generate();
}

void DiscoveryService::parseBeacon(const std::string& jsonStr, const std::string& senderIp) {
    // Parse JSON
    json beacon = json::parse(jsonStr);

    // Validate protocol_id
    if (!beacon.contains("protocol_id") || beacon["protocol_id"] != PROTOCOL_ID) {
        // Not our protocol, ignore
        return;
    }

    // Extract required fields
    if (!beacon.contains("device_uuid") || !beacon.contains("display_name")) {
        return;
    }

    // Ignore beacons from ourselves
    std::string uuid = beacon["device_uuid"];
    if (uuid == m_uuid) {
        return;
    }

    // NEW: Check for goodbye beacon type
    if (beacon.contains("beacon_type") && beacon["beacon_type"] == BEACON_TYPE_GOODBYE) {
        std::lock_guard<std::mutex> lock(m_peerMutex);

        auto it = m_peers.find(uuid);
        if (it != m_peers.end()) {
            std::string displayName = beacon["display_name"];
            m_peers.erase(it);
        }
        return;
    }

    // Original beacon processing (announce type or legacy without type)
    if (!beacon.contains("tcp_port")) {
        return;
    }

    std::string displayName = beacon["display_name"];
    uint16_t tcpPort = beacon["tcp_port"];

    // Sanitize display name length
    if (displayName.length() > MAX_DISPLAY_NAME) {
        displayName = displayName.substr(0, MAX_DISPLAY_NAME);
    }

    // Update or add peer
    std::lock_guard<std::mutex> lock(m_peerMutex);

    auto it = m_peers.find(uuid);
    if (it != m_peers.end()) {
        // Update existing peer
        it->second.lastSeen = std::chrono::steady_clock::now();
    } else {
        // Add new peer
        PeerInfo peer(uuid, displayName, senderIp, tcpPort);
        m_peers[uuid] = peer;
    }
}

//=============================================================================
// Socket Management
//=============================================================================

bool DiscoveryService::initializeSocket() {
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return false;
    }

    // Create UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    // Enable SO_BROADCAST
    int optval = 1;
    result = setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       reinterpret_cast<char*>(&optval), sizeof(optval));
    if (result == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // Bind to discovery port
    sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(DISCOVERY_PORT_DEFAULT);

    result = bind(sock, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr));
    if (result == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    m_udpSocket = sock;
    m_socketInitialized = true;
    return true;
}

void DiscoveryService::cleanupSocket() {
    // Idempotent cleanup - safe to call multiple times
    if (m_udpSocket != INVALID_SOCKET) {
        // Graceful shutdown before close
        shutdown(m_udpSocket, SD_BOTH);
        closesocket(m_udpSocket);
        m_udpSocket = INVALID_SOCKET;
    }

    if (m_socketInitialized) {
        WSACleanup();
        m_socketInitialized = false;
    }
}

//=============================================================================
// Goodbye Beacon Protocol
//=============================================================================

void DiscoveryService::broadcastGoodbye() {
    // Get all broadcast addresses
    std::vector<std::string> broadcastAddresses = getBroadcastAddresses();

    // Create goodbye beacon JSON
    json beacon;
    beacon["protocol_id"] = PROTOCOL_ID;
    beacon["beacon_type"] = BEACON_TYPE_GOODBYE;
    beacon["device_uuid"] = m_uuid;
    beacon["display_name"] = m_displayName;

    std::string goodbyeBeacon = beacon.dump();

    // Broadcast goodbye multiple times for reliability
    for (int i = 0; i < GOODBYE_BROADCAST_COUNT; ++i) {
        // Send to each broadcast address
        for (const auto& broadcastIp : broadcastAddresses) {
            sockaddr_in broadcastAddr;
            broadcastAddr.sin_family = AF_INET;
            broadcastAddr.sin_port = htons(DISCOVERY_PORT_DEFAULT);
            inet_pton(AF_INET, broadcastIp.c_str(), &broadcastAddr.sin_addr);

            sendto(
                m_udpSocket,
                goodbyeBeacon.c_str(),
                static_cast<int>(goodbyeBeacon.length()),
                0,
                reinterpret_cast<sockaddr*>(&broadcastAddr),
                sizeof(broadcastAddr)
            );
        }

        // Small delay between broadcasts (except after last one)
        if (i < GOODBYE_BROADCAST_COUNT - 1) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(GOODBYE_BROADCAST_DELAY_MS)
            );
        }
    }
}

}  // namespace ExoSend
