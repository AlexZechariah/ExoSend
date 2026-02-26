/**
 * @file DiscoveryService.cpp
 * @brief Implementation of UDP broadcast discovery service
 *
 * Handles automatic peer discovery on the local network using
 * UDP broadcast beacons with JSON payloads.
 */

#include "exosend/DiscoveryService.h"
#include "exosend/config.h"
#include "exosend/FingerprintUtils.h"
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
#include <chrono>
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
    , m_boundDiscoveryPort(0)
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

void DiscoveryService::setDeviceUuid(const std::string& uuid) {
    if (m_running.load()) {
        return;
    }

    if (uuid.empty() || uuid.size() > MAX_UUID_LENGTH) {
        return;
    }

    m_uuid = uuid;
}

void DiscoveryService::setCertificateFingerprintSha256Hex(const std::string& fingerprintSha256Hex) {
    if (m_running.load()) {
        return;
    }

    const std::string normalized = FingerprintUtils::normalizeSha256Hex(fingerprintSha256Hex);
    if (normalized.empty()) {
        m_certFingerprintSha256Hex.clear();
        return;
    }

    m_certFingerprintSha256Hex = normalized;
}

//=============================================================================
// Private Thread Functions
//=============================================================================

void DiscoveryService::transmitterThreadFunc() {
    // Properly seed mt19937 with full state_size draws from random_device.
    // On MSVC, random_device is backed by BCryptGenRandom -- never blocks.
    auto& rng = []() -> std::mt19937& {
        std::array<std::mt19937::result_type, std::mt19937::state_size> seedData;
        std::random_device rd;
        std::generate(seedData.begin(), seedData.end(), std::ref(rd));
        std::seed_seq seq(seedData.begin(), seedData.end());
        thread_local std::mt19937 rng_(seq);
        return rng_;
    }();

    // Get initial broadcast addresses.
    std::vector<std::string> broadcastAddresses = getBroadcastAddresses();
    auto lastRefresh    = std::chrono::steady_clock::now();
    int  burstRemaining = DISCOVERY_STARTUP_BURST_COUNT;

    while (!m_stopRequested.load()) {
        // Generate beacon JSON (includes discovery_port, timestamp_ms, proto_version).
        std::string beacon = generateBeaconJson();

        // Send to EVERY port in the discovery pool x EVERY adapter broadcast address.
        // This ensures peers bound to any pool port still receive our beacons.
        for (uint16_t targetPort : DISCOVERY_POOL_PORTS) {
            for (const auto& broadcastIp : broadcastAddresses) {
                sockaddr_in broadcastAddr{};
                broadcastAddr.sin_family = AF_INET;
                broadcastAddr.sin_port   = htons(targetPort);
                inet_pton(AF_INET, broadcastIp.c_str(), &broadcastAddr.sin_addr);
                sendto(m_udpSocket,
                       beacon.c_str(),
                       static_cast<int>(beacon.length()),
                       0,
                       reinterpret_cast<sockaddr*>(&broadcastAddr),
                       sizeof(broadcastAddr));
            }
        }

        // Determine sleep interval: startup burst or steady state.
        uint32_t baseIntervalMs;
        if (burstRemaining > 0) {
            baseIntervalMs = DISCOVERY_STARTUP_INTERVAL_MS;
            --burstRemaining;
        } else {
            baseIntervalMs = DISCOVERY_INTERVAL_MS;
        }

        // Apply jitter: +/- BEACON_JITTER_MAX_PERCENT% of base interval.
        // Desynchronises 100 simultaneous peers to prevent broadcast storms.
        const int jitterRange = static_cast<int>(baseIntervalMs) *
                                BEACON_JITTER_MAX_PERCENT / 100;
        std::uniform_int_distribution<int> dist(-jitterRange, jitterRange);
        const int sleepMs = (std::max)(500, static_cast<int>(baseIntervalMs) + dist(rng));

        // Refresh broadcast adapter list if interval has elapsed.
        // This handles VPN connect / WiFi roam / new NIC without restart.
        const auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - lastRefresh).count() >= BROADCAST_REFRESH_INTERVAL_S) {
            broadcastAddresses = getBroadcastAddresses();
            lastRefresh        = now;
        }

        // Wait for the jittered interval or stop signal.
        std::unique_lock<std::mutex> waitLock(m_stopCvMutex);
        m_stopCv.wait_for(waitLock,
                          std::chrono::milliseconds(sleepMs),
                          [this]() { return m_stopRequested.load(); });
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

            // Rate-limit check: drop flood packets BEFORE JSON parse to prevent
            // CPU amplification from beacon flood attacks.
            if (!m_rateLimiter.shouldProcess(senderIp)) {
                continue;
            }

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
    beacon["protocol_id"]   = PROTOCOL_ID;
    beacon["beacon_type"]   = BEACON_TYPE_ANNOUNCE;
    beacon["device_uuid"]   = m_uuid;
    beacon["display_name"]  = m_displayName;
    beacon["os_platform"]   = OS_PLATFORM;
    beacon["tcp_port"]      = m_tcpPort;

    // v0.3 fields (new -- v0.2 parsers silently ignore unknown JSON keys).
    beacon["discovery_port"] = m_boundDiscoveryPort;
    beacon["timestamp_ms"]   = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    beacon["proto_version"]  = 3;

    if (!m_certFingerprintSha256Hex.empty()) {
        beacon["cert_fingerprint_sha256"] = m_certFingerprintSha256Hex;
    }

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

    // Optional anti-replay timestamp check.
    // timestamp_ms is absent in v0.2 beacons -- skip check for backward compat.
    if (beacon.contains("timestamp_ms")) {
        const int64_t beaconTime = beacon["timestamp_ms"].get<int64_t>();
        const int64_t localTime  = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const int64_t ageDelta = std::abs(localTime - beaconTime);
        if (ageDelta > BEACON_TIMESTAMP_MAX_AGE_MS) {
            std::cerr << "[Discovery] Beacon from " << senderIp
                      << " rejected: timestamp age " << ageDelta
                      << " ms (limit " << BEACON_TIMESTAMP_MAX_AGE_MS << " ms)\n";
            return;
        }
    }

    // Goodbye beacon: remove peer only if the goodbye came from the known IP
    // of that peer. This prevents a spoofed goodbye from removing a live peer.
    if (beacon.contains("beacon_type") && beacon["beacon_type"] == BEACON_TYPE_GOODBYE) {
        std::lock_guard<std::mutex> lock(m_peerMutex);
        auto it = m_peers.find(uuid);
        if (it != m_peers.end()) {
            if (it->second.ipAddress == senderIp) {
                std::cout << "[Discovery] Peer departed (goodbye validated): "
                          << uuid << " (" << senderIp << ")\n";
                m_peers.erase(it);
            } else {
                std::cerr << "[Discovery] Goodbye from " << senderIp
                          << " claimed UUID " << uuid
                          << " (peer known at " << it->second.ipAddress
                          << ") -- IGNORED (possible spoofing attempt)\n";
            }
        }
        return;
    }

    // Original beacon processing (announce type or legacy without type)
    if (!beacon.contains("tcp_port")) {
        return;
    }

    std::string displayName = beacon["display_name"];
    uint16_t tcpPort = beacon["tcp_port"];
    std::string fingerprint;
    if (beacon.contains("cert_fingerprint_sha256") && beacon["cert_fingerprint_sha256"].is_string()) {
        fingerprint = FingerprintUtils::normalizeSha256Hex(beacon["cert_fingerprint_sha256"].get<std::string>());
    }

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
        it->second.displayName = displayName;
        it->second.ipAddress = senderIp;
        it->second.tcpPort = tcpPort;
        if (!fingerprint.empty()) {
            it->second.certFingerprintSha256Hex = fingerprint;
        }
    } else {
        // Add new peer
        PeerInfo peer(uuid, displayName, senderIp, tcpPort, fingerprint);
        m_peers[uuid] = peer;
    }
}

//=============================================================================
// Socket Management
//=============================================================================

bool DiscoveryService::initializeSocket() {
    // Initialize Winsock once for this service instance.
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Discovery] WSAStartup failed\n";
        return false;
    }

    for (uint16_t port : DISCOVERY_POOL_PORTS) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            std::cerr << "[Discovery] socket() failed: " << WSAGetLastError()
                      << " -- cannot create UDP socket\n";
            WSACleanup();
            return false;
        }

        // Enable SO_BROADCAST for sending broadcast beacons.
        int broadcastEnable = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       reinterpret_cast<char*>(&broadcastEnable),
                       sizeof(broadcastEnable)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            std::cerr << "[Discovery] SO_BROADCAST failed: " << WSAGetLastError() << "\n";
            return false;
        }

        // Expand UDP receive buffer to absorb bursts from up to 100 simultaneous peers.
        // Non-fatal if Windows clamps the value -- log actual size and continue.
        int rcvBuf = UDP_RECV_BUF_SIZE;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<char*>(&rcvBuf), sizeof(rcvBuf));
        int actualBuf = 0;
        int optLen = sizeof(actualBuf);
        if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                       reinterpret_cast<char*>(&actualBuf), &optLen) == 0) {
            std::cout << "[Discovery] UDP recv buffer: requested " << UDP_RECV_BUF_SIZE
                      << " bytes, actual " << actualBuf << " bytes\n";
        }

        sockaddr_in localAddr{};
        localAddr.sin_family      = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port        = htons(port);

        if (bind(sock, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) == 0) {
            m_udpSocket          = sock;
            m_socketInitialized  = true;
            m_boundDiscoveryPort = port;
            std::cout << "[Discovery] Bound UDP discovery socket to port " << port << "\n";
            return true;
        }

        const int err = WSAGetLastError();
        closesocket(sock);
        std::cout << "[Discovery] Port " << port << " unavailable (WSA " << err
                  << "), trying next pool port\n";
    }

    WSACleanup();
    std::cerr << "[Discovery] All discovery pool ports unavailable. Tried: "
              << "41000, 42100, 43210, 43500, 45100, 46000, 46100, 47100, 47500, 48100. "
              << "Cannot start discovery service.\n";
    return false;
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

    m_boundDiscoveryPort = 0;
}

//=============================================================================
// Goodbye Beacon Protocol
//=============================================================================

void DiscoveryService::broadcastGoodbye() {
    std::vector<std::string> broadcastAddresses = getBroadcastAddresses();

    json beacon;
    beacon["protocol_id"]    = PROTOCOL_ID;
    beacon["beacon_type"]    = BEACON_TYPE_GOODBYE;
    beacon["device_uuid"]    = m_uuid;
    beacon["display_name"]   = m_displayName;
    beacon["discovery_port"] = m_boundDiscoveryPort;
    beacon["timestamp_ms"]   = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    beacon["proto_version"]  = 3;

    std::string goodbyeBeacon = beacon.dump();

    // Broadcast goodbye multiple times to all pool ports for reliability.
    // Receivers validate the sender IP before acting on goodbye beacons.
    for (int i = 0; i < GOODBYE_BROADCAST_COUNT; ++i) {
        for (uint16_t targetPort : DISCOVERY_POOL_PORTS) {
            for (const auto& broadcastIp : broadcastAddresses) {
                sockaddr_in broadcastAddr{};
                broadcastAddr.sin_family = AF_INET;
                broadcastAddr.sin_port   = htons(targetPort);
                inet_pton(AF_INET, broadcastIp.c_str(), &broadcastAddr.sin_addr);
                sendto(m_udpSocket,
                       goodbyeBeacon.c_str(),
                       static_cast<int>(goodbyeBeacon.length()),
                       0,
                       reinterpret_cast<sockaddr*>(&broadcastAddr),
                       sizeof(broadcastAddr));
            }
        }

        if (i < GOODBYE_BROADCAST_COUNT - 1) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(GOODBYE_BROADCAST_DELAY_MS));
        }
    }
}

//=============================================================================
// Public helpers (including test helpers)
//=============================================================================

bool DiscoveryService::hasPeerByIp(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(m_peerMutex);
    for (const auto& [uuid, peer] : m_peers) {
        if (peer.ipAddress == ip) return true;
    }
    return false;
}

void DiscoveryService::injectPeerForTesting(const std::string& uuid,
                                            const std::string& displayName,
                                            const std::string& ip,
                                            uint16_t tcpPort) {
    PeerInfo peer(uuid, displayName, ip, tcpPort, "");
    std::lock_guard<std::mutex> lock(m_peerMutex);
    m_peers[uuid] = peer;
}

bool DiscoveryService::hasPeer(const std::string& uuid) const {
    std::lock_guard<std::mutex> lock(m_peerMutex);
    return m_peers.count(uuid) > 0;
}

void DiscoveryService::simulateIncomingBeacon(const std::string& beaconJson,
                                              const std::string& senderIp) {
    // Bypasses the rate limiter so tests can control rate-limit behavior directly.
    parseBeacon(beaconJson, senderIp);
}

std::string DiscoveryService::generateBeaconJsonForTesting() const {
    return generateBeaconJson();
}

}  // namespace ExoSend
