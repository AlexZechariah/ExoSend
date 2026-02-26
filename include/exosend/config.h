/**
 * @file config.h
 * @brief Configuration constants for ExoSend
 *
 * This file contains all compile-time configuration constants used throughout
 * the ExoSend application, including network ports, timing values, buffer sizes,
 * protocol identifiers, and TLS/SSL configuration.
 *
 * All constants are organized into logical groups and documented with their
 * purpose and usage. These values can be modified at compile-time to customize
 * ExoSend behavior.
 *
 * @note Changes to these constants may affect protocol compatibility.
 *       Ensure all peers use compatible configurations.
 */

#pragma once

#include <array>
#include <cstdint>
#include <winsock2.h>

/**
 * @namespace ExoSend
 * @brief ExoSend namespace containing all public APIs
 *
 * All ExoSend classes, functions, and constants are within this namespace to
 * prevent naming conflicts with user code or third-party libraries.
 */
namespace ExoSend {

//=========================================================================
// Network Ports
//=========================================================================

/** @defgroup NetworkPorts Network Ports Configuration
 * @brief UDP discovery port pool and dynamic TCP port for ExoSend
 *
 * UDP discovery uses a port pool: DiscoveryService binds the first available
 * port and broadcasts beacons to ALL pool ports so peers on different pool
 * ports still discover each other. TCP transfer binds to port 0 and reads
 * the OS-assigned ephemeral port via getsockname().
 * @{
 */

/**
 * @brief UDP discovery port pool (10 ports, IANA registered range 40000-49151).
 *
 * DiscoveryService iterates this list and binds the first available port.
 * Beacons are broadcast to EVERY port in this pool so peers bound to
 * different pool ports still discover each other.
 *
 * Port selection rationale (researched 2026-02):
 *   41000: Low conflict -- no known IANA registration or common app default
 *   42100: Low conflict -- avoids VTun at 42000 (IANA registered)
 *   43210: Low conflict -- no known registration; memorable but not a documented default
 *   43500: Low conflict -- clear of 44818 (EtherNet/IP, IANA, common in industrial Win)
 *   45100: Low conflict -- avoids 44818 and 45000 (ASMP)
 *   46000: Low conflict -- no known IANA registration
 *   46100: Low conflict -- no known registration
 *   47100: Low conflict -- avoids 47001 (WinRM, Windows Remote Management)
 *   47500: Low conflict -- no known registration
 *   48100: Low conflict -- avoids 48000 (Nimbus, IANA registered)
 *
 * CAUTION: Port 38888 (original choice) is FineReport's WebSocket port -- AVOIDED.
 * CAUTION: Port 38889 is FineReport NGINX proxy port -- AVOIDED.
 * All pool ports are in IANA registered range (1024-49151) to avoid Windows
 * ephemeral ports (49152-65535) which the OS uses for outbound connections.
 */
constexpr std::array<uint16_t, 10> DISCOVERY_POOL_PORTS = {
    41000, 42100, 43210, 43500, 45100,
    46000, 46100, 47100, 47500, 48100
};

/**
 * @brief TCP transfer port: documentation only.
 *
 * TransferServer binds to port 0 so the OS assigns a free ephemeral port
 * (49152-65535) and reads it via getsockname(). This constant exists for
 * backward-compatible code that previously referenced TCP_PORT_DEFAULT.
 */
constexpr uint16_t TCP_PORT_DEFAULT = 0;

/** @} */ // end of NetworkPorts

//=========================================================================
// Timing
//=========================================================================

/** @defgroup Timing Timing Configuration
 * @brief Timing intervals and timeouts (in milliseconds)
 *
 * These constants control the timing of various operations including
 * discovery intervals, peer timeouts, and cleanup intervals.
 * @{
 */

/**
 * @brief Steady-state interval between discovery beacon broadcasts.
 *
 * 5 seconds keeps WiFi broadcast load below 3.2% of 6 Mbps basic rate at
 * 100 nodes (10 pool ports x 100 nodes x 1 pkt/5s = 200 pkts/s = ~0.3 Mbps).
 * ExoSend sends an initial burst of DISCOVERY_STARTUP_BURST_COUNT beacons at
 * DISCOVERY_STARTUP_INTERVAL_MS for fast initial peer discovery, then switches
 * to this steady-state interval.
 */
constexpr uint32_t DISCOVERY_INTERVAL_MS = 5000;

/**
 * @brief Fast startup beacon interval.
 *
 * Used for the first DISCOVERY_STARTUP_BURST_COUNT beacons only.
 * Allows peers to appear quickly after launching ExoSend without
 * waiting the full steady-state interval.
 */
constexpr uint32_t DISCOVERY_STARTUP_INTERVAL_MS = 2000;

/**
 * @brief Number of beacons to send at DISCOVERY_STARTUP_INTERVAL_MS.
 *
 * After this many beacons, the transmitter switches to DISCOVERY_INTERVAL_MS.
 */
constexpr int DISCOVERY_STARTUP_BURST_COUNT = 5;

/**
 * @brief Peer inactivity timeout
 *
 * If no beacon is received from a peer for 10000ms (10 seconds),
 * the peer is removed from the peer list. This ensures stale peers
 * are cleaned up properly.
 */
constexpr uint32_t PEER_TIMEOUT_MS = 10000;

/**
 * @brief Goodbye beacon broadcast count
 *
 * When a peer quits, it broadcasts a goodbye beacon this many times
 * to ensure at least one copy reaches all peers on the network.
 */
constexpr int GOODBYE_BROADCAST_COUNT = 3;

/**
 * @brief Delay between goodbye beacon broadcasts
 *
 * Wait 50ms between each goodbye broadcast to account for
 * network collisions and ensure reliable delivery.
 */
constexpr uint32_t GOODBYE_BROADCAST_DELAY_MS = 50;

/**
 * @brief Beacon type field values
 *
 * Identifies the type of discovery beacon being transmitted.
 */
constexpr const char* BEACON_TYPE_ANNOUNCE = "announce";  ///< Normal presence beacon
constexpr const char* BEACON_TYPE_GOODBYE = "goodbye";    ///< Departure notification

/**
 * @brief Garbage collection interval
 *
 * The peer list is scanned every 5000ms (5 seconds) to remove
 * stale peers that have exceeded the timeout threshold.
 */
constexpr uint32_t GC_INTERVAL_MS = 5000;

/** @} */ // end of Timing

//=========================================================================
// Security and Rate Limiting
//=========================================================================

/** @defgroup SecurityConfig Security and Rate Limiting Configuration
 * @brief Constants for beacon flood protection, anti-replay, and jitter.
 * @{
 */

/**
 * @brief Maximum beacon packets processed per source IP within the sliding window.
 *
 * Excess packets are dropped BEFORE JSON parse to prevent CPU amplification
 * from flood attacks. 10 beacons / 5 seconds is well above normal peer activity.
 */
constexpr size_t BEACON_RATE_LIMIT_MAX_COUNT = 10;

/**
 * @brief Sliding window duration for per-IP beacon rate limiting (ms).
 */
constexpr int64_t BEACON_RATE_LIMIT_WINDOW_MS = 5000;

/**
 * @brief Maximum number of distinct source IPs tracked by the beacon rate limiter.
 *
 * UDP source IPs can be spoofed. Bounding the in-memory tracking table prevents
 * unbounded growth under a spoofed-source flood.
 */
constexpr size_t BEACON_RATE_LIMIT_MAX_IPS = 2048;

/**
 * @brief Maximum TCP connection attempts processed per source IP within the sliding window.
 *
 * This bounds thread and TLS-handshake churn under connection floods.
 */
constexpr size_t TRANSFER_CONN_RATE_LIMIT_MAX_COUNT = 20;

/**
 * @brief Sliding window duration for per-IP TCP connection rate limiting (ms).
 */
constexpr int64_t TRANSFER_CONN_RATE_LIMIT_WINDOW_MS = 10000;

/**
 * @brief Maximum number of distinct source IPs tracked by the TCP connection rate limiter.
 */
constexpr size_t TRANSFER_CONN_RATE_LIMIT_MAX_IPS = 2048;

/**
 * @brief Maximum age of a beacon's timestamp_ms field before rejection.
 *
 * Beacons whose timestamp_ms differs from the local wall clock by more than
 * this value are rejected as likely replays or stale packets.
 * 60 seconds covers worst-case NTP skew on offline machines
 * (Kerberos uses 5 minutes; we use 60s for stricter protection).
 *
 * IMPORTANT: timestamp_ms is optional for backward compatibility with v0.2
 * peers. If the field is absent, the timestamp check is skipped entirely.
 */
constexpr int64_t BEACON_TIMESTAMP_MAX_AGE_MS = 300000; // 300 s (5 min) -- tolerates VMware clock drift on paused/resumed VMs

/**
 * @brief Maximum jitter applied to beacon interval as a percentage.
 *
 * Each beacon cycle adds a random offset of up to +/- this percentage of
 * the current interval. At 20% with DISCOVERY_INTERVAL_MS=5000ms: actual
 * interval is 4000-6000ms. This desynchronises 100 peers to prevent
 * simultaneous broadcast storms (thundering herd).
 */
constexpr int BEACON_JITTER_MAX_PERCENT = 20;

/**
 * @brief UDP socket receive buffer size (bytes).
 *
 * 512 KB absorbs bursts from up to 100 peers broadcasting simultaneously.
 * Windows may silently clamp this value; always verify with getsockopt()
 * and log the actual buffer size. Non-fatal if the request is partially honored.
 */
constexpr int UDP_RECV_BUF_SIZE = 524288;  // 512 KB

/**
 * @brief Broadcast adapter list refresh interval (seconds).
 *
 * The list of network adapter broadcast addresses is refreshed at this interval
 * to pick up new adapters (VPN connect, WiFi roam, NIC plug) without requiring
 * a service restart.
 */
constexpr int BROADCAST_REFRESH_INTERVAL_S = 60;

/** @} */ // end of SecurityConfig

//=========================================================================
// Buffer Sizes
//=========================================================================

/** @defgroup BufferSizes Buffer Size Configuration
 * @brief Buffer sizes for various operations
 *
 * These constants define the size of buffers used for file transfer,
 * protocol messages, and string operations.
 * @{
 */

/**
 * @brief File transfer buffer size
 *
 * Files are transferred in chunks of 65536 bytes (64 KB).
 * This size provides a good balance between throughput and memory usage.
 * Larger buffers may improve performance but use more RAM.
 */
constexpr size_t BUFFER_SIZE = 262144;  // 256 KB

/**
 * @brief Binary protocol header size
 *
 * The ExoSend protocol header is exactly 512 bytes.
 * This header contains metadata about the transfer including
 * file size, filename, and packet type.
 */
constexpr size_t HEADER_SIZE = 512;

/**
 * @brief Maximum discovery beacon size
 *
 * JSON beacons are limited to 4096 bytes to prevent memory exhaustion
 * attacks from malformed beacons.
 */
constexpr size_t MAX_BEACON_SIZE = 4096;

/**
 * @brief Maximum display name length
 *
 * Peer display names are limited to 64 characters.
 * Longer names are truncated to this length.
 */
constexpr size_t MAX_DISPLAY_NAME = 64;

/**
 * @brief Maximum UUID string length
 *
 * Device UUIDs are limited to 64 characters when represented as strings.
 * This accommodates standard UUID formats and provides a safety margin.
 */
constexpr size_t MAX_UUID_LENGTH = 64;

/**
 * @brief Default maximum allowed incoming offer size (bytes)
 *
 * This is a safety and DoS mitigation guardrail. Users may override this
 * limit in settings.
 */
constexpr uint64_t DEFAULT_MAX_INCOMING_SIZE_BYTES = 10ULL * 1024ULL * 1024ULL * 1024ULL;  // 10 GB

/** @} */ // end of BufferSizes

//=========================================================================
// Protocol
//=========================================================================

/** @defgroup Protocol Protocol Identifiers
 * @brief Protocol identification strings
 *
 * These constants define protocol identifiers used for compatibility checks
 * and peer identification.
 * @{
 */

/**
 * @brief Protocol identifier string
 *
 * This string identifies the ExoSend protocol version.
 * Peers with mismatched protocol IDs may not be compatible.
 */
constexpr const char* PROTOCOL_ID = "EXOSEND_V1";

/**
 * @brief Operating system platform identifier
 *
 * Identifies this peer as running on Windows 10.
 * Used for peer information display and compatibility checks.
 */
constexpr const char* OS_PLATFORM = "Windows 10";

/** @} */ // end of Protocol

//=========================================================================
// Socket Configuration
//=========================================================================

/** @defgroup SocketConfig Socket Configuration
 * @brief Socket addresses and connection settings
 *
 * These constants define default socket addresses and connection parameters.
 * @{
 */

/**
 * @brief IPv4 broadcast address
 *
 * Used for sending discovery beacons to all devices on the local network.
 * This address sends to 255.255.255.255, reaching all hosts on the LAN.
 */
constexpr const char* BROADCAST_ADDRESS = "255.255.255.255";

/**
 * @brief Localhost IP address
 *
 * The loopback address 127.0.0.1 for local testing.
 * Used for connecting to services on the same machine.
 */
constexpr const char* LOCALHOST_IP = "127.0.0.1";

/**
 * @brief Maximum pending connections
 *
 * The maximum length of the pending connections queue for listening sockets.
 * This value is typically 5 on Windows systems.
 */
constexpr int SOMAXCONN_VALUE = SOMAXCONN;

/** @} */ // end of SocketConfig

//=========================================================================
// Binary Protocol
//=========================================================================

/** @defgroup BinaryProtocol Binary Protocol Configuration
 * @brief Constants for the ExoSend binary transfer protocol
 *
 * These constants define the format of the 512-byte binary header
 * used for file transfer negotiation.
 * @{
 */

/**
 * @brief Magic number for protocol identification
 *
 * The first 4 bytes of every ExoSend header must contain this value
 * (0x45584F53 = ASCII "EXOS"). This validates that the received data
 * is an ExoSend protocol message.
 */
constexpr uint32_t MAGIC_NUMBER = 0x45584F53;  // ASCII: "EXOS"

/**
 * @brief Maximum filename length in header
 *
 * Filenames in the transfer header are limited to 256 characters.
 * Longer filenames are truncated during header serialization.
 */
constexpr size_t MAX_FILENAME_LENGTH = 256;

/**
 * @brief SHA-256 hash size in bytes
 *
 * SHA-256 produces a 32-byte (256-bit) hash value.
 * This hash is used to verify file integrity after transfer.
 */
constexpr size_t HASH_SIZE = 32;  // SHA-256 produces 32 bytes

/** @} */ // end of BinaryProtocol

//=========================================================================
// Transfer Configuration
//=========================================================================

/** @defgroup TransferConfig Transfer Configuration
 * @brief File transfer timing and retry settings
 *
 * These constants control connection timeouts, retry behavior,
 * and transfer-related timing parameters.
 * @{
 */

/**
 * @brief Connection timeout
 *
 * If a connection cannot be established within 30000ms (30 seconds),
 * the transfer attempt is aborted.
 */
constexpr uint32_t CONNECTION_TIMEOUT_MS = 30000;  // 30 seconds

/**
 * @brief Delay between send retries
 *
 * When a partial send occurs, wait 100ms before retrying.
 * This prevents busy-waiting and allows network conditions to stabilize.
 */
constexpr uint32_t SEND_RETRY_DELAY_MS = 100;       // 100ms between retries

/**
 * @brief Maximum number of send retries
 *
 * If a send operation fails after 5 retry attempts, the transfer
 * is considered failed and the connection is closed.
 */
constexpr int MAX_SEND_RETRIES = 5;                 // Max retries for partial sends

/** @} */ // end of TransferConfig

//=========================================================================
// Multi-threading Configuration
//=========================================================================

/** @defgroup Threading Multi-threading Configuration
 * @brief Thread pool and concurrency settings
 *
 * These constants control the maximum number of concurrent transfers,
 * queue timeouts, and progress update throttling.
 * @{
 */

/**
 * @brief Maximum concurrent transfer sessions
 *
 * No more than 3 simultaneous transfers can be active at once.
 * Additional transfer requests are queued until a session completes.
 */
constexpr size_t MAX_CONCURRENT_TRANSFERS = 3;

/**
 * @brief Maximum concurrent incoming client handler threads
 *
 * TransferServer spawns a dedicated handler thread per accepted TCP connection.
 * This limit bounds resource usage under connection floods (including TLS
 * handshake floods and pairing requests).
 */
constexpr size_t MAX_CONCURRENT_INCOMING_CLIENT_THREADS = 16;

/**
 * @brief Transfer queue timeout
 *
 * Queued transfer requests expire after 30000ms (30 seconds)
 * if they cannot be processed.
 */
constexpr uint32_t TRANSFER_QUEUE_TIMEOUT_MS = 30000;    // 30 seconds

/**
 * @brief Session cleanup interval
 *
 * Completed transfer sessions are cleaned up every 5000ms (5 seconds).
 * This interval balances prompt cleanup with minimal overhead.
 */
constexpr uint32_t SESSION_CLEANUP_INTERVAL_MS = 5000;    // 5 seconds

/**
 * @brief Progress update throttle interval
 *
 * UI progress updates are throttled to 50ms intervals to prevent
 * UI thread saturation. Updates more frequent than this are coalesced.
 */
constexpr uint32_t PROGRESS_THROTTLE_MS = 50;             // 50ms

/**
 * @brief Session completion polling interval
 *
 * When waiting for a transfer session to complete, the calling thread
 * polls at this interval. Lower values increase CPU usage but provide
 * faster responsiveness; higher values reduce CPU usage but may delay
 * detection of session completion.
 */
constexpr uint32_t SESSION_POLL_INTERVAL_MS = 100;        // 100ms

/**
 * @brief Maximum session ID length
 *
 * Session identifiers are limited to 64 characters.
 * Session IDs are generated from UUIDs or other unique identifiers.
 */
constexpr size_t MAX_SESSION_ID_LENGTH = 64;

/** @} */ // end of Threading

//=========================================================================
// TLS/SSL Configuration
//=========================================================================

/** @defgroup TLS TLS/SSL Configuration
 * @brief Transport Layer Security settings for secure transfers
 *
 * These constants configure TLS encryption for file transfers.
 * TLS 1.3 is used to secure data in transit.
 * @{
 */

/**
 * @brief TLS enabled flag
 *
 * When true, all file transfers use TLS encryption.
 * Set to false only for debugging purposes (not recommended for production).
 */
constexpr bool TLS_ENABLED = true;                      // Enable/disable TLS

/**
 * @brief Minimum TLS version
 *
 * The minimum accepted TLS version is "TLSv1.3".
 * TLS 1.2 and below are intentionally rejected for maximum security and simpler
 * protocol surface.
 */
constexpr const char* TLS_VERSION = "TLSv1.3";          // Minimum TLS version (docs)

/**
 * @brief TLS cipher suite specification
 *
 * Specifies which cipher suites are acceptable for TLS connections.
 * This configuration uses strong ciphers and excludes weak ones.
 */
// Added !RC4 (RC4 stream cipher is cryptographically broken since 2013) and
// !EXPORT (export-grade ciphers are banned; FREAK/LOGJAM attacks exploit them).
constexpr const char* TLS_CIPHER_SUITE = "HIGH:!aNULL:!MD5:!3DES:!RC4:!EXPORT";

/**
 * @brief TLS 1.3 cipher suite specification
 *
 * TLS 1.3 cipher suites are configured separately from the legacy TLS <= 1.2
 * cipher list. ExoSend restricts to the strong, widely-supported TLS 1.3
 * suites provided by OpenSSL.
 */
constexpr const char* TLS13_CIPHER_SUITES =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";

/**
 * @brief Supported key exchange groups (ECDHE)
 *
 * Keep the group list small and modern for predictable security properties.
 * X25519 is preferred when available.
 */
constexpr const char* TLS_GROUPS_LIST = "X25519:P-256:P-384";

/**
 * @brief Certificate directory name
 *
 * TLS certificates are stored in the "certs" subdirectory of
 * %LOCALAPPDATA%\ExoSend\.
 */
constexpr const char* CERT_DIR = "certs";

/**
 * @brief Server certificate filename
 *
 * The PEM-encoded certificate file for TLS identification.
 */
constexpr const char* CERT_FILE = "server.crt";

/**
 * @brief Private key filename
 *
 * The PEM-encoded private key file for TLS operations.
 * This file must be kept secure and not shared.
 */
constexpr const char* KEY_FILE = "server.key";

/**
 * @brief Certificate validity period in days
 *
 * Self-signed certificates are valid for 365 days (1 year).
 * After expiration, a new certificate is automatically generated.
 */
constexpr int CERT_VALIDITY_DAYS = 365;                 // 1 year self-signed cert

/**
 * @brief TLS handshake timeout
 *
 * If the TLS handshake does not complete within 10000ms (10 seconds),
 * the connection is aborted.
 */
constexpr uint32_t TLS_HANDSHAKE_TIMEOUT_MS = 10000;   // 10 seconds

/**
 * @brief Maximum TLS record size
 *
 * The maximum TLS record size is 16384 bytes (16 KB).
 * This is a limitation of the TLS protocol.
 */
constexpr size_t TLS_MAX_PACKET_SIZE = 16384;          // Max TLS record size (16KB)

/**
 * @brief OpenSSL security options bitmask
 *
 * Bit flags for SSL_CTX_set_options() to disable insecure protocols.
 * These flags disable SSLv2, SSLv3, TLSv1.0, TLSv1.1, and compression.
 *
 * Bit breakdown:
 * - 0x00000080: SSL_OP_NO_SSLv2
 * - 0x02000000: SSL_OP_NO_SSLv3
 * - 0x04000000: SSL_OP_NO_TLSv1
 * - 0x08000000: SSL_OP_NO_TLSv1_1
 * - 0x00020000: SSL_OP_NO_COMPRESSION
 * - 0x00100000: SSL_OP_SINGLE_DH_USE
 * - 0x00200000: SSL_OP_SINGLE_ECDH_USE
 */
constexpr uint64_t TLS_SECURITY_OPTIONS = 0x00000080UL |  // SSL_OP_NO_SSLv2
                                          0x02000000UL |  // SSL_OP_NO_SSLv3
                                          0x04000000UL |  // SSL_OP_NO_TLSv1
                                          0x08000000UL |  // SSL_OP_NO_TLSv1_1
                                          0x00020000UL |  // SSL_OP_NO_COMPRESSION
                                          0x00100000UL |  // SSL_OP_SINGLE_DH_USE
                                          0x00200000UL;   // SSL_OP_SINGLE_ECDH_USE

/** @} */ // end of TLS

}  // namespace ExoSend
