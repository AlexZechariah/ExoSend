/**
 * @file TransferHeader.h
 * @brief Binary protocol header for file transfers
 */

#pragma once

#include "config.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <winsock2.h>
#include <ws2tcpip.h>

// Ensure Windows has inet_pton and inet_ntop
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

namespace ExoSend {

/**
 * @brief Packet types for the ExoSend binary transfer protocol
 *
 * These packet types define the state machine for file transfer negotiation.
 */
enum class PacketType : uint8_t {
    OFFER = 0x01,   ///< Sender offers a file for transfer
    ACCEPT = 0x02,  ///< Receiver accepts the file transfer
    REJECT = 0x03,  ///< Receiver rejects the file transfer
    BUSY = 0x04     ///< Receiver is busy and cannot accept
};

/**
 * @brief Transfer states for the file transfer state machine
 */
enum class TransferState : uint8_t {
    IDLE = 0,           ///< Socket connected, no transfer in progress
    NEGOTIATING = 1,    ///< Exchanging headers (offer/accept/reject)
    STREAMING = 2,      ///< Transferring file data
    FINALIZE = 3        ///< Verifying transfer completion
};

/**
 * @brief Binary protocol header for ExoSend file transfers
 *
 * This header is sent before any file data to negotiate the transfer.
 * It contains metadata about the file being transferred.
 *
 * Header Layout (512 bytes total):
 * - Offset 0-3:   Magic number (4 bytes)
 * - Offset 4:     Packet type (1 byte)
 * - Offset 5-12:  File size (8 bytes)
 * - Offset 13-14: Filename length (2 bytes)
 * - Offset 15-270: Filename (256 bytes)
 * - Offset 271-511: Padding (241 bytes)
 *
 * All integer fields use network byte order (Big-Endian).
 * Use htonl/htons before sending and ntohl/ntohs after receiving.
 */
#pragma pack(push, 1)
struct ExoHeader {
    uint32_t magic;              ///< Magic number 0x45584F53
    uint8_t packetType;          ///< Packet type from PacketType enum
    uint64_t fileSize;           ///< File size in bytes
    uint16_t filenameLength;     ///< Length of filename (max 256)
    char filename[256];          ///< UTF-8 filename (zero-padded)
    uint8_t padding[241];        ///< Zero-filled padding to make 512 bytes

    /**
     * @brief Default constructor - initializes header to zeros
     */
    ExoHeader() {
        std::memset(this, 0, sizeof(ExoHeader));
    }

    /**
     * @brief Create a header with specific values
     * @param type Packet type (OFFER, ACCEPT, REJECT, BUSY)
     * @param size File size in bytes
     * @param name Filename (will be truncated to 255 chars if needed)
     */
    ExoHeader(PacketType type, uint64_t size, const std::string& name)
        : magic(MAGIC_NUMBER), packetType(static_cast<uint8_t>(type)), fileSize(size),
          filenameLength(0)
    {
        std::memset(padding, 0, sizeof(padding));
        setFilename(name);
    }

    /**
     * @brief Set the filename field (with length validation)
     * @param name The filename to set
     *
     * Truncates to 255 characters if needed and updates filenameLength.
     * The filename buffer is always null-terminated.
     */
    void setFilename(const std::string& name) {
        size_t maxLen = sizeof(filename) - 1;  // Leave room for null terminator
        size_t copyLen = (name.length() < maxLen) ? name.length() : maxLen;

        std::memset(filename, 0, sizeof(filename));
        std::memcpy(filename, name.c_str(), copyLen);
        filename[copyLen] = '\0';  // Ensure null termination

        filenameLength = static_cast<uint16_t>(copyLen);
    }

    /**
     * @brief Get the filename as a std::string
     * @return The filename string
     */
    std::string getFilename() const {
        return std::string(filename, filenameLength);
    }

    /**
     * @brief Serialize this header to network byte order for transmission
     * @param buffer Output buffer (must be at least 512 bytes)
     * @return true if successful
     *
     * Converts all integer fields to network byte order (Big-Endian)
     * and copies the structure to the buffer.
     */
    bool serializeToBuffer(uint8_t* buffer) const {
        if (!buffer) return false;

        // Create a copy with network byte order
        ExoHeader networkHeader = *this;
        networkHeader.magic = htonl(magic);
        networkHeader.fileSize = htonll(fileSize);
        networkHeader.filenameLength = htons(filenameLength);
        // packetType is 1 byte, no conversion needed
        // filename and padding are byte arrays, no conversion needed

        std::memcpy(buffer, &networkHeader, sizeof(ExoHeader));
        return true;
    }

    /**
     * @brief Deserialize header from network byte order after reception
     * @param buffer Input buffer (must be at least 512 bytes)
     * @return true if successful
     *
     * Copies from buffer and converts all integer fields from network
     * byte order (Big-Endian) to host byte order.
     */
    bool deserializeFromBuffer(const uint8_t* buffer) {
        if (!buffer) return false;

        std::memcpy(this, buffer, sizeof(ExoHeader));

        // Convert from network byte order to host byte order
        magic = ntohl(magic);
        fileSize = ntohll(fileSize);
        filenameLength = ntohs(filenameLength);
        // packetType is 1 byte, no conversion needed
        // filename and padding are byte arrays, no conversion needed

        return true;
    }

    /**
     * @brief Validate the header fields
     * @return true if header is valid
     *
     * Checks:
     * - Magic number matches 0x45584F53
     * - Packet type is valid (0x01-0x04)
     * - Filename length is <= 256
     */
    bool isValid() const {
        if (magic != MAGIC_NUMBER) {
            return false;
        }

        if (packetType < static_cast<uint8_t>(PacketType::OFFER) ||
            packetType > static_cast<uint8_t>(PacketType::BUSY)) {
            return false;
        }

        if (filenameLength > 256) {
            return false;
        }

        return true;
    }

    /**
     * @brief Get the packet type as an enum
     * @return Packet type enum value
     */
    PacketType getPacketType() const {
        return static_cast<PacketType>(packetType);
    }

    /**
     * @brief Get human-readable description of packet type
     * @return String describing the packet type
     */
    std::string getPacketTypeString() const {
        switch (getPacketType()) {
            case PacketType::OFFER:
                return "OFFER";
            case PacketType::ACCEPT:
                return "ACCEPT";
            case PacketType::REJECT:
                return "REJECT";
            case PacketType::BUSY:
                return "BUSY";
            default:
                return "UNKNOWN";
        }
    }

    /**
     * @brief Get file size as human-readable string
     * @return String like "1.5 MB" or "512 KB"
     */
    std::string getFileSizeString() const {
        const double KB = 1024.0;
        const double MB = 1024.0 * 1024.0;
        const double GB = 1024.0 * 1024.0 * 1024.0;

        if (fileSize >= GB) {
            return std::to_string(fileSize / GB) + " GB";
        } else if (fileSize >= MB) {
            return std::to_string(fileSize / MB) + " MB";
        } else if (fileSize >= KB) {
            return std::to_string(fileSize / KB) + " KB";
        } else {
            return std::to_string(fileSize) + " bytes";
        }
    }

private:
    /**
     * @brief Convert 64-bit value to network byte order
     * @param value Host byte order value
     * @return Network byte order value
     *
     * Windows doesn't have htonll, so we implement it.
     * Windows x86/x64 is always little-endian.
     */
    static uint64_t htonll(uint64_t value) {
        // Little-endian to big-endian conversion
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) |
               htonl(value >> 32);
    }

    /**
     * @brief Convert 64-bit value from network byte order
     * @param value Network byte order value
     * @return Host byte order value
     */
    static uint64_t ntohll(uint64_t value) {
        // Big-endian to little-endian conversion
        return ((uint64_t)ntohl(value & 0xFFFFFFFF) << 32) |
               ntohl(value >> 32);
    }
};
#pragma pack(pop)

static_assert(sizeof(ExoHeader) == HEADER_SIZE,
              "ExoHeader wire layout must be exactly HEADER_SIZE bytes");

}  // namespace ExoSend
