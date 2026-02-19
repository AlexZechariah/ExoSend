/**
 * @file UuidGenerator.h
 * @brief UUID version 4 generation utility
 *
 * Provides centralized UUID generation to avoid code duplication
 * across DiscoveryService, TransferSession, and SettingsManager.
 */

#pragma once

#include <string>
#include <iomanip>
#include <array>
#include <cstdint>
#include <sstream>
#include <random>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>  // Must be included before windows.h to avoid winsock.h conflicts
#include <windows.h>
#include <bcrypt.h>
#endif

namespace ExoSend {

/**
 * @class UuidGenerator
 * @brief Thread-safe UUID version 4 generator
 *
 * Generates random UUIDs conforming to RFC 4122 version 4 format:
 * xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 *
 * Thread Safety:
 * - The static generate() method is thread-safe due to thread_local storage
 */
class UuidGenerator {
public:
    /**
     * @brief Generate a random UUID v4
     * @return UUID string in standard format (e.g., "550e8400-e29b-41d4-a716-446655440000")
     *
     * Uses OS CSPRNG on Windows via BCryptGenRandom.
     */
    static std::string generate() {
        std::array<uint8_t, 16> bytes{};
        if (!fillRandom(bytes.data(), bytes.size())) {
            return {};
        }

        // RFC 4122 version 4
        bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
        // RFC 4122 variant (10xx)
        bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

        return formatUuid(bytes);
    }

    /**
     * @brief Generate a prefixed ID (e.g., "sess_xxxx-xxxx...")
     * @param prefix String prefix to prepend
     * @return Prefixed ID string
     */
    static std::string generateWithPrefix(const std::string& prefix) {
        std::array<uint8_t, 8> bytes{};
        if (!fillRandom(bytes.data(), bytes.size())) {
            return {};
        }

        std::ostringstream oss;
        oss << prefix << std::hex << std::setfill('0');

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i == 2 || i == 4 || i == 6) {
                oss << '-';
            }
            oss << std::setw(2) << static_cast<int>(bytes[i]);
        }

        return oss.str();
    }

private:
    // Private constructor - all methods are static
    UuidGenerator() = delete;

    static bool fillRandom(uint8_t* out, size_t len) {
        if (!out || len == 0) {
            return false;
        }

#ifdef _WIN32
        const NTSTATUS status = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(out),
            static_cast<ULONG>(len),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (BCRYPT_SUCCESS(status)) {
            return true;
        }

        // Fallback: best-effort entropy if BCrypt is unavailable in a constrained environment.
        std::random_device rd;
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>(rd());
        }
        return true;
#else
        (void)out;
        (void)len;
        return false;
#endif
    }

    static std::string formatUuid(const std::array<uint8_t, 16>& bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                oss << '-';
            }
            oss << std::setw(2) << static_cast<int>(bytes[i]);
        }

        return oss.str();
    }
};

}  // namespace ExoSend
