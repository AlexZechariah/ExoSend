/**
 * @file UuidGenerator.h
 * @brief UUID version 4 generation utility
 *
 * Provides centralized UUID generation to avoid code duplication
 * across DiscoveryService, TransferSession, and SettingsManager.
 */

#pragma once

#include <string>
#include <random>
#include <sstream>
#include <iomanip>

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
     * Uses a Mersenne Twister PRNG seeded by std::random_device.
     * Thread-safe: uses thread-local storage for the RNG.
     */
    static std::string generate() {
        // Thread-local RNG for thread safety
        thread_local std::random_device rd;
        thread_local std::mt19937 gen(rd());
        thread_local std::uniform_int_distribution<> dis(0, 15);
        thread_local std::uniform_int_distribution<> dis2(8, 11);

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');

        // xxxxxxxx
        for (int i = 0; i < 8; ++i) {
            oss << dis(gen);
        }
        oss << '-';

        // xxxx
        for (int i = 0; i < 4; ++i) {
            oss << dis(gen);
        }
        oss << '-';

        // 4xxx (version 4)
        oss << '4';
        for (int i = 0; i < 3; ++i) {
            oss << dis(gen);
        }
        oss << '-';

        // yxxx (variant: 10xx in binary = 8, 9, a, or b)
        oss << std::hex << dis2(gen);
        for (int i = 0; i < 3; ++i) {
            oss << dis(gen);
        }
        oss << '-';

        // xxxxxxxxxxxx
        for (int i = 0; i < 12; ++i) {
            oss << dis(gen);
        }

        return oss.str();
    }

    /**
     * @brief Generate a prefixed ID (e.g., "sess_xxxx-xxxx...")
     * @param prefix String prefix to prepend
     * @return Prefixed ID string
     */
    static std::string generateWithPrefix(const std::string& prefix) {
        // Thread-local RNG for thread safety
        thread_local std::random_device rd;
        thread_local std::mt19937 gen(rd());
        thread_local std::uniform_int_distribution<> dis(0, 15);

        std::ostringstream oss;
        oss << prefix;

        for (int i = 0; i < 16; ++i) {
            if (i == 4 || i == 8 || i == 12) {
                oss << '-';
            }
            oss << std::hex << dis(gen);
        }

        return oss.str();
    }

private:
    // Private constructor - all methods are static
    UuidGenerator() = delete;
};

}  // namespace ExoSend
