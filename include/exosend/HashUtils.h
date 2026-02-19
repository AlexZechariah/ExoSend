/**
 * @file HashUtils.h
 * @brief SHA-256 hash computation utilities
 */

#pragma once

#include "config.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ExoSend {

/**
 * @class HashUtils
 * @brief SHA-256 hashing utilities for file integrity verification
 *
 * This class provides static methods for computing SHA-256 hashes
 * of files and memory buffers using OpenSSL.
 *
 * Thread Safety:
 * - All methods are thread-safe (no shared state)
 * - Uses OpenSSL's SHA256 functions
 */
class HashUtils {
public:
    /**
     * @brief Compute SHA-256 hash of a file
     * @param filePath Path to the file to hash
     * @param hash Output buffer (must be at least HASH_SIZE bytes)
     * @param errorMsg Output error message if computation fails
     * @return true if successful, false otherwise
     *
     * Reads the entire file and computes its SHA-256 hash.
     * The hash is written to the provided buffer.
     */
    static bool computeFileHash(const std::string& filePath,
                                unsigned char* hash,
                                std::string& errorMsg);

    /**
     * @brief Compute SHA-256 hash of a memory buffer
     * @param data Pointer to the data to hash
     * @param size Size of the data in bytes
     * @return Vector containing the 32-byte hash
     *
     * Computes SHA-256 hash of the provided memory buffer.
     * Returns a vector with exactly HASH_SIZE (32) bytes.
     */
    static std::vector<unsigned char> computeBufferHash(const uint8_t* data,
                                                        size_t size);

    /**
     * @brief Convert binary hash to hexadecimal string
     * @param hash Binary hash (must be HASH_SIZE bytes)
     * @return Hexadecimal string representation (64 hex characters)
     *
     * Converts the 32-byte binary hash to a 64-character
     * hexadecimal string for display and comparison.
     */
    static std::string hashToString(const unsigned char* hash);

    /**
     * @brief Convert hexadecimal string to binary hash
     * @param hexString Hexadecimal string (64 characters)
     * @param hash Output buffer (must be at least HASH_SIZE bytes)
     * @return true if successful, false if invalid hex string
     *
     * Parses a 64-character hex string and writes the 32-byte
     * binary hash to the output buffer.
     */
    static bool stringToHash(const std::string& hexString,
                            unsigned char* hash);

    /**
     * @brief Compare two hashes for equality
     * @param hash1 First hash (HASH_SIZE bytes)
     * @param hash2 Second hash (HASH_SIZE bytes)
     * @return true if hashes are identical
     *
     * Constant-time comparison to prevent timing attacks.
     */
    static bool compareHashes(const unsigned char* hash1,
                             const unsigned char* hash2);

    /**
     * @brief Create a SHA-256 hash context for incremental hashing
     *
     * Use this class when you need to compute a hash incrementally
     * (e.g., while reading a file chunk by chunk).
     */
    class IncrementalHash {
    public:
        /**
         * @brief Constructor - initializes OpenSSL EVP digest context
         */
        IncrementalHash();

        /**
         * @brief Destructor - cleans up OpenSSL EVP context
         */
        ~IncrementalHash();

        // Prevent copying (context cannot be copied)
        IncrementalHash(const IncrementalHash&) = delete;
        IncrementalHash& operator=(const IncrementalHash&) = delete;

        // Allow moving (transfers ownership of EVP_MD_CTX)
        IncrementalHash(IncrementalHash&& other) noexcept;
        IncrementalHash& operator=(IncrementalHash&& other) noexcept;

        /**
         * @brief Add data to the hash computation
         * @param data Pointer to data
         * @param size Size of data in bytes
         * @return true if successful
         */
        bool update(const uint8_t* data, size_t size);

        /**
         * @brief Finalize and get the hash result
         * @param hash Output buffer (must be at least HASH_SIZE bytes)
         * @return true if successful
         *
         * After calling finalize(), you can no longer call update().
         */
        bool finalize(unsigned char* hash);

        /**
         * @brief Reset the hash context to start a new hash
         * @return true if successful
         */
        bool reset();

    private:
        void* m_ctx;  ///< Opaque pointer to EVP_MD_CTX
        bool m_finalized;
    };
};

}  // namespace ExoSend
