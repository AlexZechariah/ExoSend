/**
 * @file HashUtils.cpp
 * @brief SHA-256 hash computation utilities using OpenSSL EVP API
 *
 * Uses the modern EVP API instead of deprecated SHA256_* functions
 * for compatibility with OpenSSL 3.0+.
 */

#include "exosend/HashUtils.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace ExoSend {

//=============================================================================
// Static Methods
//=============================================================================

/**
 * @brief Compute SHA-256 hash of file using EVP API
 * @param filePath Path to file
 * @param hash Output buffer (32 bytes)
 * @param errorMsg Error message output
 * @return true on success
 */

bool HashUtils::computeFileHash(const std::string& filePath,
                                 unsigned char* hash,
                                 std::string& errorMsg)
{
    if (!hash) {
        errorMsg = "Hash buffer is null";
        return false;
    }

    // Open file in binary mode
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        errorMsg = "Failed to open file: " + filePath;
        return false;
    }

    // Create EVP digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        errorMsg = "Failed to create EVP_MD_CTX";
        return false;
    }

    // Initialize SHA-256 digest
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        errorMsg = "Failed to initialize SHA256 context";
        return false;
    }

    // Read file in chunks and update hash
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();

        if (bytesRead > 0) {
            if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                EVP_MD_CTX_free(ctx);
                errorMsg = "Failed to update SHA256 hash";
                return false;
            }
        }
    }

    // Check for read errors
    if (file.bad()) {
        EVP_MD_CTX_free(ctx);
        errorMsg = "Error reading file: " + filePath;
        return false;
    }

    // Finalize hash
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        errorMsg = "Failed to finalize SHA256 hash";
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

std::vector<unsigned char> HashUtils::computeBufferHash(const uint8_t* data,
                                                         size_t size)
{
    std::vector<unsigned char> hash(HASH_SIZE);

    // Use EVP API for single-shot hash
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return hash;  // Return empty/zeroed hash on error
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
        if (data && size > 0) {
            EVP_DigestUpdate(ctx, data, size);
        }
        unsigned int hashLen = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string HashUtils::hashToString(const unsigned char* hash)
{
    if (!hash) {
        return "";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);
    }
    return oss.str();
}

bool HashUtils::stringToHash(const std::string& hexString,
                              unsigned char* hash)
{
    if (!hash || hexString.length() != HASH_SIZE * 2) {
        return false;
    }

    // Convert hex string to binary
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        std::string byteString = hexString.substr(i * 2, 2);
        try {
            hash[i] = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        } catch (...) {
            return false;  // Invalid hex string
        }
    }

    return true;
}

/**
 * @brief Constant-time hash comparison
 * @param hash1 First hash (32 bytes)
 * @param hash2 Second hash (32 bytes)
 * @return true if hashes match
 *
 * Uses constant-time comparison to prevent timing attacks.
 */
bool HashUtils::compareHashes(const unsigned char* hash1,
                               const unsigned char* hash2)
{
    if (!hash1 || !hash2) {
        return false;
    }

    // Constant-time comparison
    int result = 0;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        result |= hash1[i] ^ hash2[i];
    }
    return result == 0;
}

//=============================================================================
// IncrementalHash Class (using EVP API)
//=============================================================================

/**
 * @class HashUtils::IncrementalHash
 * @brief Incremental SHA-256 hashing for streaming data using EVP API
 *
 * Allows computing hash of data in chunks, useful for large files
 * or streaming data where the entire data set is not available at once.
 */

HashUtils::IncrementalHash::IncrementalHash()
    : m_ctx(nullptr), m_finalized(false)
{
    m_ctx = EVP_MD_CTX_new();
    reset();
}

HashUtils::IncrementalHash::~IncrementalHash()
{
    if (m_ctx) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(m_ctx));
        m_ctx = nullptr;
    }
}

HashUtils::IncrementalHash::IncrementalHash(IncrementalHash&& other) noexcept
    : m_ctx(other.m_ctx)
    , m_finalized(other.m_finalized)
{
    // Steal the context from other, leave other in valid empty state
    other.m_ctx = nullptr;
    other.m_finalized = false;
}

HashUtils::IncrementalHash& HashUtils::IncrementalHash::operator=(IncrementalHash&& other) noexcept {
    if (this != &other) {
        // Clean up existing context if we have one
        if (m_ctx) {
            EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(m_ctx));
        }

        // Steal from other
        m_ctx = other.m_ctx;
        m_finalized = other.m_finalized;

        // Leave other in valid empty state
        other.m_ctx = nullptr;
        other.m_finalized = false;
    }
    return *this;
}

bool HashUtils::IncrementalHash::update(const uint8_t* data, size_t size)
{
    if (m_finalized) {
        return false;  // Cannot update after finalize
    }

    if (!data || size == 0) {
        return true;  // Nothing to update
    }

    EVP_MD_CTX* ctx = static_cast<EVP_MD_CTX*>(m_ctx);
    return EVP_DigestUpdate(ctx, data, size) == 1;
}

bool HashUtils::IncrementalHash::finalize(unsigned char* hash)
{
    if (m_finalized || !hash) {
        return false;
    }

    EVP_MD_CTX* ctx = static_cast<EVP_MD_CTX*>(m_ctx);
    unsigned int hashLen = 0;
    bool success = (EVP_DigestFinal_ex(ctx, hash, &hashLen) == 1);
    m_finalized = true;
    return success;
}

bool HashUtils::IncrementalHash::reset()
{
    if (!m_ctx) {
        return false;
    }
    EVP_MD_CTX* ctx = static_cast<EVP_MD_CTX*>(m_ctx);
    bool success = (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1);
    m_finalized = false;
    return success;
}

}  // namespace ExoSend
