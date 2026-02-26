/**
 * @file CertificateManager.h
 * @brief TLS certificate generation and management
 */

#pragma once

#include "config.h"
#include <string>

// Forward declarations for OpenSSL types
struct ssl_ctx_st;
typedef struct ssl_ctx_st SSL_CTX;

namespace ExoSend {

//=============================================================================
// CertificateManager Class
//=============================================================================

/**
 * @class CertificateManager
 * @brief Manages self-signed certificate generation and loading for ExoSend
 *
 * Uses self-signed certificates for TLS encryption. Certificates are stored
 * in %LOCALAPPDATA%\ExoSend\certs\
 *
 * Security Model:
 * - Self-signed certificates (no CA validation)
 * - Provides encryption (confidentiality)
 * - Provides integrity (SHA-256 signatures)
 * - Peer authentication is enforced by secure pairing confirmation plus
 *   certificate fingerprint pinning (not CA validation)
 *
 * Usage:
 * @code
 * // Generate certificate on first run
 * std::string error;
 * if (!CertificateManager::ensureCertificateExists(error)) {
 *     std::cerr << "Failed to generate certificate: " << error << "\n";
 *     return false;
 * }
 *
 * // Load certificate into SSL context
 * SSL_CTX* ctx = ...;
 * if (!CertificateManager::loadCertificate(ctx, error)) {
 *     std::cerr << "Failed to load certificate: " << error << "\n";
 *     return false;
 * }
 * @endcode
 */
class CertificateManager {
public:
    //=========================================================================
    // Certificate Generation
    //=========================================================================

    /**
     * @brief Generate a self-signed certificate
     * @param certPath Output path for certificate (.crt file)
     * @param keyPath Output path for private key (.key file)
     * @param commonName Common name (CN) for certificate
     * @param errorMsg Output error message on failure
     * @return true if certificate generated successfully
     *
     * Creates:
     * - RSA 2048-bit key pair (EVP_PKEY)
     * - X.509 v3 certificate
     * - Valid for CERT_VALIDITY_DAYS (365 days by default)
     * - Subject: CN=<commonName>
     * - Issuer: CN=<commonName> (self-signed)
     * - Signature: SHA-256
     * - Serial number: 1
     *
     * The certificate is saved in PEM format.
     * The private key is saved in PEM format (no encryption/password).
     *
     * @param certPath Path to .crt file
     * @param keyPath Path to .key file
     * @param commonName Certificate common name
     * @param errorMsg Output error message
     * @return true on success
     */
    static bool generateSelfSignedCert(const std::string& certPath,
                                       const std::string& keyPath,
                                       const std::string& commonName,
                                       std::string& errorMsg);

    //=========================================================================
    // Certificate Loading
    //=========================================================================

    /**
     * @brief Load certificate and private key into SSL context
     * @param ctx OpenSSL SSL context
     * @param certPath Path to certificate file (.crt)
     * @param keyPath Path to private key file (.key)
     * @param errorMsg Output error message on failure
     * @return true if loaded successfully
     *
     * Loads:
     * - Certificate from PEM file (SSL_CTX_use_certificate_file)
     * - Private key from PEM file (SSL_CTX_use_PrivateKey_file)
     * - Verifies private key matches certificate (SSL_CTX_check_private_key)
     *
     * @param ctx SSL context
     * @param certPath Certificate file path
     * @param keyPath Private key file path
     * @param errorMsg Output error message
     * @return true on success
     */
    static bool loadCertificate(SSL_CTX* ctx,
                               const std::string& certPath,
                               const std::string& keyPath,
                               std::string& errorMsg);

    //=========================================================================
    // Certificate Existence Check
    //=========================================================================

    /**
     * @brief Check if certificate file exists
     * @param certPath Path to certificate file
     * @return true if certificate exists
     *
     * Uses std::filesystem to check file existence.
     *
     * @param certPath Certificate file path
     * @return true if file exists
     */
    static bool certificateExists(const std::string& certPath);

    //=========================================================================
    // Lazy Initialization (Recommended)
    //=========================================================================

    /**
     * @brief Ensure certificate exists (generate if missing)
     * @param errorMsg Output error message on failure
     * @return true if certificate exists or was generated successfully
     *
     * This is the recommended method for certificate management:
     * - Checks if certificate already exists
     * - If exists, returns true (no action)
     * - If missing, generates new certificate
     * - Uses default paths from getCertFilePath() and getKeyFilePath()
     *
     * Call this on application startup or before first TLS handshake.
     *
     * @param errorMsg Output error message
     * @return true on success
     */
    static bool ensureCertificateExists(std::string& errorMsg);

    //=========================================================================
    // Path Utilities
    //=========================================================================

    /**
     * @brief Get default certificate directory
     * @return Path to %LOCALAPPDATA%\ExoSend\certs\
     *
     * Uses Windows Known Folder APIs to locate LocalAppData.
     * Fallback to "./certs" if LocalAppData unavailable.
     *
     * @return Certificate directory path
     */
    static std::string getDefaultCertDir();

    /**
     * @brief Get certificate file path
     * @return Full path to server.crt
     *
     * Returns: %LOCALAPPDATA%\ExoSend\certs\server.crt
     *
     * @return Certificate file path
     */
    static std::string getCertFilePath();

    /**
     * @brief Get private key file path
     * @return Full path to server.key
     *
     * Returns: %LOCALAPPDATA%\ExoSend\certs\server.key
     *
     * @return Private key file path
     */
    static std::string getKeyFilePath();

    //=========================================================================
    // Certificate Information
    //=========================================================================

    /**
     * @brief Get certificate fingerprint (SHA-256)
     * @param certPath Path to certificate file
     * @param errorMsg Output error message on failure
     * @return Hexadecimal fingerprint string (64 characters), or empty on error
     *
     * Reads certificate file and computes SHA-256 hash of DER encoding.
     * Useful for displaying to users for manual verification.
     *
     * @param certPath Certificate file path
     * @param errorMsg Output error message
     * @return Certificate fingerprint or empty string
     */
    static std::string getCertificateFingerprint(const std::string& certPath,
                                                 std::string& errorMsg);

    /**
     * @brief Get certificate common name (CN)
     * @param certPath Path to certificate file
     * @param errorMsg Output error message on failure
     * @return Common name from certificate, or empty on error
     *
     * Reads certificate file and extracts subject CN field.
     *
     * @param certPath Certificate file path
     * @param errorMsg Output error message
     * @return Common name or empty string
     */
    static std::string getCertificateCommonName(const std::string& certPath,
                                                std::string& errorMsg);

    /**
     * @brief Get certificate expiry date
     * @param certPath Path to certificate file
     * @param errorMsg Output error message on failure
     * @return Expiry date as string (YYYY-MM-DD), or empty on error
     *
     * Reads certificate file and extracts notAfter field.
     *
     * @param certPath Certificate file path
     * @param errorMsg Output error message
     * @return Expiry date or empty string
     */
    static std::string getCertificateExpiry(const std::string& certPath,
                                            std::string& errorMsg);

    /**
     * @brief Check if certificate is expired
     * @param certPath Path to certificate file
     * @param errorMsg Output error message on failure
     * @return true if certificate is expired, false if valid
     *
     * Compares certificate notAfter date with current time.
     *
     * @param certPath Certificate file path
     * @param errorMsg Output error message
     * @return true if expired
     */
    static bool isCertificateExpired(const std::string& certPath,
                                     std::string& errorMsg);

private:
    //=========================================================================
    // Private Methods
    //=========================================================================

    /**
     * @brief Ensure certificate directory exists
     * @param certDir Directory path
     * @param errorMsg Output error message on failure
     * @return true if directory exists or was created successfully
     *
     * Creates directory recursively using std::filesystem.
     *
     * @param certDir Directory path
     * @param errorMsg Output error message
     * @return true on success
     */
    static bool ensureCertDir(const std::string& certDir,
                             std::string& errorMsg);

    /**
     * @brief Generate hostname for certificate CN
     * @return Hostname or "ExoSend-Local" if unavailable
     *
     * Uses gethostname() to get local hostname.
     * Falls back to "ExoSend-Local" if hostname unavailable.
     *
     * @return Hostname string
     */
    static std::string getHostname();
};

}  // namespace ExoSend
