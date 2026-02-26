/**
 * @file CertificateManager.cpp
 * @brief TLS certificate generation and management
 */

#include "exosend/CertificateManager.h"
#include "exosend/FingerprintUtils.h"
#include "exosend/WindowsAcl.h"
#include "exosend/AppPaths.h"
#include "exosend/MigrationUtils.h"
#include "exosend/ThreadSafeLog.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>  // For SSL_CTX functions and SSL_FILETYPE_PEM
#include <openssl/asn1.h>  // For ASN1_TIME functions
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdlib>

// Windows headers for path functions
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

namespace ExoSend {

//=============================================================================
// Path Utilities
//=============================================================================

std::string CertificateManager::getDefaultCertDir() {
#ifdef _WIN32
    {
        DWORD required = GetEnvironmentVariableA("EXOSEND_CERT_DIR", nullptr, 0);
        if (required > 1) {
            std::string certDir;
            certDir.resize(required - 1);
            DWORD written = GetEnvironmentVariableA("EXOSEND_CERT_DIR", certDir.data(), required);
            if (written > 0) {
                for (char& c : certDir) {
                    if (c == '\\') c = '/';
                }
                return certDir;
            }
        }
    }
#endif

#ifdef _WIN32
    // Canonical location: %LOCALAPPDATA%\\ExoSend\\certs
    const auto dir = ExoSend::AppPaths::certsDir();
    if (!dir.empty()) {
        std::string certDir = dir.u8string();
        for (char& c : certDir) {
            if (c == '\\') c = '/';
        }
        return certDir;
    }
#endif

    // Fallback to current directory
    return "./certs";
}

std::string CertificateManager::getCertFilePath() {
    return getDefaultCertDir() + "/" + CERT_FILE;
}

std::string CertificateManager::getKeyFilePath() {
    return getDefaultCertDir() + "/" + KEY_FILE;
}

std::string CertificateManager::getHostname() {
    char hostname[256];
#ifdef _WIN32
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#endif
    return "ExoSend-Local";
}

//=============================================================================
// CertificateManager: Directory Management
//=============================================================================

bool CertificateManager::ensureCertDir(const std::string& certDir,
                                      std::string& errorMsg) {
    try {
        std::filesystem::path dir(certDir);

        if (std::filesystem::exists(dir)) {
            // Verify it's a directory
            if (!std::filesystem::is_directory(dir)) {
                errorMsg = "Certificate path exists but is not a directory: " + certDir;
                return false;
            }
            return true;
        }

        // Create directory recursively
        if (!std::filesystem::create_directories(dir)) {
            errorMsg = "Failed to create certificate directory: " + certDir;
            return false;
        }

        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        errorMsg = std::string("Filesystem error: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        errorMsg = std::string("Failed to create certificate directory: ") + e.what();
        return false;
    }
}

//=============================================================================
// CertificateManager: Certificate Existence
//=============================================================================

bool CertificateManager::certificateExists(const std::string& certPath) {
    try {
        std::filesystem::path path(certPath);
        return std::filesystem::exists(path) &&
               std::filesystem::is_regular_file(path);
    } catch (...) {
        return false;
    }
}

bool CertificateManager::ensureCertificateExists(std::string& errorMsg) {
#ifdef _WIN32
    // One-time migration: older builds stored certs under %APPDATA%\ExoSend\certs\.
    // Canonical location for v0.3.x is %LOCALAPPDATA%\ExoSend\certs\.
    // Skip migration when EXOSEND_CERT_DIR override is used (dev/test).
    {
        DWORD required = GetEnvironmentVariableA("EXOSEND_CERT_DIR", nullptr, 0);
        if (required <= 1) {
            const auto destDir = ExoSend::AppPaths::certsDir();
            const auto legacyDir = ExoSend::AppPaths::legacyRoamingCertsDir();
            const auto r = ExoSend::MigrationUtils::migrateCertMaterialIfMissing(
                destDir, legacyDir, CERT_FILE, KEY_FILE);
            if (!r.ok) {
                // Best-effort only; certificate generation below will still work.
                ExoSend::ThreadSafeLog::log("CERT_MIGRATE_WARN: " + r.error);
            } else if (r.migrated) {
                std::wstring aclErr;
                (void)restrictPathToCurrentUser(destDir.wstring(), &aclErr);
                (void)restrictPathToCurrentUser((destDir / CERT_FILE).wstring(), &aclErr);
                (void)restrictPathToCurrentUser((destDir / KEY_FILE).wstring(), &aclErr);
                ExoSend::ThreadSafeLog::log("CERT_MIGRATE: migrated cert material to LocalAppData");
            }
        }
    }
#endif

    // Check if certificate already exists
    std::string certPath = getCertFilePath();
    std::string keyPath = getKeyFilePath();

    if (certificateExists(certPath) && certificateExists(keyPath)) {
        // Check if certificate is expired
        if (isCertificateExpired(certPath, errorMsg)) {
            // Certificate expired - regenerate
        } else {
            // Certificate exists and is valid
            return true;
        }
    }

    // Generate new certificate
    std::string commonName = "ExoSend-" + getHostname();
    return generateSelfSignedCert(certPath, keyPath, commonName, errorMsg);
}

//=============================================================================
// CertificateManager: Certificate Generation
//=============================================================================

bool CertificateManager::generateSelfSignedCert(const std::string& certPath,
                                                const std::string& keyPath,
                                                const std::string& commonName,
                                                std::string& errorMsg) {
    // Ensure directory exists
    std::string certDir = std::filesystem::path(certPath).parent_path().string();
    if (!ensureCertDir(certDir, errorMsg)) {
        return false;
    }

    // Initialize OpenSSL
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    BIO* certBio = nullptr;
    BIO* keyBio = nullptr;

    bool success = false;

    try {
        // Generate RSA 2048-bit key pair
        EVP_PKEY_CTX* pkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!pkeyCtx) {
            errorMsg = "Failed to create key context";
            goto cleanup;
        }

        if (EVP_PKEY_keygen_init(pkeyCtx) <= 0) {
            errorMsg = "Failed to initialize keygen";
            EVP_PKEY_CTX_free(pkeyCtx);
            goto cleanup;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyCtx, 2048) <= 0) {
            errorMsg = "Failed to set RSA key size";
            EVP_PKEY_CTX_free(pkeyCtx);
            goto cleanup;
        }

        if (EVP_PKEY_keygen(pkeyCtx, &pkey) <= 0) {
            errorMsg = "Failed to generate RSA key";
            EVP_PKEY_CTX_free(pkeyCtx);
            goto cleanup;
        }

        EVP_PKEY_CTX_free(pkeyCtx);

        // Create X.509 certificate
        cert = X509_new();
        if (!cert) {
            errorMsg = "Failed to create certificate";
            goto cleanup;
        }

        // Set version (X509v3)
        if (X509_set_version(cert, 2) != 1) {
            errorMsg = "Failed to set certificate version";
            goto cleanup;
        }

        // Set serial number
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

        // Set validity period
        X509_gmtime_adj(X509_get_notBefore(cert), 0);  // Now
        X509_gmtime_adj(X509_get_notAfter(cert),
                        CERT_VALIDITY_DAYS * 24 * 60 * 60);  // CERT_VALIDITY_DAYS from now

        // Set public key
        if (X509_set_pubkey(cert, pkey) != 1) {
            errorMsg = "Failed to set public key";
            goto cleanup;
        }

        // Set subject name
        X509_NAME* name = X509_get_subject_name(cert);
        if (!name) {
            errorMsg = "Failed to get subject name";
            goto cleanup;
        }

        // Add common name
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(commonName.c_str()),
                                       static_cast<int>(commonName.length()), -1, 0) != 1) {
            errorMsg = "Failed to set common name";
            goto cleanup;
        }

        // Add organization name
        if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>("ExoSend"),
                                       7, -1, 0) != 1) {
            errorMsg = "Failed to set organization";
            goto cleanup;
        }

        // Self-signed: issuer = subject
        if (X509_set_issuer_name(cert, name) != 1) {
            errorMsg = "Failed to set issuer name";
            goto cleanup;
        }

        // Sign certificate with SHA-256
        if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
            errorMsg = "Failed to sign certificate";
            goto cleanup;
        }

        // Write certificate to file
        certBio = BIO_new_file(certPath.c_str(), "w");
        if (!certBio) {
            errorMsg = "Failed to create certificate file: " + certPath;
            goto cleanup;
        }

        if (PEM_write_bio_X509(certBio, cert) != 1) {
            errorMsg = "Failed to write certificate";
            goto cleanup;
        }

        // Write private key to file (no encryption)
        keyBio = BIO_new_file(keyPath.c_str(), "w");
        if (!keyBio) {
            errorMsg = "Failed to create key file: " + keyPath;
            goto cleanup;
        }

        if (PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            errorMsg = "Failed to write private key";
            goto cleanup;
        }

#ifdef _WIN32
        // Best-effort defense-in-depth: restrict cert/key ACLs to current user only.
        // Failure is non-fatal because %APPDATA% is already user-scoped by default.
        {
            std::wstring aclErr;
            const auto certDirW = std::filesystem::path(certPath).parent_path().wstring();
            (void)restrictPathToCurrentUser(certDirW, &aclErr);

            (void)restrictPathToCurrentUser(std::filesystem::path(certPath).wstring(), &aclErr);
            (void)restrictPathToCurrentUser(std::filesystem::path(keyPath).wstring(), &aclErr);
        }
#endif

        success = true;

    } catch (const std::exception& e) {
        errorMsg = std::string("Exception during certificate generation: ") + e.what();
        success = false;
    }

cleanup:
    if (certBio) BIO_free(certBio);
    if (keyBio) BIO_free(keyBio);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);

    return success;
}

//=============================================================================
// CertificateManager: Certificate Loading
//=============================================================================

bool CertificateManager::loadCertificate(SSL_CTX* ctx,
                                        const std::string& certPath,
                                        const std::string& keyPath,
                                        std::string& errorMsg) {
    if (!ctx) {
        errorMsg = "SSL context is null";
        return false;
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        errorMsg = "Failed to load certificate: " + certPath;
        return false;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        errorMsg = "Failed to load private key: " + keyPath;
        return false;
    }

    // Verify private key matches certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        errorMsg = "Private key does not match certificate";
        return false;
    }

    return true;
}

//=============================================================================
// CertificateManager: Certificate Information
//=============================================================================

std::string CertificateManager::getCertificateFingerprint(const std::string& certPath,
                                                          std::string& errorMsg) {
    // Read certificate file
    BIO* bio = BIO_new_file(certPath.c_str(), "r");
    if (!bio) {
        errorMsg = "Failed to open certificate file: " + certPath;
        return "";
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        errorMsg = "Failed to read certificate";
        return "";
    }

    // Get DER encoding
    unsigned char* der = nullptr;
    int derLen = i2d_X509(cert, &der);
    X509_free(cert);

    if (derLen < 0) {
        errorMsg = "Failed to encode certificate";
        return "";
    }

    // Compute SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<size_t>(derLen), hash);
    OPENSSL_free(der);

    // Convert to canonical hex string (64 uppercase hex, no separators)
    std::string fingerprint;
    fingerprint.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", hash[i]);
        fingerprint += buf;
    }

    // Defensive: ensure canonical form even if formatting changes later.
    return FingerprintUtils::normalizeSha256Hex(fingerprint);
}

std::string CertificateManager::getCertificateCommonName(const std::string& certPath,
                                                         std::string& errorMsg) {
    BIO* bio = BIO_new_file(certPath.c_str(), "r");
    if (!bio) {
        errorMsg = "Failed to open certificate file";
        return "";
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        errorMsg = "Failed to read certificate";
        return "";
    }

    X509_NAME* name = X509_get_subject_name(cert);
    char cnBuffer[256];
    int cnLen = X509_NAME_get_text_by_NID(name, NID_commonName,
                                         cnBuffer, sizeof(cnBuffer));
    X509_free(cert);

    if (cnLen <= 0) {
        errorMsg = "No common name in certificate";
        return "";
    }

    return std::string(cnBuffer, static_cast<size_t>(cnLen));
}

std::string CertificateManager::getCertificateExpiry(const std::string& certPath,
                                                     std::string& errorMsg) {
    BIO* bio = BIO_new_file(certPath.c_str(), "r");
    if (!bio) {
        errorMsg = "Failed to open certificate file";
        return "";
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        errorMsg = "Failed to read certificate";
        return "";
    }

    // Get notAfter time (const pointer in OpenSSL 3.x)
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);

    // Use BIO to print ASN1_TIME
    BIO* memBio = BIO_new(BIO_s_mem());
    if (!memBio) {
        X509_free(cert);
        errorMsg = "Failed to create BIO";
        return "";
    }

    ASN1_TIME_print(memBio, notAfter);

    // Read from BIO
    char buffer[256];
    int len = BIO_read(memBio, buffer, sizeof(buffer) - 1);
    X509_free(cert);
    BIO_free(memBio);

    if (len <= 0) {
        errorMsg = "Failed to format expiry date";
        return "";
    }

    buffer[len] = '\0';
    return std::string(buffer);
}

bool CertificateManager::isCertificateExpired(const std::string& certPath,
                                             std::string& errorMsg) {
    BIO* bio = BIO_new_file(certPath.c_str(), "r");
    if (!bio) {
        errorMsg = "Failed to open certificate file";
        return true;  // Treat missing cert as expired
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        errorMsg = "Failed to read certificate";
        return true;
    }

    // Get current time and certificate expiry
    int result = X509_cmp_time(X509_get0_notAfter(cert), nullptr);

    X509_free(cert);

    // If result < 0, certificate has expired
    return result < 0;
}

}  // namespace ExoSend
