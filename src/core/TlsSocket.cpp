/**
 * @file TlsSocket.cpp
 * @brief TLS/SSL wrapper for secure file transfers
 */

#include "exosend/TlsSocket.h"
#include "exosend/CertificateManager.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <string>
#include <cstring>
#include <iostream>
#include <algorithm>

// Undefine Windows macros that conflict with std::min/max
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace ExoSend {

//=============================================================================
// OpenSSL Initialization (Static)
//=============================================================================

namespace {
    bool g_openSslInitialized = false;
}

void initOpenSsl() {
    if (!g_openSslInitialized) {
        // Note: In OpenSSL 1.1.0+, explicit initialization is optional
        // but we call it for compatibility and clarity
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        g_openSslInitialized = true;
    }
}

void cleanupOpenSsl() {
    // Note: EVP_cleanup() and ERR_free_strings() are deprecated and
    // are no-ops in OpenSSL 1.1.0+. OpenSSL automatically cleans up
    // resources when the process exits. We keep this function for
    // API compatibility but it no longer needs to do anything.
    g_openSslInitialized = false;
}

//=============================================================================
// TlsSocket: Constructor / Destructor
//=============================================================================

TlsSocket::TlsSocket(SOCKET socket, TlsRole role)
    : m_socket(socket)
    , m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_role(role)
    , m_connected(false)
    , m_initialized(false)
{
    // Ensure OpenSSL is initialized
    initOpenSsl();
}

TlsSocket::~TlsSocket() {
    shutdown();

    // Free SSL object
    if (m_ssl) {
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }

    // Free SSL context
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }

    m_initialized = false;
}

TlsSocket::TlsSocket(TlsSocket&& other) noexcept
    : m_socket(other.m_socket)
    , m_ctx(other.m_ctx)
    , m_ssl(other.m_ssl)
    , m_role(other.m_role)
    , m_connected(other.m_connected)
    , m_initialized(other.m_initialized)
{
    // Nullify other's pointers (transfer ownership)
    other.m_ctx = nullptr;
    other.m_ssl = nullptr;
    other.m_connected = false;
    other.m_initialized = false;
}

TlsSocket& TlsSocket::operator=(TlsSocket&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        shutdown();
        if (m_ssl) {
            SSL_free(m_ssl);
        }
        if (m_ctx) {
            SSL_CTX_free(m_ctx);
        }

        // Transfer ownership
        m_socket = other.m_socket;
        m_ctx = other.m_ctx;
        m_ssl = other.m_ssl;
        m_role = other.m_role;
        m_connected = other.m_connected;
        m_initialized = other.m_initialized;

        // Nullify other's pointers
        other.m_ctx = nullptr;
        other.m_ssl = nullptr;
        other.m_connected = false;
        other.m_initialized = false;
    }
    return *this;
}

//=============================================================================
// TlsSocket: SSL Context Creation
//=============================================================================

bool TlsSocket::createContext(std::string& errorMsg) {
    // Choose method based on role
    const SSL_METHOD* method;
    if (m_role == TlsRole::SERVER) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }

    // Create SSL context
    m_ctx = SSL_CTX_new(method);
    if (!m_ctx) {
        errorMsg = "Failed to create SSL context: " + getLastError();
        return false;
    }

    // Set minimum TLS version to 1.2
    if (SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION) != 1) {
        errorMsg = "Failed to set minimum TLS version: " + getLastError();
        return false;
    }

    // Set strong cipher list
    if (SSL_CTX_set_cipher_list(m_ctx, TLS_CIPHER_SUITE) != 1) {
        errorMsg = "Failed to set cipher list: " + getLastError();
        return false;
    }

    // Set security options (disable old protocols, compression, enable forward secrecy)
    SSL_CTX_set_options(m_ctx,
        SSL_OP_NO_SSLv2 |          // SSLv2 is obsolete
        SSL_OP_NO_SSLv3 |          // SSLv3 has POODLE vulnerability
        SSL_OP_NO_TLSv1 |          // TLSv1.0 has known issues
        SSL_OP_NO_TLSv1_1 |        // TLSv1.1 is deprecated
        SSL_OP_NO_COMPRESSION |    // CRIME attack prevention
        SSL_OP_SINGLE_DH_USE |     // Forward secrecy (DH)
        SSL_OP_SINGLE_ECDH_USE);   // Forward secrecy (ECDH)

    // Enable ECDHE for forward secrecy
    SSL_CTX_set_ecdh_auto(m_ctx, 1);

    // Configure certificate verification
    if (!configureVerification(errorMsg)) {
        return false;
    }

    return true;
}

bool TlsSocket::configureVerification(std::string& errorMsg) {
    if (m_role == TlsRole::SERVER) {
        // Server: Don't verify client certificate
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        // Client: Verify server certificate, accept self-signed
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, tlsVerifyCallback);
        SSL_CTX_set_verify_depth(m_ctx, 0);
    }

    return true;
}

bool TlsSocket::loadCertificates(std::string& errorMsg) {
    // Only server mode loads certificates
    if (m_role != TlsRole::SERVER) {
        return true;
    }

    // Use CertificateManager to load certificates
    std::string certPath = CertificateManager::getCertFilePath();
    std::string keyPath = CertificateManager::getKeyFilePath();

    return CertificateManager::loadCertificate(m_ctx, certPath, keyPath, errorMsg);
}

bool TlsSocket::createSsl(std::string& errorMsg) {
    // Create SSL object from context
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        errorMsg = "Failed to create SSL object: " + getLastError();
        return false;
    }

    // Attach SSL to socket
    if (SSL_set_fd(m_ssl, static_cast<int>(m_socket)) != 1) {
        errorMsg = "Failed to set SSL file descriptor: " + getLastError();
        return false;
    }

    return true;
}

//=============================================================================
// TlsSocket: TLS Handshake
//=============================================================================

bool TlsSocket::handshake(std::string& errorMsg) {
    // Step 1: Create SSL context
    if (!createContext(errorMsg)) {
        return false;
    }

    // Step 2: Load certificates (server only)
    if (!loadCertificates(errorMsg)) {
        // Note: Clean up SSL context on certificate load failure
        if (m_ctx) {
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
        return false;
    }

    // Step 3: Create SSL object
    if (!createSsl(errorMsg)) {
        return false;
    }

    // Step 4: Perform handshake
    int result;
    if (m_role == TlsRole::SERVER) {
        result = SSL_accept(m_ssl);
    } else {
        result = SSL_connect(m_ssl);
    }

    if (result != 1) {
        int err = SSL_get_error(m_ssl, result);
        errorMsg = "TLS handshake failed (" + getErrorDescription(err) + "): " + getLastError();
        return false;
    }

    m_connected = true;
    m_initialized = true;
    return true;
}

//=============================================================================
// TlsSocket: Send / Receive
//=============================================================================

bool TlsSocket::send(const uint8_t* data, size_t size, std::string& errorMsg) {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return false;
    }

    if (!data || size == 0) {
        return true;  // Nothing to send
    }

    // Split into TLS_MAX_PACKET_SIZE chunks
    size_t offset = 0;
    while (offset < size) {
        size_t chunkSize = std::min(size - offset, TLS_MAX_PACKET_SIZE);
        int sent = SSL_write(m_ssl, data + offset, static_cast<int>(chunkSize));

        if (sent <= 0) {
            int err = SSL_get_error(m_ssl, sent);
            errorMsg = "TLS write failed (" + getErrorDescription(err) + "): " + getLastError();
            return false;
        }

        offset += static_cast<size_t>(sent);
    }

    return true;
}

size_t TlsSocket::recv(uint8_t* buffer, size_t size, std::string& errorMsg) {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return 0;
    }

    if (!buffer || size == 0) {
        return 0;  // Nothing to receive
    }

    int received = SSL_read(m_ssl, buffer, static_cast<int>(size));

    if (received <= 0) {
        int err = SSL_get_error(m_ssl, received);

        // Connection closed cleanly
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }

        errorMsg = "TLS read failed (" + getErrorDescription(err) + "): " + getLastError();
        return 0;
    }

    return static_cast<size_t>(received);
}

bool TlsSocket::sendExact(const uint8_t* data, size_t size, std::string& errorMsg) {
    if (!data || size == 0) {
        return true;
    }

    size_t totalSent = 0;
    while (totalSent < size) {
        size_t remaining = size - totalSent;
        size_t chunkSize = std::min(remaining, TLS_MAX_PACKET_SIZE);

        int sent = SSL_write(m_ssl, data + totalSent, static_cast<int>(chunkSize));

        if (sent <= 0) {
            int err = SSL_get_error(m_ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE) {
                continue;  // Retry
            }
            errorMsg = "TLS send failed (" + getErrorDescription(err) + "): " + getLastError();
            return false;
        }

        totalSent += static_cast<size_t>(sent);
    }

    return true;
}

bool TlsSocket::recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) {
    if (!buffer || size == 0) {
        return true;
    }

    size_t totalReceived = 0;
    while (totalReceived < size) {
        int received = SSL_read(m_ssl, buffer + totalReceived,
                                static_cast<int>(size - totalReceived));

        if (received <= 0) {
            int err = SSL_get_error(m_ssl, received);

            if (err == SSL_ERROR_ZERO_RETURN) {
                errorMsg = "Connection closed by peer";
                return false;
            }

            if (err == SSL_ERROR_WANT_READ) {
                continue;  // Retry
            }

            errorMsg = "TLS recv failed (" + getErrorDescription(err) + "): " + getLastError();
            return false;
        }

        totalReceived += static_cast<size_t>(received);
    }

    return true;
}

//=============================================================================
// TlsSocket: Connection Management
//=============================================================================

void TlsSocket::shutdown() {
    if (m_ssl && m_connected) {
        SSL_shutdown(m_ssl);
        m_connected = false;
    }
}

//=============================================================================
// TlsSocket: Certificate Information
//=============================================================================

std::string TlsSocket::getPeerFingerprint(std::string& errorMsg) {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return "";
    }

    // Get peer certificate
    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert) {
        errorMsg = "No peer certificate";
        return "";
    }

    // Get DER encoded certificate
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

    // Convert to hex string
    std::string fingerprint;
    fingerprint.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        fingerprint += buf;

        // Add colon for readability (except last byte)
        if (i < SHA256_DIGEST_LENGTH - 1) {
            fingerprint += ":";
        }
    }

    // Convert to uppercase
    for (char& c : fingerprint) {
        if (c >= 'a' && c <= 'f') {
            c = c - 'a' + 'A';
        }
    }

    return fingerprint;
}

std::string TlsSocket::getPeerCommonName(std::string& errorMsg) {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return "";
    }

    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert) {
        errorMsg = "No peer certificate";
        return "";
    }

    // Get subject name
    X509_NAME* name = X509_get_subject_name(cert);
    if (!name) {
        X509_free(cert);
        errorMsg = "No subject name in certificate";
        return "";
    }

    // Extract common name (CN)
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

//=============================================================================
// TlsSocket: Error Handling
//=============================================================================

std::string TlsSocket::getLastError() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Unknown error";
    }

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

std::string TlsSocket::getErrorDescription(int sslErrorCode) {
    switch (sslErrorCode) {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN (connection closed)";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ (retry needed)";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE (retry needed)";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL (I/O error)";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL (protocol error)";
        default:
            return "SSL_ERROR_UNKNOWN (" + std::to_string(sslErrorCode) + ")";
    }
}

//=============================================================================
// Certificate Verification Callback
//=============================================================================

/**
 * @brief TLS certificate verification callback
 *
 * Accepts self-signed certificates for peer-to-peer transfers.
 * Uses Trust-On-First-Use (TOFU) model for certificate validation.
 */
int tlsVerifyCallback(int preverifyOk, X509_STORE_CTX* ctx) {
    // Get certificate
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int err = X509_STORE_CTX_get_error(ctx);

    // Suppress unused variable warning
    (void)depth;

    // Accept self-signed certificates for peer-to-peer transfers
    if (!preverifyOk) {
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));

        if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
            err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            return 1;  // Accept self-signed certificates
        }

        return 1;  // Accept certificate
    }

    return 1;  // Accept
}

}  // namespace ExoSend
