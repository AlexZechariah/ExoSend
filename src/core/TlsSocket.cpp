/**
 * @file TlsSocket.cpp
 * @brief TLS/SSL wrapper for secure file transfers
 */

#include "exosend/TlsSocket.h"
#include "exosend/FingerprintUtils.h"
#include "exosend/CertificateManager.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <string>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <windows.h>

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
    static std::string formatSslFailureDetails(int sslErrorCode, int wsaErrorCode);
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

    // TLS 1.3 only (no legacy protocol negotiation).
    if (SSL_CTX_set_min_proto_version(m_ctx, TLS1_3_VERSION) != 1) {
        errorMsg = "Failed to set minimum TLS version: " + getLastError();
        return false;
    }
    if (SSL_CTX_set_max_proto_version(m_ctx, TLS1_3_VERSION) != 1) {
        errorMsg = "Failed to set maximum TLS version: " + getLastError();
        return false;
    }

    // TLS 1.3 cipher suites are configured separately from legacy ciphers.
    if (SSL_CTX_set_ciphersuites(m_ctx, TLS13_CIPHER_SUITES) != 1) {
        errorMsg = "Failed to set TLS 1.3 cipher suites: " + getLastError();
        return false;
    }

    // Set strong cipher list (legacy API, retained for completeness even though
    // TLS <= 1.2 is disabled by version policy).
    if (SSL_CTX_set_cipher_list(m_ctx, TLS_CIPHER_SUITE) != 1) {
        errorMsg = "Failed to set cipher list: " + getLastError();
        return false;
    }

    if (SSL_CTX_set1_groups_list(m_ctx, TLS_GROUPS_LIST) != 1) {
        errorMsg = "Failed to set TLS groups list: " + getLastError();
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
    (void)errorMsg;

    // Peer-to-peer: require a certificate from the peer, but accept self-signed
    // certificates at the OpenSSL layer. Pairing and pinning is enforced by the app
    // by comparing the peer fingerprint against the persisted trust store.
    int mode = SSL_VERIFY_PEER;
    if (m_role == TlsRole::SERVER) {
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(m_ctx, mode, tlsVerifyCallback);
    SSL_CTX_set_verify_depth(m_ctx, 0);

    return true;
}

bool TlsSocket::loadCertificates(std::string& errorMsg) {
    // Both client and server present certificates for mutual authentication.
    if (!CertificateManager::ensureCertificateExists(errorMsg)) {
        return false;
    }

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
        const int wsaError = WSAGetLastError();
        int err = SSL_get_error(m_ssl, result);
        errorMsg = "TLS handshake failed (" + getErrorDescription(err) + "): " +
                   formatSslFailureDetails(err, wsaError);
        return false;
    }

    // Ensure peer presented a certificate (required for pinning)
    X509* peerCert = SSL_get_peer_certificate(m_ssl);
    if (!peerCert) {
        errorMsg = "TLS handshake succeeded but peer did not present a certificate";
        return false;
    }
    X509_free(peerCert);

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
            const int wsaError = WSAGetLastError();
            int err = SSL_get_error(m_ssl, sent);
            errorMsg = "TLS write failed (" + getErrorDescription(err) + "): " +
                       formatSslFailureDetails(err, wsaError);
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
        const int wsaError = WSAGetLastError();
        int err = SSL_get_error(m_ssl, received);

        // Connection closed cleanly
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }

        errorMsg = "TLS read failed (" + getErrorDescription(err) + "): " +
                   formatSslFailureDetails(err, wsaError);
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
            const int wsaError = WSAGetLastError();
            int err = SSL_get_error(m_ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE) {
                continue;  // Retry
            }
            errorMsg = "TLS send failed (" + getErrorDescription(err) + "): " +
                       formatSslFailureDetails(err, wsaError);
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
            const int wsaError = WSAGetLastError();
            int err = SSL_get_error(m_ssl, received);

            if (err == SSL_ERROR_ZERO_RETURN) {
                errorMsg = "Connection closed by peer";
                return false;
            }

            if (err == SSL_ERROR_WANT_READ) {
                continue;  // Retry
            }

            errorMsg = "TLS recv failed (" + getErrorDescription(err) + "): " +
                       formatSslFailureDetails(err, wsaError);
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

    // Convert to canonical hex string (64 uppercase hex, no separators)
    std::string fingerprint;
    fingerprint.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", hash[i]);
        fingerprint += buf;
    }

    // Defensive: enforce canonical form even if formatting changes later.
    return FingerprintUtils::normalizeSha256Hex(fingerprint);
}

std::string TlsSocket::getLocalFingerprint(std::string& errorMsg) {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return "";
    }

    X509* cert = SSL_get_certificate(m_ssl);
    if (!cert) {
        errorMsg = "No local certificate";
        return "";
    }

    unsigned char* der = nullptr;
    int derLen = i2d_X509(cert, &der);
    if (derLen < 0) {
        errorMsg = "Failed to encode certificate";
        return "";
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<size_t>(derLen), hash);
    OPENSSL_free(der);

    std::string fingerprint;
    fingerprint.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", hash[i]);
        fingerprint += buf;
    }

    return FingerprintUtils::normalizeSha256Hex(fingerprint);
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

bool TlsSocket::getTlsExporterChannelBinding(std::array<uint8_t, 32>& out, std::string& errorMsg) const {
    if (!m_connected || !m_ssl) {
        errorMsg = "TLS not connected";
        return false;
    }

    constexpr const char* kLabel = "EXPORTER-Channel-Binding";
    std::fill(out.begin(), out.end(), 0);

    // RFC 9266 defines the context as the empty string. OpenSSL exposes this
    // via the use_context flag. Note: for TLS 1.2 and below, an omitted context
    // differs from an empty context, so keep use_context=1 even with length 0.
    static const unsigned char kEmptyContext[1] = { 0 };

    const int ok = SSL_export_keying_material(
        m_ssl,
        out.data(),
        out.size(),
        kLabel,
        std::strlen(kLabel),
        kEmptyContext,
        0,
        1
    );
    if (ok != 1) {
        errorMsg = "TLS exporter failed: " + getLastError();
        return false;
    }

    return true;
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

namespace {

static std::string trimRight(std::string s) {
    while (!s.empty()) {
        const unsigned char c = static_cast<unsigned char>(s.back());
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            s.pop_back();
            continue;
        }
        break;
    }
    return s;
}

static std::string win32ErrorToString(DWORD code) {
    if (code == 0) return {};

    LPSTR buf = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    const DWORD n = FormatMessageA(flags, nullptr, code, lang, reinterpret_cast<LPSTR>(&buf), 0, nullptr);

    std::string msg;
    if (n > 0 && buf) {
        msg.assign(buf, buf + n);
        msg = trimRight(std::move(msg));
    }
    if (buf) {
        LocalFree(buf);
    }

    if (msg.empty()) {
        return "Win32 error " + std::to_string(static_cast<unsigned long>(code));
    }
    return msg;
}

static std::string formatSslFailureDetails(int sslErrorCode, int wsaErrorCode) {
    // Prefer OpenSSL's error queue when present.
    const unsigned long opensslErr = ERR_get_error();
    if (opensslErr != 0) {
        char buf[256];
        ERR_error_string_n(opensslErr, buf, sizeof(buf));
        return std::string(buf);
    }

    // SSL_ERROR_SYSCALL often indicates an underlying socket error (or EOF)
    // and may not populate the OpenSSL error queue.
    if (sslErrorCode == SSL_ERROR_SYSCALL) {
        if (wsaErrorCode != 0) {
            const std::string msg = win32ErrorToString(static_cast<DWORD>(wsaErrorCode));
            return "WSAGetLastError()=" + std::to_string(wsaErrorCode) + " (" + msg + ")";
        }
        return "Socket I/O failed without a Windows socket error (peer may have closed the connection)";
    }

    return "Unknown error";
}

}  // namespace

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
 * @brief TLS certificate verification callback (self-signed allowed, v0.3.0+)
 *
 * Accepts self-signed certificates (X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
 * X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) to support peer-to-peer transfers
 * without a CA. Rejects all other verification errors.
 *
 * Peer identity is enforced at the application layer by comparing the peer
 * certificate fingerprint against the persisted trust store (pairing confirmation + pinning).
 */
int tlsVerifyCallback(int preverifyOk, X509_STORE_CTX* ctx) {
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    (void)depth;

    if (!preverifyOk) {
        // Permit only self-signed certificate errors. Every other error is
        // a genuine TLS failure and must be rejected to preserve trust semantics.
        if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
            err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            return 1;  // Accept self-signed certificates (identity enforced at application layer)
        }
        return 0;  // Reject all other certificate errors
    }

    return 1;  // Pre-verification passed
}

}  // namespace ExoSend
