/**
 * @file tls_callback_test.cpp
 * @brief Unit tests for the TLS certificate verification callback.
 *
 * Verifies that tlsVerifyCallback correctly implements the TOFU model:
 * - Accepts self-signed certificate errors (TOFU pairing)
 * - Rejects all other TLS verification errors
 * - Passes through when OpenSSL pre-verification succeeded
 */

#include "exosend/TlsSocket.h"
#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

using namespace ExoSend;

namespace {

// Build a minimal X509_STORE_CTX with a specific error code set.
// No real certificate is needed: we only set the error code to exercise
// the callback's decision logic.
struct TestCtx {
    X509_STORE_CTX* ctx = nullptr;
    X509_STORE* store = nullptr;

    explicit TestCtx(int errorCode) {
        store = X509_STORE_new();
        ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, nullptr, nullptr);
        X509_STORE_CTX_set_error(ctx, errorCode);
    }

    ~TestCtx() {
        if (ctx) X509_STORE_CTX_free(ctx);
        if (store) X509_STORE_free(store);
    }
};

} // namespace

// When OpenSSL pre-verification already passed, the callback must accept.
TEST(TlsCallbackTest, AcceptWhenPreverifyOk) {
    TestCtx tc(X509_V_OK);
    EXPECT_EQ(1, tlsVerifyCallback(1, tc.ctx));
}

// Self-signed cert at depth 0 must be accepted (TOFU model).
TEST(TlsCallbackTest, AcceptDepthZeroSelfSigned) {
    TestCtx tc(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    EXPECT_EQ(1, tlsVerifyCallback(0, tc.ctx));
}

// Self-signed cert in chain must be accepted (TOFU model).
TEST(TlsCallbackTest, AcceptSelfSignedInChain) {
    TestCtx tc(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN);
    EXPECT_EQ(1, tlsVerifyCallback(0, tc.ctx));
}

// Expired certificate must be rejected (not a self-signed error).
TEST(TlsCallbackTest, RejectExpiredCert) {
    TestCtx tc(X509_V_ERR_CERT_HAS_EXPIRED);
    EXPECT_EQ(0, tlsVerifyCallback(0, tc.ctx));
}

// Cert not yet valid must be rejected.
TEST(TlsCallbackTest, RejectNotYetValidCert) {
    TestCtx tc(X509_V_ERR_CERT_NOT_YET_VALID);
    EXPECT_EQ(0, tlsVerifyCallback(0, tc.ctx));
}

// Unknown issuer must be rejected.
TEST(TlsCallbackTest, RejectUnknownIssuer) {
    TestCtx tc(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    EXPECT_EQ(0, tlsVerifyCallback(0, tc.ctx));
}
