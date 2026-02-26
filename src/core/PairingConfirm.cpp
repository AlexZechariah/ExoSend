/**
 * @file PairingConfirm.cpp
 * @brief PairingConfirm implementation.
 */

#include "exosend/PairingConfirm.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace ExoSend {

namespace {

static std::string opensslLastErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "Unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

static void appendU16LE(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

static bool buildTagMessage(PairingRole role,
                            const std::string& localUuid,
                            const std::string& localFingerprint,
                            const std::string& peerUuid,
                            const std::string& peerFingerprint,
                            std::vector<uint8_t>& out,
                            std::string& errorMsg) {
    constexpr const char* kDomain = "ExoSend Pairing Confirm Tag v1";

    if (peerUuid.size() > 255u) {
        errorMsg = "peerUuid too long";
        return false;
    }
    if (peerFingerprint.size() > 255u) {
        errorMsg = "peerFingerprint too long";
        return false;
    }
    if (localUuid.size() > 255u) {
        errorMsg = "localUuid too long";
        return false;
    }
    if (localFingerprint.size() > 255u) {
        errorMsg = "localFingerprint too long";
        return false;
    }

    out.clear();
    out.insert(out.end(), kDomain, kDomain + std::strlen(kDomain));
    out.push_back(0);

    out.push_back(role == PairingRole::Client ? 1u : 2u);

    appendU16LE(out, static_cast<uint16_t>(localUuid.size()));
    out.insert(out.end(), localUuid.begin(), localUuid.end());

    appendU16LE(out, static_cast<uint16_t>(localFingerprint.size()));
    out.insert(out.end(), localFingerprint.begin(), localFingerprint.end());

    appendU16LE(out, static_cast<uint16_t>(peerUuid.size()));
    out.insert(out.end(), peerUuid.begin(), peerUuid.end());

    appendU16LE(out, static_cast<uint16_t>(peerFingerprint.size()));
    out.insert(out.end(), peerFingerprint.begin(), peerFingerprint.end());

    return true;
}

static bool hmacSha256(const std::array<uint8_t, 32>& key,
                       const std::vector<uint8_t>& msg,
                       std::array<uint8_t, 32>& outTag,
                       std::string& errorMsg) {
    unsigned int outLen = 0;
    unsigned char* result = HMAC(
        EVP_sha256(),
        key.data(),
        static_cast<int>(key.size()),
        msg.data(),
        msg.size(),
        outTag.data(),
        &outLen
    );

    if (!result || outLen != outTag.size()) {
        errorMsg = "HMAC-SHA256 failed: " + opensslLastErrorString();
        std::fill(outTag.begin(), outTag.end(), 0);
        return false;
    }

    return true;
}

}  // namespace

bool PairingConfirm::deriveConfirmKey(const std::array<uint8_t, 16>& pairingSecret,
                                      const std::array<uint8_t, 32>& tlsExporterChannelBinding,
                                      std::array<uint8_t, 32>& outKey,
                                      std::string& errorMsg) {
    constexpr const char* kInfo = "ExoSend Pairing Confirm Key v1";

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        errorMsg = "EVP_PKEY_CTX_new_id(HKDF) failed: " + opensslLastErrorString();
        return false;
    }

    bool ok = false;
    do {
        if (EVP_PKEY_derive_init(pctx) != 1) {
            errorMsg = "EVP_PKEY_derive_init failed: " + opensslLastErrorString();
            break;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) {
            errorMsg = "EVP_PKEY_CTX_set_hkdf_md failed: " + opensslLastErrorString();
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx,
                                        tlsExporterChannelBinding.data(),
                                        tlsExporterChannelBinding.size()) != 1) {
            errorMsg = "EVP_PKEY_CTX_set1_hkdf_salt failed: " + opensslLastErrorString();
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx,
                                       pairingSecret.data(),
                                       pairingSecret.size()) != 1) {
            errorMsg = "EVP_PKEY_CTX_set1_hkdf_key failed: " + opensslLastErrorString();
            break;
        }
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx,
                                        reinterpret_cast<const unsigned char*>(kInfo),
                                        std::strlen(kInfo)) != 1) {
            errorMsg = "EVP_PKEY_CTX_add1_hkdf_info failed: " + opensslLastErrorString();
            break;
        }

        size_t outLen = outKey.size();
        if (EVP_PKEY_derive(pctx, outKey.data(), &outLen) != 1 || outLen != outKey.size()) {
            errorMsg = "EVP_PKEY_derive(HKDF) failed: " + opensslLastErrorString();
            break;
        }

        ok = true;
    } while (false);

    EVP_PKEY_CTX_free(pctx);

    if (!ok) {
        std::fill(outKey.begin(), outKey.end(), 0);
    }

    return ok;
}

bool PairingConfirm::computeTag(const std::array<uint8_t, 32>& confirmKey,
                               PairingRole role,
                               const std::string& localUuid,
                               const std::string& localFingerprint,
                               const std::string& peerUuid,
                               const std::string& peerFingerprint,
                               std::array<uint8_t, 32>& outTag,
                               std::string& errorMsg) {
    std::vector<uint8_t> msg;
    if (!buildTagMessage(role, localUuid, localFingerprint, peerUuid, peerFingerprint, msg, errorMsg)) {
        std::fill(outTag.begin(), outTag.end(), 0);
        return false;
    }
    return hmacSha256(confirmKey, msg, outTag, errorMsg);
}

bool PairingConfirm::verifyTag(const std::array<uint8_t, 32>& confirmKey,
                              PairingRole role,
                              const std::string& localUuid,
                              const std::string& localFingerprint,
                              const std::string& peerUuid,
                              const std::string& peerFingerprint,
                              const std::array<uint8_t, 32>& receivedTag,
                              std::string& errorMsg) {
    std::array<uint8_t, 32> expected{};
    if (!computeTag(confirmKey, role, localUuid, localFingerprint, peerUuid, peerFingerprint, expected, errorMsg)) {
        return false;
    }

    if (CRYPTO_memcmp(expected.data(), receivedTag.data(), expected.size()) != 0) {
        errorMsg = "Pairing confirm tag mismatch";
        return false;
    }

    return true;
}

}  // namespace ExoSend
