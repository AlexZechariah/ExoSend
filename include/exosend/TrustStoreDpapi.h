/**
 * @file TrustStoreDpapi.h
 * @brief Helpers for DPAPI-protected trust store persistence.
 */

#pragma once

#include <functional>
#include <string>
#include <vector>

namespace ExoSend {

struct TrustStoreDpapiProtectResult {
    bool ok{false};
    bool usedExisting{false};
    std::string trustStoreDpapiBase64;
    std::string error;
};

/**
 * @brief Protect the trust store JSON and return base64 for settings persistence.
 *
 * If protectFn fails (returns empty ciphertext), this function can preserve an existing
 * base64 value to avoid erasing the persisted trust store.
 *
 * @param trustStoreJson Plaintext trust store JSON (already serialized).
 * @param existingTrustStoreDpapiBase64 Existing persisted base64 (can be empty).
 * @param protectFn Function that returns ciphertext bytes (empty means failure).
 * @return Result with ok=true and trustStoreDpapiBase64 set on success.
 */
TrustStoreDpapiProtectResult protectTrustStoreJsonToBase64(
    const std::string& trustStoreJson,
    const std::string& existingTrustStoreDpapiBase64,
    const std::function<std::vector<uint8_t>(const std::string& plaintext, std::string& errorMsg)>& protectFn);

}  // namespace ExoSend

