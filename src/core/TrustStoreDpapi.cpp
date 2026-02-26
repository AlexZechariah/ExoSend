/**
 * @file TrustStoreDpapi.cpp
 * @brief DPAPI trust store persistence helpers implementation.
 */

#include "exosend/TrustStoreDpapi.h"
#include "exosend/ProtectedBlob.h"

namespace ExoSend {

TrustStoreDpapiProtectResult protectTrustStoreJsonToBase64(
    const std::string& trustStoreJson,
    const std::string& existingTrustStoreDpapiBase64,
    const std::function<std::vector<uint8_t>(const std::string& plaintext, std::string& errorMsg)>& protectFn)
{
    TrustStoreDpapiProtectResult out;

    if (!protectFn) {
        out.ok = false;
        out.error = "protectFn is null";
        return out;
    }

    std::string protectError;
    const std::vector<uint8_t> ciphertext = protectFn(trustStoreJson, protectError);
    if (ciphertext.empty()) {
        if (!existingTrustStoreDpapiBase64.empty()) {
            out.ok = true;
            out.usedExisting = true;
            out.trustStoreDpapiBase64 = existingTrustStoreDpapiBase64;
            out.error = protectError;
            return out;
        }

        out.ok = false;
        out.usedExisting = false;
        out.error = protectError.empty() ? "protect failed" : protectError;
        return out;
    }

    out.trustStoreDpapiBase64 = ProtectedBlob::toBase64(ciphertext);
    if (out.trustStoreDpapiBase64.empty()) {
        out.ok = false;
        out.usedExisting = false;
        out.error = "Base64 encoding failed";
        return out;
    }

    out.ok = true;
    out.usedExisting = false;
    out.error.clear();
    return out;
}

}  // namespace ExoSend
