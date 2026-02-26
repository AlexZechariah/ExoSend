/**
 * @file IncomingTransferPolicy.cpp
 * @brief Incoming transfer security policy implementation.
 */

#include "exosend/IncomingTransferPolicy.h"
#include "exosend/FingerprintUtils.h"

namespace ExoSend {

bool shouldAutoAcceptIncoming(bool autoAcceptEnabled,
                              const std::string& pinnedFingerprintSha256Hex,
                              const std::string& presentedFingerprintSha256Hex)
{
    if (!autoAcceptEnabled) {
        return false;
    }

    const std::string pinned =
        FingerprintUtils::normalizeSha256Hex(pinnedFingerprintSha256Hex);
    const std::string presented =
        FingerprintUtils::normalizeSha256Hex(presentedFingerprintSha256Hex);

    if (pinned.empty() || presented.empty()) {
        return false;
    }

    return pinned == presented;
}

}  // namespace ExoSend
