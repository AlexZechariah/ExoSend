/**
 * @file IncomingTransferPolicy.h
 * @brief Security policy helpers for incoming transfer decisions.
 */

#pragma once

#include <string>

namespace ExoSend {

/**
 * @brief Decide whether an incoming transfer may be auto-accepted.
 *
 * Auto-accept is only safe when:
 * - the user explicitly enabled auto-accept for this peer, AND
 * - the peer is already pinned (non-empty pinned fingerprint), AND
 * - the presented TLS fingerprint matches the pinned fingerprint.
 *
 * This function is intentionally strict. It prevents identity confusion and
 * ensures auto-accept never bypasses certificate pinning.
 */
bool shouldAutoAcceptIncoming(bool autoAcceptEnabled,
                              const std::string& pinnedFingerprintSha256Hex,
                              const std::string& presentedFingerprintSha256Hex);

}  // namespace ExoSend

