/**
 * @file ErrorCodes.h
 * @brief Stable, user-visible error codes for troubleshooting.
 *
 * These codes are intended to be:
 * - Stable across versions (avoid renaming once shipped)
 * - Short and searchable
 * - Presented alongside a human-readable message
 */

#pragma once

namespace ExoSend {
namespace ErrorCodes {

// Pairing (secure pairing / trust establishment)
inline constexpr const char* PAIRING_CANCELLED = "EXO-PAIR-1000";
inline constexpr const char* PAIRING_INVALID_PHRASE = "EXO-PAIR-1001";
inline constexpr const char* PAIRING_AMBIGUOUS_PHRASE = "EXO-PAIR-1002";
inline constexpr const char* PAIRING_TIMED_OUT = "EXO-PAIR-1003";
inline constexpr const char* PAIRING_REJECTED_REMOTE = "EXO-PAIR-1004";
inline constexpr const char* PAIRING_PROTOCOL_ERROR = "EXO-PAIR-1100";
inline constexpr const char* PAIRING_TLS_ERROR = "EXO-PAIR-1200";
inline constexpr const char* PAIRING_INTERNAL_ERROR = "EXO-PAIR-1300";

}  // namespace ErrorCodes
}  // namespace ExoSend

