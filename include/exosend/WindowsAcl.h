/**
 * @file WindowsAcl.h
 * @brief Windows-only helpers for restricting file ACLs to the current user.
 */

#pragma once

#include <string>

namespace ExoSend {

#ifdef _WIN32

/**
 * @brief Restrict an existing file or directory to the current Windows user.
 *
 * Best-effort defense-in-depth to reduce accidental disclosure to other local users.
 * This is not intended to defend against malware running as the same user.
 */
bool restrictPathToCurrentUser(const std::wstring& path, std::wstring* errorMsg = nullptr);

#endif  // _WIN32

}  // namespace ExoSend

