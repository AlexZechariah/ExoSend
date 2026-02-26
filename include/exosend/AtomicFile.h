/**
 * @file AtomicFile.h
 * @brief Small helpers for atomic file writes (write temp, then rename).
 */

#pragma once

#include <filesystem>
#include <string>

namespace ExoSend {

struct AtomicFilePaths {
    std::filesystem::path finalPath;
    std::filesystem::path tempPath;
};

/**
 * @brief Compute a temp path next to finalPath for atomic writes.
 *
 * The temp path is derived deterministically from finalPath so callers can
 * clean up partial files on error.
 */
AtomicFilePaths computeAtomicFilePaths(const std::filesystem::path& finalPath);

/**
 * @brief Atomically replace finalPath with tempPath using rename semantics.
 *
 * Requirements:
 * - tempPath must exist as a file.
 * - finalPath must not already exist (callers should choose a unique final name).
 */
bool atomicRenameToFinal(const std::filesystem::path& tempPath,
                         const std::filesystem::path& finalPath,
                         std::string& errorMsg);

}  // namespace ExoSend

