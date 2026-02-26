/**
 * @file MigrationUtils.h
 * @brief Best-effort migration helpers for on-disk state between versions.
 *
 * These helpers are intended for:
 * - Moving config.json from legacy Qt-derived locations to canonical paths
 * - Moving certificate/key material from legacy roaming locations to local paths
 *
 * Migration is best-effort and must never corrupt existing destination state.
 */

#pragma once

#include <filesystem>
#include <string>

namespace ExoSend::MigrationUtils {

struct Result {
    bool ok = true;
    bool migrated = false;
    std::string error;
};

/**
 * @brief Migrate a legacy file to a destination path if and only if the destination
 *        does not already exist.
 *
 * Behavior:
 * - If dest exists: ok=true, migrated=false
 * - If legacy does not exist: ok=true, migrated=false
 * - If legacy exists and dest missing: attempt rename; if that fails, copy+delete.
 * - Never overwrites an existing dest.
 */
Result migrateFileIfDestMissing(const std::filesystem::path& dest,
                               const std::filesystem::path& legacy);

/**
 * @brief Migrate certificate directory contents from legacyDir into destDir.
 *
 * This is targeted and avoids unexpected merges:
 * - If destDir contains both required files, nothing happens.
 * - If destDir missing required files and legacyDir has them, copy them to destDir.
 * - On successful copy of both required files, legacy files are removed (best-effort).
 */
Result migrateCertMaterialIfMissing(const std::filesystem::path& destDir,
                                   const std::filesystem::path& legacyDir,
                                   const std::string& certFileName,
                                   const std::string& keyFileName);

}  // namespace ExoSend::MigrationUtils

