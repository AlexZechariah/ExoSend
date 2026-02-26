/**
 * @file MigrationUtils.cpp
 * @brief On-disk state migration helpers.
 */

#include "exosend/MigrationUtils.h"

#include <system_error>

namespace ExoSend::MigrationUtils {

static bool pathExistsRegularFile(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec) && std::filesystem::is_regular_file(p, ec);
}

static bool pathExistsDirectory(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec) && std::filesystem::is_directory(p, ec);
}

static void tryRemoveIfEmpty(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        return;
    }
    if (std::filesystem::is_empty(dir, ec)) {
        (void)std::filesystem::remove(dir, ec);
    }
}

Result migrateFileIfDestMissing(const std::filesystem::path& dest,
                               const std::filesystem::path& legacy) {
    Result r;

    if (dest.empty() || legacy.empty()) {
        return r;
    }

    std::error_code ec;

    if (std::filesystem::exists(dest, ec)) {
        // Never overwrite.
        r.ok = true;
        r.migrated = false;
        return r;
    }

    if (!pathExistsRegularFile(legacy)) {
        r.ok = true;
        r.migrated = false;
        return r;
    }

    const auto destDir = dest.parent_path();
    if (!destDir.empty()) {
        std::filesystem::create_directories(destDir, ec);
        if (ec) {
            r.ok = false;
            r.error = "Failed to create destination directory: " + destDir.u8string();
            return r;
        }
    }

    // Prefer rename for atomic move within volume.
    std::filesystem::rename(legacy, dest, ec);
    if (!ec) {
        r.ok = true;
        r.migrated = true;
        tryRemoveIfEmpty(legacy.parent_path());
        return r;
    }

    // Fallback: copy then remove legacy.
    ec.clear();
    std::filesystem::copy_file(legacy, dest, std::filesystem::copy_options::none, ec);
    if (ec) {
        r.ok = false;
        r.error = "Failed to copy legacy file to destination";
        return r;
    }

    ec.clear();
    (void)std::filesystem::remove(legacy, ec);
    tryRemoveIfEmpty(legacy.parent_path());

    r.ok = true;
    r.migrated = true;
    return r;
}

Result migrateCertMaterialIfMissing(const std::filesystem::path& destDir,
                                   const std::filesystem::path& legacyDir,
                                   const std::string& certFileName,
                                   const std::string& keyFileName) {
    Result r;
    if (destDir.empty() || legacyDir.empty()) {
        return r;
    }

    const auto destCert = destDir / certFileName;
    const auto destKey = destDir / keyFileName;
    const auto legacyCert = legacyDir / certFileName;
    const auto legacyKey = legacyDir / keyFileName;

    const bool destHasAll = pathExistsRegularFile(destCert) && pathExistsRegularFile(destKey);
    if (destHasAll) {
        r.ok = true;
        r.migrated = false;
        return r;
    }

    const bool legacyHasAll = pathExistsRegularFile(legacyCert) && pathExistsRegularFile(legacyKey);
    if (!legacyHasAll) {
        r.ok = true;
        r.migrated = false;
        return r;
    }

    std::error_code ec;
    std::filesystem::create_directories(destDir, ec);
    if (ec) {
        r.ok = false;
        r.error = "Failed to create destination cert directory: " + destDir.u8string();
        return r;
    }

    // Copy both required files. Never overwrite.
    if (!std::filesystem::exists(destCert, ec)) {
        ec.clear();
        std::filesystem::copy_file(legacyCert, destCert, std::filesystem::copy_options::none, ec);
        if (ec) {
            r.ok = false;
            r.error = "Failed to copy legacy certificate file";
            return r;
        }
    }

    if (!std::filesystem::exists(destKey, ec)) {
        ec.clear();
        std::filesystem::copy_file(legacyKey, destKey, std::filesystem::copy_options::none, ec);
        if (ec) {
            r.ok = false;
            r.error = "Failed to copy legacy key file";
            return r;
        }
    }

    // Best-effort cleanup of legacy to reduce key material duplication on disk.
    ec.clear();
    (void)std::filesystem::remove(legacyCert, ec);
    ec.clear();
    (void)std::filesystem::remove(legacyKey, ec);
    tryRemoveIfEmpty(legacyDir);
    tryRemoveIfEmpty(legacyDir.parent_path());

    r.ok = true;
    r.migrated = true;
    return r;
}

}  // namespace ExoSend::MigrationUtils

