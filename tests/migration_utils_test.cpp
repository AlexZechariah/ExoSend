#include <gtest/gtest.h>

#include "exosend/MigrationUtils.h"

#include <filesystem>
#include <fstream>

static void writeTextFile(const std::filesystem::path& p, const std::string& s)
{
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << s;
}

static std::string readTextFile(const std::filesystem::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

TEST(MigrationUtilsTest, MigrateFileIfDestMissingMovesLegacyFile)
{
    const auto root = std::filesystem::temp_directory_path() / "exosend_migration_utils_file_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    const auto legacy = root / "legacy" / "config.json";
    const auto dest = root / "dest" / "config.json";

    writeTextFile(legacy, "hello");
    ASSERT_TRUE(std::filesystem::exists(legacy));
    ASSERT_FALSE(std::filesystem::exists(dest));

    const auto r = ExoSend::MigrationUtils::migrateFileIfDestMissing(dest, legacy);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.migrated);

    EXPECT_TRUE(std::filesystem::exists(dest));
    EXPECT_FALSE(std::filesystem::exists(legacy));
    EXPECT_EQ(readTextFile(dest), "hello");
}

TEST(MigrationUtilsTest, MigrateCertMaterialCopiesBothThenRemovesLegacy)
{
    const auto root = std::filesystem::temp_directory_path() / "exosend_migration_utils_certs_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    const auto legacyDir = root / "legacy_certs";
    const auto destDir = root / "dest_certs";

    const std::string certName = "server.crt";
    const std::string keyName = "server.key";

    writeTextFile(legacyDir / certName, "CERT");
    writeTextFile(legacyDir / keyName, "KEY");

    const auto r = ExoSend::MigrationUtils::migrateCertMaterialIfMissing(
        destDir, legacyDir, certName, keyName);

    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.migrated);

    EXPECT_TRUE(std::filesystem::exists(destDir / certName));
    EXPECT_TRUE(std::filesystem::exists(destDir / keyName));
    EXPECT_EQ(readTextFile(destDir / certName), "CERT");
    EXPECT_EQ(readTextFile(destDir / keyName), "KEY");

    EXPECT_FALSE(std::filesystem::exists(legacyDir / certName));
    EXPECT_FALSE(std::filesystem::exists(legacyDir / keyName));
}

