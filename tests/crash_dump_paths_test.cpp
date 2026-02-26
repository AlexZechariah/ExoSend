#include <gtest/gtest.h>

#include "exosend/CrashDumpPaths.h"

#include <filesystem>

TEST(CrashDumpPathsTest, UsesLocalAppDataExoSendCrashDumpsDir)
{
#ifdef _WIN32
    const auto dir = ExoSend::CrashDumpPaths::dumpDir();
    ASSERT_FALSE(dir.empty());

    EXPECT_EQ(dir.filename(), std::filesystem::path("crash_dumps"));
    EXPECT_EQ(dir.parent_path().filename(), std::filesystem::path("ExoSend"));
#else
    GTEST_SKIP() << "Windows-only";
#endif
}

TEST(CrashDumpPathsTest, FileNamesContainTimestampAndPid)
{
#ifdef _WIN32
    const std::string ts = "20260226_104000_123";
    const unsigned long pid = 4242;

    const auto dmp = ExoSend::CrashDumpPaths::dumpFilePath(ts, pid);
    const auto log = ExoSend::CrashDumpPaths::logFilePath(ts, pid);

    ASSERT_FALSE(dmp.empty());
    ASSERT_FALSE(log.empty());

    EXPECT_TRUE(dmp.filename().wstring().find(L"crash_") != std::wstring::npos);
    EXPECT_TRUE(dmp.filename().wstring().find(L"pid4242") != std::wstring::npos);
    EXPECT_EQ(dmp.extension(), std::filesystem::path(".dmp"));

    EXPECT_TRUE(log.filename().wstring().find(L"crash_") != std::wstring::npos);
    EXPECT_TRUE(log.filename().wstring().find(L"pid4242") != std::wstring::npos);
    EXPECT_EQ(log.extension(), std::filesystem::path(".txt"));
#else
    GTEST_SKIP() << "Windows-only";
#endif
}

