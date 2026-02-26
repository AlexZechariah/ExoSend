#include <gtest/gtest.h>

#include "exosend/AppPaths.h"

#include <filesystem>

TEST(AppPathsTest, CanonicalConfigPathIsSingleExoSendFolder)
{
#ifdef _WIN32
    const auto canonical = ExoSend::AppPaths::configJsonPath();
    const auto legacy = ExoSend::AppPaths::legacyQtAppLocalConfigJsonPath();

    ASSERT_FALSE(canonical.empty());
    ASSERT_FALSE(legacy.empty());

    EXPECT_EQ(canonical.filename(), std::filesystem::path("config.json"));
    EXPECT_EQ(canonical.parent_path().filename(), std::filesystem::path("ExoSend"));

    // Canonical and legacy must differ; legacy path contains the redundant ExoSend\ExoSend.
    EXPECT_NE(canonical, legacy);
    EXPECT_EQ(legacy.filename(), std::filesystem::path("config.json"));
    EXPECT_EQ(legacy.parent_path().filename(), std::filesystem::path("ExoSend"));
    EXPECT_EQ(legacy.parent_path().parent_path().filename(), std::filesystem::path("ExoSend"));
#else
    GTEST_SKIP() << "Windows-only path contract";
#endif
}

TEST(AppPathsTest, CrashTraceLogPathIsUnderLocalAppDataLogs)
{
#ifdef _WIN32
    const auto p = ExoSend::AppPaths::crashTraceLogPath();
    ASSERT_FALSE(p.empty());
    EXPECT_EQ(p.filename(), std::filesystem::path("crash_trace.txt"));
    EXPECT_EQ(p.parent_path().filename(), std::filesystem::path("logs"));
    EXPECT_EQ(p.parent_path().parent_path().filename(), std::filesystem::path("ExoSend"));
#else
    GTEST_SKIP() << "Windows-only path contract";
#endif
}
