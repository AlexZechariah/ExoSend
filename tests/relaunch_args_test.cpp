/**
 * @file relaunch_args_test.cpp
 * @brief Tests for ExoSendRelaunch argument parsing.
 */

#include "exosend/RelaunchArgs.h"

#include <gtest/gtest.h>

#include <vector>

using ExoSend::RelaunchArgs;

TEST(RelaunchArgsTest, ParseOk_WaitPidAndLaunch)
{
    std::vector<std::wstring> args{
        L"--wait-pid",
        L"1234",
        L"--launch",
        L"C:\\Path\\ExoSend.exe",
    };

    RelaunchArgs out;
    std::wstring err;
    ASSERT_TRUE(RelaunchArgs::parse(args, out, &err));
    EXPECT_EQ(out.waitPid, 1234u);
    EXPECT_EQ(out.launchPath, L"C:\\Path\\ExoSend.exe");
}

TEST(RelaunchArgsTest, ParseRejectsMissingLaunch)
{
    std::vector<std::wstring> args{
        L"--wait-pid",
        L"1",
    };

    RelaunchArgs out;
    std::wstring err;
    EXPECT_FALSE(RelaunchArgs::parse(args, out, &err));
    EXPECT_FALSE(err.empty());
}

TEST(RelaunchArgsTest, ParseRejectsMissingWaitPid)
{
    std::vector<std::wstring> args{
        L"--launch",
        L"C:\\Path\\ExoSend.exe",
    };

    RelaunchArgs out;
    std::wstring err;
    EXPECT_FALSE(RelaunchArgs::parse(args, out, &err));
    EXPECT_FALSE(err.empty());
}

TEST(RelaunchArgsTest, ParseRejectsNonNumericPid)
{
    std::vector<std::wstring> args{
        L"--wait-pid",
        L"abc",
        L"--launch",
        L"C:\\Path\\ExoSend.exe",
    };

    RelaunchArgs out;
    std::wstring err;
    EXPECT_FALSE(RelaunchArgs::parse(args, out, &err));
    EXPECT_FALSE(err.empty());
}

TEST(RelaunchArgsTest, ParseRejectsUnknownFlag)
{
    std::vector<std::wstring> args{
        L"--nope",
    };

    RelaunchArgs out;
    std::wstring err;
    EXPECT_FALSE(RelaunchArgs::parse(args, out, &err));
    EXPECT_FALSE(err.empty());
}
