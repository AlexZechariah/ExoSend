/**
 * @file dev_reset_args_test.cpp
 * @brief Tests for ExoSendDevReset argument parsing (developer tooling).
 */

#include "exosend/DevResetArgs.h"

#include <gtest/gtest.h>

using namespace ExoSend;

TEST(DevResetArgsTest, HelpFlagSetsShowHelp) {
    const char* argv[] = {"ExoSendDevReset.exe", "--help"};
    DevResetArgs a = DevResetArgs::parseOrThrow(2, argv);
    EXPECT_TRUE(a.showHelp);
}

TEST(DevResetArgsTest, AllExpandsToAllActions) {
    const char* argv[] = {"ExoSendDevReset.exe", "--all", "--force"};
    DevResetArgs a = DevResetArgs::parseOrThrow(3, argv);
    EXPECT_TRUE(a.wipeState);
    EXPECT_TRUE(a.wipeCerts);
    EXPECT_TRUE(a.firewallRemove);
    EXPECT_TRUE(a.force);
}

TEST(DevResetArgsTest, DryRunIsNonDestructive) {
    const char* argv[] = {"ExoSendDevReset.exe", "--dry-run", "--all"};
    DevResetArgs a = DevResetArgs::parseOrThrow(3, argv);
    EXPECT_TRUE(a.dryRun);
    EXPECT_TRUE(a.wipeState);
    EXPECT_TRUE(a.wipeCerts);
    EXPECT_TRUE(a.firewallRemove);
}

TEST(DevResetArgsTest, MissingActionFlagsThrows) {
    const char* argv[] = {"ExoSendDevReset.exe", "--force"};
    EXPECT_THROW((void)DevResetArgs::parseOrThrow(2, argv), std::runtime_error);
}

