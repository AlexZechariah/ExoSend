/**
 * @file DevResetArgs.h
 * @brief Developer-only reset tool argument parsing.
 */

#pragma once

#include <stdexcept>

namespace ExoSend {

struct DevResetArgs {
    bool showHelp = false;
    bool dryRun = false;

    bool wipeState = false;
    bool wipeCerts = false;
    bool firewallRemove = false;

    bool force = false;

    static DevResetArgs parseOrThrow(int argc, const char* const* argv);
};

}  // namespace ExoSend

