/**
 * @file DevResetArgs.cpp
 * @brief Developer-only reset tool argument parsing.
 */

#include "exosend/DevResetArgs.h"

#include <string>

namespace ExoSend {

DevResetArgs DevResetArgs::parseOrThrow(int argc, const char* const* argv) {
    DevResetArgs out;

    auto setAll = [&out]() {
        out.wipeState = true;
        out.wipeCerts = true;
        out.firewallRemove = true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i] ? std::string(argv[i]) : std::string();

        if (a == "--help" || a == "-h" || a == "/?") {
            out.showHelp = true;
            continue;
        }

        if (a == "--dry-run") {
            out.dryRun = true;
            continue;
        }

        if (a == "--force" || a == "--yes") {
            out.force = true;
            continue;
        }

        if (a == "--all") {
            setAll();
            continue;
        }

        if (a == "--wipe-state") {
            out.wipeState = true;
            continue;
        }

        if (a == "--wipe-certs") {
            out.wipeCerts = true;
            continue;
        }

        if (a == "--firewall-remove") {
            out.firewallRemove = true;
            continue;
        }

        throw std::runtime_error("Unknown argument: " + a);
    }

    if (!out.showHelp && !out.wipeState && !out.wipeCerts && !out.firewallRemove) {
        throw std::runtime_error("No action flags provided. Use --all or specific actions.");
    }

    return out;
}

}  // namespace ExoSend
