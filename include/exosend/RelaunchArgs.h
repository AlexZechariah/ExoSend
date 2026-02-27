/**
 * @file RelaunchArgs.h
 * @brief Argument parsing for ExoSendRelaunch helper.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ExoSend {

struct RelaunchArgs {
    uint32_t waitPid = 0;
    std::wstring launchPath;

    /**
     * @brief Parse arguments (excluding argv[0]) in a strict, fail-closed manner.
     *
     * Supported flags:
     * - --wait-pid <pid>
     * - --launch <path-to-ExoSend.exe>
     */
    static bool parse(const std::vector<std::wstring>& args, RelaunchArgs& out, std::wstring* outErr);
};

}  // namespace ExoSend

