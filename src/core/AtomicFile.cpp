/**
 * @file AtomicFile.cpp
 * @brief Atomic file helpers implementation.
 */

#include "exosend/AtomicFile.h"

namespace ExoSend {

AtomicFilePaths computeAtomicFilePaths(const std::filesystem::path& finalPath)
{
    AtomicFilePaths out;
    out.finalPath = finalPath;
    out.tempPath = finalPath;
    out.tempPath += ".part";
    return out;
}

bool atomicRenameToFinal(const std::filesystem::path& tempPath,
                         const std::filesystem::path& finalPath,
                         std::string& errorMsg)
{
    errorMsg.clear();

    std::error_code ec;
    if (!std::filesystem::exists(tempPath, ec) || ec) {
        errorMsg = "Temp file does not exist";
        return false;
    }

    if (std::filesystem::exists(finalPath, ec)) {
        errorMsg = "Final file already exists";
        return false;
    }

    std::filesystem::rename(tempPath, finalPath, ec);
    if (ec) {
        errorMsg = std::string("rename failed: ") + ec.message();
        return false;
    }

    return true;
}

}  // namespace ExoSend
