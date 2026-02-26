#include <gtest/gtest.h>

#ifdef _WIN32

#include "exosend/WinSafeFile.h"

#include <filesystem>
#include <fstream>

namespace {

static std::vector<uint8_t> readAllBytes(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::vector<uint8_t> bytes;
    bytes.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return bytes;
}

}  // namespace

TEST(WinSafeFile, CreateWriteRenameRoundTrip) {
    const auto base = std::filesystem::temp_directory_path() / "ExoSendWinSafeFileTest-\xE6\xB5\x8B\xE8\xAF\x95";
    std::filesystem::create_directories(base);

    std::wstring baseResolved;
    {
        std::string err;
        ASSERT_TRUE(ExoSend::getFinalPathForDirectory(base.wstring(), baseResolved, err)) << err;
        ASSERT_FALSE(baseResolved.empty());
    }

    const auto finalPath = base / "hello.bin";
    const auto tempPath = base / "hello.bin.part";

    // Clean up from previous runs.
    std::error_code ec;
    std::filesystem::remove(finalPath, ec);
    std::filesystem::remove(tempPath, ec);

    void* h = nullptr;
    std::wstring finalResolved;
    std::string err;

    EXPECT_TRUE(ExoSend::createNewWinFileExclusive(tempPath.wstring(), h, finalResolved, err))
        << err;
    ASSERT_NE(h, nullptr);

    const std::vector<uint8_t> payload = {'h','e','l','l','o'};
    EXPECT_TRUE(ExoSend::writeAllWinFile(h, payload.data(), payload.size(), err)) << err;

    ExoSend::closeWinFile(h);
    EXPECT_EQ(h, nullptr);

    EXPECT_TRUE(ExoSend::atomicRenameWin(tempPath.wstring(), finalPath.wstring(), err))
        << err;

    ASSERT_TRUE(std::filesystem::exists(finalPath));
    EXPECT_EQ(readAllBytes(finalPath), payload);
}

#endif  // _WIN32
