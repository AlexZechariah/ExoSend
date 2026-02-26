#include <gtest/gtest.h>

#include "exosend/AtomicFile.h"

#include <fstream>

TEST(AtomicFileTest, ComputePathsAddsPartSuffix)
{
    const auto p = ExoSend::computeAtomicFilePaths(
        std::filesystem::path("C:\\tmp\\example.txt"));

    EXPECT_EQ(p.finalPath, std::filesystem::path("C:\\tmp\\example.txt"));
    EXPECT_EQ(p.tempPath, std::filesystem::path("C:\\tmp\\example.txt.part"));
}

TEST(AtomicFileTest, AtomicRenameMovesTempToFinal)
{
    const auto root = std::filesystem::temp_directory_path() / "exosend_atomic_file_test";
    std::filesystem::create_directories(root);

    const auto finalPath = root / "final.bin";
    const auto tempPath = root / "final.bin.part";

    // Clean slate
    std::error_code ec;
    std::filesystem::remove(finalPath, ec);
    std::filesystem::remove(tempPath, ec);

    {
        std::ofstream out(tempPath, std::ios::binary);
        out << "hello";
    }

    std::string err;
    ASSERT_TRUE(ExoSend::atomicRenameToFinal(tempPath, finalPath, err)) << err;

    EXPECT_TRUE(std::filesystem::exists(finalPath));
    EXPECT_FALSE(std::filesystem::exists(tempPath));

    std::ifstream in(finalPath, std::ios::binary);
    std::string content;
    content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "hello");
}

