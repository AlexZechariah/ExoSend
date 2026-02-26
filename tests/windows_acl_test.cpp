#ifdef _WIN32

#include <gtest/gtest.h>

#include "exosend/WindowsAcl.h"

#include <filesystem>
#include <fstream>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

static std::string wideToUtf8(const std::wstring& w)
{
    if (w.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8, 0,
        w.data(), static_cast<int>(w.size()),
        nullptr, 0,
        nullptr, nullptr
    );
    if (required <= 0) {
        return {};
    }

    std::string out(static_cast<size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, 0,
        w.data(), static_cast<int>(w.size()),
        out.data(), required,
        nullptr, nullptr
    );
    if (written <= 0) {
        return {};
    }
    return out;
}

TEST(WindowsAclTest, RestrictPathToCurrentUserSucceedsOnTempFile)
{
    const auto root = std::filesystem::temp_directory_path() / "exosend_windows_acl_test";
    std::filesystem::create_directories(root);

    const auto p = root / "acl_test.txt";
    {
        std::ofstream out(p, std::ios::binary);
        out << "data";
    }

    std::wstring err;
    EXPECT_TRUE(ExoSend::restrictPathToCurrentUser(p.wstring(), &err)) << wideToUtf8(err);
}

#endif
