#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <string>

namespace ExoSend {

// Creates a new file at `path` using Win32 CREATE_NEW semantics (fails if exists),
// and returns a handle plus the final resolved path of the opened handle.
// `outHandle` is a Win32 HANDLE represented as void* to avoid leaking windows.h
// into public headers.
bool createNewWinFileExclusive(const std::wstring& path,
                               void*& outHandle,
                               std::wstring& outFinalPath,
                               std::string& errorMsg);

bool writeAllWinFile(void* handle,
                     const uint8_t* data,
                     size_t size,
                     std::string& errorMsg);

void closeWinFile(void*& handle);

bool atomicRenameWin(const std::wstring& fromPath,
                     const std::wstring& toPath,
                     std::string& errorMsg);

// Resolves a directory path to its final normalized path using a directory handle.
// Output uses the same `\\?\`-prefixed DOS volume form as GetFinalPathNameByHandleW.
bool getFinalPathForDirectory(const std::wstring& dirPath,
                              std::wstring& outFinalDirPath,
                              std::string& errorMsg);

// Simple RAII wrapper for a Win32 HANDLE represented as void*.
// Needed to avoid double-close in move operations when used as a class member.
struct ScopedWinFile {
    void* handle = nullptr;

    ScopedWinFile() = default;
    explicit ScopedWinFile(void* h) : handle(h) {}

    ~ScopedWinFile() { closeWinFile(handle); }

    ScopedWinFile(const ScopedWinFile&) = delete;
    ScopedWinFile& operator=(const ScopedWinFile&) = delete;

    ScopedWinFile(ScopedWinFile&& other) noexcept : handle(other.handle) {
        other.handle = nullptr;
    }

    ScopedWinFile& operator=(ScopedWinFile&& other) noexcept {
        if (this != &other) {
            closeWinFile(handle);
            handle = other.handle;
            other.handle = nullptr;
        }
        return *this;
    }
};

}  // namespace ExoSend

#endif  // _WIN32
