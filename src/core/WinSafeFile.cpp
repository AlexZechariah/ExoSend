#ifdef _WIN32

#include "exosend/WinSafeFile.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <vector>

namespace ExoSend {
namespace {

static std::string winErr(DWORD err) {
    return "Win32 error " + std::to_string(static_cast<unsigned long long>(err));
}

static bool getFinalPathByHandle(HANDLE h, std::wstring& outFinalPath, std::string& errorMsg) {
    outFinalPath.clear();

    std::vector<wchar_t> buf(32768);
    const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD n = GetFinalPathNameByHandleW(h, buf.data(), static_cast<DWORD>(buf.size()), flags);
    if (n == 0 || n >= buf.size()) {
        errorMsg = "GetFinalPathNameByHandleW failed: " + winErr(GetLastError());
        return false;
    }
    outFinalPath.assign(buf.data(), n);
    return true;
}

}  // namespace

bool createNewWinFileExclusive(const std::wstring& path,
                               void*& outHandle,
                               std::wstring& outFinalPath,
                               std::string& errorMsg) {
    outHandle = nullptr;
    outFinalPath.clear();

    HANDLE h = CreateFileW(
        path.c_str(),
        GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        0,                // share mode: exclusive
        nullptr,
        CREATE_NEW,       // fail if exists
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) {
        errorMsg = "CreateFileW(CREATE_NEW) failed: " + winErr(GetLastError());
        return false;
    }

    if (!getFinalPathByHandle(h, outFinalPath, errorMsg)) {
        CloseHandle(h);
        return false;
    }

    outHandle = reinterpret_cast<void*>(h);
    return true;
}

bool writeAllWinFile(void* handle,
                     const uint8_t* data,
                     size_t size,
                     std::string& errorMsg) {
    if (!handle) {
        errorMsg = "Invalid file handle";
        return false;
    }
    if (!data || size == 0) return true;

    HANDLE h = reinterpret_cast<HANDLE>(handle);
    size_t totalWritten = 0;
    while (totalWritten < size) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(size - totalWritten, 1024 * 1024));
        DWORD written = 0;
        if (!WriteFile(h, data + totalWritten, chunk, &written, nullptr)) {
            errorMsg = "WriteFile failed: " + winErr(GetLastError());
            return false;
        }
        if (written == 0) {
            errorMsg = "WriteFile wrote 0 bytes";
            return false;
        }
        totalWritten += written;
    }
    return true;
}

void closeWinFile(void*& handle) {
    if (!handle) return;
    HANDLE h = reinterpret_cast<HANDLE>(handle);
    CloseHandle(h);
    handle = nullptr;
}

bool atomicRenameWin(const std::wstring& fromPath,
                     const std::wstring& toPath,
                     std::string& errorMsg) {
    const DWORD flags = MOVEFILE_WRITE_THROUGH;
    if (!MoveFileExW(fromPath.c_str(), toPath.c_str(), flags)) {
        errorMsg = "MoveFileExW failed: " + winErr(GetLastError());
        return false;
    }
    return true;
}

bool getFinalPathForDirectory(const std::wstring& dirPath,
                              std::wstring& outFinalDirPath,
                              std::string& errorMsg) {
    outFinalDirPath.clear();

    HANDLE h = CreateFileW(
        dirPath.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (h == INVALID_HANDLE_VALUE) {
        errorMsg = "CreateFileW(directory) failed: " + winErr(GetLastError());
        return false;
    }

    const bool ok = getFinalPathByHandle(h, outFinalDirPath, errorMsg);
    CloseHandle(h);
    return ok;
}

}  // namespace ExoSend

#endif  // _WIN32
