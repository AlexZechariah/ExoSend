/**
 * @file ProtectedBlob.cpp
 * @brief Windows DPAPI wrapper implementation.
 *
 * Uses CryptProtectData / CryptUnprotectData for user-scoped encryption and
 * CryptBinaryToStringA / CryptStringToBinaryA for Base64 encoding/decoding,
 * all from Crypt32.lib (Windows SDK -- no additional vcpkg dependency needed).
 */

#include "exosend/ProtectedBlob.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>  // CryptProtectData, CryptUnprotectData, CryptBinaryToStringA

#pragma comment(lib, "Crypt32.lib")
#endif

#include <cstring>
#include <stdexcept>

namespace ExoSend {

std::vector<uint8_t> ProtectedBlob::protect(const std::string& plaintext,
                                             std::string& errorMsg)
{
#ifdef _WIN32
    if (plaintext.empty()) {
        // Protecting empty data is valid; DPAPI will return a non-empty blob.
        // We still allow it so an empty trust store gets properly encrypted.
    }

    DATA_BLOB input{};
    input.cbData = static_cast<DWORD>(plaintext.size());
    // DATA_BLOB.pbData is BYTE* (non-const); we cast from const char* safely
    // because CryptProtectData treats the buffer as read-only.
    input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()));

    DATA_BLOB output{};
    output.cbData = 0;
    output.pbData = nullptr;

    // CRYPTPROTECT_UI_FORBIDDEN: never show a UI prompt (service/background context).
    BOOL ok = CryptProtectData(
        &input,
        nullptr,            // szDataDescr: optional description (not needed)
        nullptr,            // pOptionalEntropy: not used (user-scope is sufficient)
        nullptr,            // pvReserved
        nullptr,            // pPromptStruct
        CRYPTPROTECT_UI_FORBIDDEN,
        &output
    );

    if (!ok) {
        DWORD lastErr = GetLastError();
        char buf[64];
        snprintf(buf, sizeof(buf), "CryptProtectData failed: error 0x%08lX", lastErr);
        errorMsg = buf;
        return {};
    }

    std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
#else
    errorMsg = "DPAPI not available on this platform";
    return {};
#endif
}

std::string ProtectedBlob::unprotect(const std::vector<uint8_t>& ciphertext,
                                     std::string& errorMsg)
{
#ifdef _WIN32
    if (ciphertext.empty()) {
        errorMsg = "Empty ciphertext";
        return {};
    }

    DATA_BLOB input{};
    input.cbData = static_cast<DWORD>(ciphertext.size());
    input.pbData = const_cast<BYTE*>(ciphertext.data());

    DATA_BLOB output{};
    output.cbData = 0;
    output.pbData = nullptr;

    BOOL ok = CryptUnprotectData(
        &input,
        nullptr,    // ppszDataDescr: optional description output (not needed)
        nullptr,    // pOptionalEntropy
        nullptr,    // pvReserved
        nullptr,    // pPromptStruct
        CRYPTPROTECT_UI_FORBIDDEN,
        &output
    );

    if (!ok) {
        DWORD lastErr = GetLastError();
        char buf[64];
        snprintf(buf, sizeof(buf), "CryptUnprotectData failed: error 0x%08lX", lastErr);
        errorMsg = buf;
        return {};
    }

    std::string result(reinterpret_cast<char*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    return result;
#else
    errorMsg = "DPAPI not available on this platform";
    return {};
#endif
}

std::string ProtectedBlob::toBase64(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty()) {
        return {};
    }

#ifdef _WIN32
    // First call to get the required buffer size (including null terminator).
    DWORD encodedLen = 0;
    BOOL ok = CryptBinaryToStringA(
        bytes.data(),
        static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr,
        &encodedLen
    );
    if (!ok || encodedLen == 0) {
        return {};
    }

    std::string result(encodedLen, '\0');
    ok = CryptBinaryToStringA(
        bytes.data(),
        static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &result[0],
        &encodedLen
    );
    if (!ok) {
        return {};
    }

    // CryptBinaryToStringA null-terminates and encodedLen includes the null;
    // trim the trailing null so std::string has correct length.
    while (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    return result;
#else
    // Fallback: manual Base64 for non-Windows (not used in production).
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= bytes.size()) {
        uint32_t v = (static_cast<uint32_t>(bytes[i]) << 16) |
                     (static_cast<uint32_t>(bytes[i+1]) << 8) |
                     bytes[i+2];
        out += kTable[(v >> 18) & 63];
        out += kTable[(v >> 12) & 63];
        out += kTable[(v >>  6) & 63];
        out += kTable[(v >>  0) & 63];
        i += 3;
    }
    size_t rem = bytes.size() - i;
    if (rem == 1) {
        uint32_t v = static_cast<uint32_t>(bytes[i]) << 16;
        out += kTable[(v >> 18) & 63];
        out += kTable[(v >> 12) & 63];
        out += '='; out += '=';
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint32_t>(bytes[i]) << 16) |
                     (static_cast<uint32_t>(bytes[i+1]) << 8);
        out += kTable[(v >> 18) & 63];
        out += kTable[(v >> 12) & 63];
        out += kTable[(v >>  6) & 63];
        out += '=';
    }
    return out;
#endif
}

std::vector<uint8_t> ProtectedBlob::fromBase64(const std::string& b64)
{
    if (b64.empty()) {
        return {};
    }

#ifdef _WIN32
    DWORD decodedLen = 0;
    BOOL ok = CryptStringToBinaryA(
        b64.c_str(),
        static_cast<DWORD>(b64.size()),
        CRYPT_STRING_BASE64,
        nullptr,
        &decodedLen,
        nullptr,
        nullptr
    );
    if (!ok || decodedLen == 0) {
        return {};
    }

    std::vector<uint8_t> result(decodedLen);
    ok = CryptStringToBinaryA(
        b64.c_str(),
        static_cast<DWORD>(b64.size()),
        CRYPT_STRING_BASE64,
        result.data(),
        &decodedLen,
        nullptr,
        nullptr
    );
    if (!ok) {
        return {};
    }
    result.resize(decodedLen);
    return result;
#else
    // Fallback manual Base64 decode for non-Windows.
    static const int8_t kDecode[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve((b64.size() / 4) * 3);
    int val = 0, valb = -8;
    for (unsigned char c : b64) {
        if (c == '=') break;
        int d = kDecode[c];
        if (d == -1) return {};
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
#endif
}

}  // namespace ExoSend
