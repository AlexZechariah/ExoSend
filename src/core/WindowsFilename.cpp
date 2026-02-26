#include "exosend/WindowsFilename.h"

#include <algorithm>
#include <cctype>
#include <string_view>

namespace ExoSend {
namespace {

constexpr size_t kMaxFilenameBytes = 240;

static bool isControlChar(unsigned char ch) {
    return ch < 32;
}

static bool isInvalidWindowsFilenameChar(unsigned char ch) {
    // Win32 invalid filename characters: < > : " / \ | ? *
    switch (ch) {
    case '<':
    case '>':
    case ':':
    case '"':
    case '/':
    case '\\':
    case '|':
    case '?':
    case '*':
        return true;
    default:
        return false;
    }
}

static std::string toUpperAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char ch : s) {
        out.push_back(static_cast<char>(std::toupper(ch)));
    }
    return out;
}

static bool isReservedDeviceName(std::string_view nameNoExtUpper) {
    // Reserved device names: CON, PRN, AUX, NUL, COM1..COM9, LPT1..LPT9
    if (nameNoExtUpper == "CON" || nameNoExtUpper == "PRN" || nameNoExtUpper == "AUX" ||
        nameNoExtUpper == "NUL") {
        return true;
    }
    if (nameNoExtUpper.size() == 4) {
        const auto prefix = nameNoExtUpper.substr(0, 3);
        const char digit = nameNoExtUpper[3];
        if ((prefix == "COM" || prefix == "LPT") && (digit >= '1' && digit <= '9')) {
            return true;
        }
    }
    return false;
}

static std::string_view stripExtension(std::string_view name) {
    // Reserved device name matching should ignore everything after the FIRST dot.
    // Windows treats e.g. "LPT1.txt" and "LPT1.anything" as reserved device names.
    const auto dot = name.find_first_of('.');
    if (dot == std::string_view::npos) return name;
    return name.substr(0, dot);
}

static void trimTrailingDotsAndSpaces(std::string& s) {
    while (!s.empty()) {
        const char ch = s.back();
        if (ch == ' ' || ch == '.') {
            s.pop_back();
            continue;
        }
        break;
    }
}

}  // namespace

bool sanitizeWindowsFilenameInPlace(std::string& name) {
    if (name.empty()) return false;

    // Reject ADS stream specifiers completely (':' anywhere).
    if (name.find(':') != std::string::npos) {
        return false;
    }

    for (char& ch : name) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (isControlChar(uch)) return false;
        if (isInvalidWindowsFilenameChar(uch)) {
            ch = '_';
        }
    }

    // Replace traversal-like hints.
    size_t pos = 0;
    while ((pos = name.find("..", pos)) != std::string::npos) {
        name.replace(pos, 2, "__");
    }

    trimTrailingDotsAndSpaces(name);

    if (name.empty()) return false;
    if (name.find_first_not_of("._") == std::string::npos) return false;
    if (name.size() > kMaxFilenameBytes) return false;

    const std::string upperNoExt = toUpperAscii(stripExtension(name));
    if (isReservedDeviceName(upperNoExt)) {
        return false;
    }

    return true;
}

bool isSafeWindowsFilename(const std::string& name) {
    std::string copy = name;
    if (!sanitizeWindowsFilenameInPlace(copy)) return false;
    return copy == name;
}

}  // namespace ExoSend
