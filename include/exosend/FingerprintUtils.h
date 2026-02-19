/**
 * @file FingerprintUtils.h
 * @brief Utilities for normalizing and formatting certificate fingerprints.
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <string>

namespace ExoSend {

class FingerprintUtils {
public:
    /**
     * @brief Normalize a SHA-256 fingerprint to canonical form.
     *
     * Canonical form:
     * - 64 hex characters
     * - uppercase
     * - no separators
     *
     * Accepts inputs that may contain ':' separators and whitespace.
     *
     * @return Normalized fingerprint, or empty string on invalid input.
     */
    static std::string normalizeSha256Hex(const std::string& input) {
        std::string out;
        out.reserve(64);

        for (unsigned char uc : input) {
            const char c = static_cast<char>(uc);
            if (c == ':' || std::isspace(uc)) {
                continue;
            }
            out.push_back(c);
        }

        if (out.size() != 64) {
            return {};
        }

        for (char& c : out) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (!std::isxdigit(uc)) {
                return {};
            }
            c = static_cast<char>(std::toupper(uc));
        }

        return out;
    }

    /**
     * @brief Format a canonical fingerprint for display (adds ':' separators).
     *
     * @return Colon-separated fingerprint, or empty string on invalid input.
     */
    static std::string formatForDisplay(const std::string& normalized64Upper) {
        const std::string norm = normalizeSha256Hex(normalized64Upper);
        if (norm.empty()) {
            return {};
        }

        std::string out;
        out.reserve(64 + 31);
        for (size_t i = 0; i < norm.size(); i += 2) {
            out.push_back(norm[i]);
            out.push_back(norm[i + 1]);
            if (i + 2 < norm.size()) {
                out.push_back(':');
            }
        }
        return out;
    }
};

}  // namespace ExoSend

