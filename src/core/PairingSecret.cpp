/**
 * @file PairingSecret.cpp
 * @brief PairingSecret implementation.
 */

#include "exosend/PairingSecret.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <vector>

namespace ExoSend {

namespace {

constexpr char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static std::string opensslLastErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "Unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

static int crockfordValue(unsigned char c) {
    // Normalize common ambiguous characters.
    if (c >= 'a' && c <= 'z') c = static_cast<unsigned char>(c - 'a' + 'A');
    if (c == 'O') c = '0';
    if (c == 'I' || c == 'L') c = '1';

    if (c >= '0' && c <= '9') return static_cast<int>(c - '0');

    // Alphabet intentionally skips I, L, O, U.
    switch (c) {
        case 'A': return 10;
        case 'B': return 11;
        case 'C': return 12;
        case 'D': return 13;
        case 'E': return 14;
        case 'F': return 15;
        case 'G': return 16;
        case 'H': return 17;
        case 'J': return 18;
        case 'K': return 19;
        case 'M': return 20;
        case 'N': return 21;
        case 'P': return 22;
        case 'Q': return 23;
        case 'R': return 24;
        case 'S': return 25;
        case 'T': return 26;
        case 'V': return 27;
        case 'W': return 28;
        case 'X': return 29;
        case 'Y': return 30;
        case 'Z': return 31;
        default: return -1;
    }
}

static bool isSkippable(unsigned char c) {
    return c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

}  // namespace

bool PairingSecret::generate128(std::array<uint8_t, 16>& out, std::string& errorMsg) {
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        errorMsg = "RAND_bytes failed: " + opensslLastErrorString();
        std::fill(out.begin(), out.end(), 0);
        return false;
    }
    return true;
}

std::string PairingSecret::toBase32Crockford(const std::array<uint8_t, 16>& secret) {
    std::string out;
    out.reserve(26);

    uint32_t buffer = 0;
    int bits = 0;
    for (uint8_t b : secret) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            const int idx = static_cast<int>((buffer >> (bits - 5)) & 0x1Fu);
            out.push_back(kAlphabet[idx]);
            bits -= 5;
        }
    }

    if (bits > 0) {
        const int idx = static_cast<int>((buffer << (5 - bits)) & 0x1Fu);
        out.push_back(kAlphabet[idx]);
    }

    return out;
}

bool PairingSecret::parse128Base32Crockford(const std::string& code,
                                            std::array<uint8_t, 16>& out,
                                            std::string& errorMsg) {
    std::vector<uint8_t> values;
    values.reserve(26);

    for (unsigned char c : code) {
        if (isSkippable(c)) continue;

        const int v = crockfordValue(c);
        if (v < 0 || v > 31) {
            errorMsg = "Invalid Base32 character";
            std::fill(out.begin(), out.end(), 0);
            return false;
        }
        values.push_back(static_cast<uint8_t>(v));
        if (values.size() > 26) {
            errorMsg = "Pairing code is too long";
            std::fill(out.begin(), out.end(), 0);
            return false;
        }
    }

    if (values.size() != 26) {
        errorMsg = "Pairing code has invalid length";
        std::fill(out.begin(), out.end(), 0);
        return false;
    }

    uint32_t buffer = 0;
    int bits = 0;
    size_t outIndex = 0;

    for (uint8_t v : values) {
        buffer = (buffer << 5) | v;
        bits += 5;
        while (bits >= 8) {
            if (outIndex >= out.size()) {
                errorMsg = "Pairing code decodes to too many bytes";
                std::fill(out.begin(), out.end(), 0);
                return false;
            }
            out[outIndex++] = static_cast<uint8_t>((buffer >> (bits - 8)) & 0xFFu);
            bits -= 8;
        }
    }

    if (outIndex != out.size()) {
        errorMsg = "Pairing code decodes to too few bytes";
        std::fill(out.begin(), out.end(), 0);
        return false;
    }

    // For 128-bit secrets, Crockford Base32 uses 26 chars (130 bits) so there
    // are 2 padding bits at the end. Enforce that those are zero.
    if (bits > 0) {
        const uint32_t mask = (1u << bits) - 1u;
        if ((buffer & mask) != 0) {
            errorMsg = "Pairing code padding bits are not zero";
            std::fill(out.begin(), out.end(), 0);
            return false;
        }
    }

    return true;
}

}  // namespace ExoSend

