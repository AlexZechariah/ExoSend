/**
 * @file PairingSecret.cpp
 * @brief PairingSecret implementation.
 */

#include "exosend/PairingSecret.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>

namespace ExoSend {

namespace {

static std::string opensslLastErrorString() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "Unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
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

}  // namespace ExoSend
