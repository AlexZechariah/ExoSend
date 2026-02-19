/**
 * @file trust_store_test.cpp
 * @brief Unit tests for TrustStore pairing and pinning persistence
 */

#include "exosend/TrustStore.h"
#include <gtest/gtest.h>

using namespace ExoSend;

TEST(TrustStoreTest, ValidFingerprintValidation) {
    EXPECT_TRUE(TrustStore::isValidFingerprintSha256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    EXPECT_TRUE(TrustStore::isValidFingerprintSha256Hex("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"));
    EXPECT_FALSE(TrustStore::isValidFingerprintSha256Hex(""));
    EXPECT_FALSE(TrustStore::isValidFingerprintSha256Hex("123"));
    EXPECT_FALSE(TrustStore::isValidFingerprintSha256Hex("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

TEST(TrustStoreTest, PinAndMatch) {
    TrustStore store;
    store.pinPeer("peer-uuid", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Peer", "2026-02-21T00:00:00Z");

    EXPECT_TRUE(store.hasPeer("peer-uuid"));
    EXPECT_TRUE(store.isPinnedFingerprintMatch("peer-uuid", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    EXPECT_FALSE(store.isPinnedFingerprintMatch("peer-uuid", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    EXPECT_FALSE(store.isPinnedFingerprintMatch("unknown", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

TEST(TrustStoreTest, JsonRoundTrip) {
    TrustStore store;
    store.pinPeer("u1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "One", "2026-02-21T01:02:03Z");
    store.pinPeer("u2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Two", "2026-02-21T01:02:03Z");

    const auto j = store.toJson();
    const TrustStore parsed = TrustStore::fromJson(j);

    EXPECT_TRUE(parsed.hasPeer("u1"));
    EXPECT_TRUE(parsed.hasPeer("u2"));
    EXPECT_TRUE(parsed.isPinnedFingerprintMatch("u2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

TEST(TrustStoreTest, FromJsonSkipsInvalidEntries) {
    nlohmann::json j = nlohmann::json::object();
    j["good"]["pinned_fingerprint_sha256"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    j["bad1"]["pinned_fingerprint_sha256"] = "not-hex";
    j["bad2"] = 123;

    TrustStore parsed = TrustStore::fromJson(j);
    EXPECT_TRUE(parsed.hasPeer("good"));
    EXPECT_FALSE(parsed.hasPeer("bad1"));
    EXPECT_FALSE(parsed.hasPeer("bad2"));
}

