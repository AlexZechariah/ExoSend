/**
 * @file settings_factory_reset_test.cpp
 * @brief Tests for SettingsManager factory reset behavior (keep identity).
 */

#include "exosend/QtUi/SettingsManager.h"

#include <QCoreApplication>
#include <QTemporaryDir>

#include <gtest/gtest.h>

#include <string>

namespace {

class EnvVarGuard {
public:
    EnvVarGuard(const char* name, const QByteArray& value) : m_name(name) {
        m_had = qEnvironmentVariableIsSet(m_name.c_str());
        if (m_had) {
            m_prev = qgetenv(m_name.c_str());
        }
        qputenv(m_name.c_str(), value);
    }

    ~EnvVarGuard() {
        if (m_had) {
            qputenv(m_name.c_str(), m_prev);
        } else {
            qunsetenv(m_name.c_str());
        }
    }

private:
    std::string m_name;
    bool m_had{false};
    QByteArray m_prev;
};

std::string makeValidFingerprintSha256Hex()
{
    // 64 hex chars (uppercase), valid canonical fingerprint form.
    return "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
}

}  // namespace

TEST(SettingsFactoryResetTest, FactoryResetKeepIdentity_ClearsTrustAndAutoAccept)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());

    EnvVarGuard cfg("EXOSEND_CONFIG_DIR", dir.path().toUtf8());

    SettingsManager mgr;
    ASSERT_TRUE(mgr.loadSettings());

    const QString uuidBefore = mgr.getDeviceUuid();
    ASSERT_FALSE(uuidBefore.trimmed().isEmpty());

    mgr.setDisplayName("Not Default");
    mgr.setEnableCrashDumps(false);
    mgr.setAutoAcceptForPeer("peer-uuid", true);
    mgr.pinPeerFingerprint(
        "peer-uuid",
        QString::fromStdString(makeValidFingerprintSha256Hex()),
        "Peer");

    ASSERT_FALSE(mgr.getTrustedPeers().empty());
    ASSERT_TRUE(mgr.getAutoAcceptForPeer("peer-uuid"));
    ASSERT_EQ(mgr.getDisplayName(), "Not Default");
    ASSERT_FALSE(mgr.getEnableCrashDumps());

    // New API; should keep UUID but clear trust + auto-accept + reset general settings.
    ASSERT_TRUE(mgr.factoryResetKeepIdentity());

    EXPECT_EQ(mgr.getDeviceUuid(), uuidBefore);
    EXPECT_TRUE(mgr.getTrustedPeers().empty());
    EXPECT_FALSE(mgr.getAutoAcceptForPeer("peer-uuid"));
    EXPECT_NE(mgr.getDisplayName(), "Not Default");
    EXPECT_TRUE(mgr.getEnableCrashDumps());
}

TEST(SettingsFactoryResetTest, FactoryResetKeepIdentity_PersistsToDisk)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());

    EnvVarGuard cfg("EXOSEND_CONFIG_DIR", dir.path().toUtf8());

    SettingsManager mgr;
    ASSERT_TRUE(mgr.loadSettings());

    const QString uuidBefore = mgr.getDeviceUuid();
    ASSERT_FALSE(uuidBefore.trimmed().isEmpty());

    mgr.setAutoAcceptForPeer("peer-uuid", true);
    mgr.pinPeerFingerprint(
        "peer-uuid",
        QString::fromStdString(makeValidFingerprintSha256Hex()),
        "Peer");

    ASSERT_FALSE(mgr.getTrustedPeers().empty());
    ASSERT_TRUE(mgr.getAutoAcceptForPeer("peer-uuid"));

    ASSERT_TRUE(mgr.factoryResetKeepIdentity());

    SettingsManager mgr2;
    ASSERT_TRUE(mgr2.loadSettings());

    EXPECT_EQ(mgr2.getDeviceUuid(), uuidBefore);
    EXPECT_TRUE(mgr2.getTrustedPeers().empty());
    EXPECT_FALSE(mgr2.getAutoAcceptForPeer("peer-uuid"));
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

