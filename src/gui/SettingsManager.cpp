/**
 * @file SettingsManager.cpp
 * @brief Settings persistence manager implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/SettingsManager.h"
#include "exosend/FingerprintUtils.h"
#include "exosend/UuidGenerator.h"
#include "exosend/ProtectedBlob.h"
#include "exosend/ThreadSafeLog.h"
#include "exosend/TrustStoreDpapi.h"
#include "exosend/WindowsAcl.h"
#include "exosend/AppPaths.h"
#include "exosend/MigrationUtils.h"
#include "exosend/config.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QDateTime>
#include <QDebug>
#include <chrono>
#include <vector>
#include <filesystem>
#include <winsock2.h>  // For gethostname

// ========================================================================
// Anonymous namespace: Windows security helpers
// ========================================================================

namespace {

static std::string readExistingTrustStoreDpapiBase64(const QString& configPath)
{
    QFile f(configPath);
    if (!f.exists()) {
        return {};
    }
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    const QByteArray data = f.readAll();
    f.close();

    json j = json::parse(data.constData(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return {};
    }

    if (j.contains("trust_store_dpapi") && j["trust_store_dpapi"].is_string()) {
        return j["trust_store_dpapi"].get<std::string>();
    }

    return {};
}

} // anonymous namespace

// ========================================================================
// Constructor / Destructor
// ========================================================================

SettingsManager::SettingsManager(QObject* parent)
    : QObject(parent)
    , m_deviceUuid()
    , m_displayName()
    , m_downloadPath()
    , m_windowGeometry()
    , m_showCloseWarning(true)
    , m_enableCrashDumps(true)
    , m_peerTimeout(10)  // Default 10 seconds (matches DiscoveryService PEER_TIMEOUT_MS)
    , m_trustStore()
    , m_maxIncomingSizeBytes(ExoSend::DEFAULT_MAX_INCOMING_SIZE_BYTES)
    , m_settingsLoaded(false)
{
    // Set initial defaults (will be overridden by loadSettings())
    resetToDefaults();
}

SettingsManager::~SettingsManager()
{
    // Auto-save on destruction if settings were loaded
    if (m_settingsLoaded) {
        saveSettings();
    }
}

// ========================================================================
// Settings Accessors
// ========================================================================

QString SettingsManager::getDeviceUuid() const
{
    return m_deviceUuid;
}

QString SettingsManager::getDisplayName() const
{
    return m_displayName;
}

QString SettingsManager::getDownloadPath() const
{
    return m_downloadPath;
}

QByteArray SettingsManager::getWindowGeometry() const
{
    return m_windowGeometry;
}

bool SettingsManager::getShowCloseWarning() const
{
    return m_showCloseWarning;
}

bool SettingsManager::getEnableCrashDumps() const
{
    return m_enableCrashDumps;
}

int SettingsManager::getPeerTimeout() const
{
    return m_peerTimeout;
}

uint64_t SettingsManager::getMaxIncomingSizeBytes() const
{
    return m_maxIncomingSizeBytes;
}

// ========================================================================
// Settings Mutators
// ========================================================================

void SettingsManager::setDisplayName(const QString& name)
{
    if (m_displayName != name) {
        m_displayName = name;
        emit displayNameChanged(name);
        emit settingsChanged();
        saveSettings();
    }
}

void SettingsManager::setDownloadPath(const QString& path)
{
    if (m_downloadPath != path) {
        m_downloadPath = path;
        emit downloadPathChanged(path);
        emit settingsChanged();
        saveSettings();
    }
}

void SettingsManager::setWindowGeometry(const QByteArray& geometry)
{
    if (m_windowGeometry != geometry) {
        m_windowGeometry = geometry;
        saveSettings();
    }
}

void SettingsManager::setShowCloseWarning(bool show)
{
    if (m_showCloseWarning != show) {
        m_showCloseWarning = show;
        emit settingsChanged();
        saveSettings();
    }
}

void SettingsManager::setEnableCrashDumps(bool enabled)
{
    if (m_enableCrashDumps != enabled) {
        m_enableCrashDumps = enabled;
        emit settingsChanged();
        saveSettings();
    }
}

void SettingsManager::setPeerTimeout(int seconds)
{
    // Clamp to valid range (1-10)
    if (seconds < 1) seconds = 1;
    if (seconds > 10) seconds = 10;

    if (m_peerTimeout != seconds) {
        m_peerTimeout = seconds;
        emit settingsChanged();
        saveSettings();
    }
}

void SettingsManager::setMaxIncomingSizeBytes(uint64_t bytes)
{
    if (bytes == 0) {
        bytes = ExoSend::DEFAULT_MAX_INCOMING_SIZE_BYTES;
    }

    if (m_maxIncomingSizeBytes != bytes) {
        m_maxIncomingSizeBytes = bytes;
        emit settingsChanged();
        saveSettings();
    }
}

bool SettingsManager::isPeerPinned(const QString& peerUuid) const
{
    return m_trustStore.hasPeer(peerUuid.toStdString());
}

QString SettingsManager::getPinnedFingerprint(const QString& peerUuid) const
{
    const auto* rec = m_trustStore.getPeer(peerUuid.toStdString());
    if (!rec) {
        return {};
    }
    return QString::fromStdString(rec->pinnedFingerprintSha256Hex);
}

void SettingsManager::pinPeerFingerprint(const QString& peerUuid,
                                         const QString& fingerprintSha256Hex,
                                         const QString& displayName)
{
    const std::string fp = ExoSend::FingerprintUtils::normalizeSha256Hex(fingerprintSha256Hex.toStdString());
    if (fp.empty() || !ExoSend::TrustStore::isValidFingerprintSha256Hex(fp)) {
        return;
    }

    const std::string now = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    m_trustStore.pinPeer(peerUuid.toStdString(), fp, displayName.toStdString(), now);
    emit settingsChanged();
    saveSettings();
}

void SettingsManager::updatePeerSeen(const QString& peerUuid, const QString& displayName)
{
    const std::string now = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs).toStdString();
    m_trustStore.updateSeen(peerUuid.toStdString(), displayName.toStdString(), now);
    emit settingsChanged();
    saveSettings();
}

bool SettingsManager::revokePeer(const QString& peerUuid)
{
    bool removed = m_trustStore.revokePeer(peerUuid.toStdString());
    if (removed) {
        emit settingsChanged();
        saveSettings();
    }
    return removed;
}

void SettingsManager::clearAllPeers()
{
    m_trustStore.clear();
    emit settingsChanged();
    saveSettings();
}

bool SettingsManager::factoryResetKeepIdentity()
{
    // Keep the device UUID stable. (Identity reset is an uninstall-only behavior.)
    resetToDefaults();

    // Clear pairing/pinning trust records.
    m_trustStore.clear();

    // Clear per-peer preferences.
    m_autoAcceptPeers.clear();

    emit settingsChanged();
    return saveSettings();
}

ExoSend::TrustStore::Map SettingsManager::getTrustedPeers() const
{
    return m_trustStore.records();
}

bool SettingsManager::getAutoAcceptForPeer(const QString& peerUuid) const
{
    return m_autoAcceptPeers.value(peerUuid, false);
}

void SettingsManager::setAutoAcceptForPeer(const QString& peerUuid, bool enabled)
{
    bool current = m_autoAcceptPeers.value(peerUuid, false);
    if (current != enabled) {
        m_autoAcceptPeers[peerUuid] = enabled;
        emit settingsChanged();
        saveSettings();
    }
}

QMap<QString, bool> SettingsManager::getAllAutoAcceptPreferences() const
{
    return m_autoAcceptPeers;
}

// ========================================================================
// Persistence Operations
// ========================================================================

bool SettingsManager::loadSettings()
{
    const QString configPath = getConfigFilePath();
    QFile configFile(configPath);

#ifdef _WIN32
    // One-time migration: if the canonical config.json is missing, attempt to migrate
    // from the legacy Qt-derived path (%LOCALAPPDATA%\ExoSend\ExoSend\config.json).
    // Skip migration when EXOSEND_CONFIG_DIR is set to avoid surprising dev/test overrides.
    const QString overrideDir = qEnvironmentVariable("EXOSEND_CONFIG_DIR").trimmed();
    if (overrideDir.isEmpty()) {
        const auto legacy = ExoSend::AppPaths::legacyQtAppLocalConfigJsonPath();
        if (!legacy.empty()) {
            const std::filesystem::path dest = ExoSend::AppPaths::configJsonPath();
            const auto r = ExoSend::MigrationUtils::migrateFileIfDestMissing(dest, legacy);
            if (!r.ok) {
                ExoSend::ThreadSafeLog::log(
                    "SETTINGS_MIGRATE_WARN: failed to migrate legacy config.json: " + r.error);
            } else if (r.migrated) {
                ExoSend::ThreadSafeLog::log(
                    "SETTINGS_MIGRATE: migrated config.json to canonical path");

                std::wstring aclErr;
                (void)ExoSend::restrictPathToCurrentUser(dest.wstring(), &aclErr);
            }
        }
    }
#endif

    // Check if config file exists
    if (!configFile.exists()) {
        // First run - generate UUID and save defaults
        m_deviceUuid = generateUuid();
        m_settingsLoaded = true;
        return saveSettings();
    }

    // Open and parse config file
    if (!configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        // Can't open file - use defaults and generate new UUID
        m_deviceUuid = generateUuid();
        m_settingsLoaded = true;
        return saveSettings();
    }

    try {
        // Read entire file
        QByteArray data = configFile.readAll();
        configFile.close();

        // Parse JSON
        json j = json::parse(data.constData(), nullptr, false);

        // Check for parse errors
        if (j.is_discarded()) {
            // Invalid JSON - recreate with defaults
            m_deviceUuid = generateUuid();
            m_settingsLoaded = true;
            return saveSettings();
        }

        // Load values from JSON
        if (j.contains("device_uuid") && j["device_uuid"].is_string()) {
            m_deviceUuid = QString::fromStdString(j["device_uuid"].get<std::string>());
        } else {
            // UUID missing - generate new one
            m_deviceUuid = generateUuid();
        }

        if (j.contains("display_name") && j["display_name"].is_string()) {
            m_displayName = QString::fromStdString(j["display_name"].get<std::string>());
        }

        if (j.contains("download_path") && j["download_path"].is_string()) {
            m_downloadPath = QString::fromStdString(j["download_path"].get<std::string>());
        }

        if (j.contains("window_geometry") && j["window_geometry"].is_string()) {
            std::string geomStr = j["window_geometry"].get<std::string>();
            m_windowGeometry = QByteArray::fromBase64(QByteArray::fromStdString(geomStr));
        }

        if (j.contains("show_close_warning") && j["show_close_warning"].is_boolean()) {
            m_showCloseWarning = j["show_close_warning"].get<bool>();
        } else {
            m_showCloseWarning = true;  // Default to true for first-time users
        }

        if (j.contains("enable_crash_dumps") && j["enable_crash_dumps"].is_boolean()) {
            m_enableCrashDumps = j["enable_crash_dumps"].get<bool>();
        } else {
            m_enableCrashDumps = true;
        }

        if (j.contains("peer_timeout") && j["peer_timeout"].is_number_integer()) {
            int timeout = j["peer_timeout"].get<int>();
            // Clamp to valid range
            if (timeout < 1) timeout = 1;
            if (timeout > 10) timeout = 10;
            m_peerTimeout = timeout;
        }

        // Load auto-accept preferences
        if (j.contains("auto_accept_peers") && j["auto_accept_peers"].is_object()) {
            m_autoAcceptPeers.clear();
            auto peersObj = j["auto_accept_peers"];
            for (auto it = peersObj.begin(); it != peersObj.end(); ++it) {
                QString uuid = QString::fromStdString(it.key());
                if (it.value().is_boolean()) {
                    m_autoAcceptPeers[uuid] = it.value().get<bool>();
                }
            }
        }

        // Load trust store (DPAPI-encrypted blob preferred; plaintext fallback for v0.2 migration)
        if (j.contains("trust_store_dpapi") && j["trust_store_dpapi"].is_string()) {
            const std::string b64 = j["trust_store_dpapi"].get<std::string>();
            const auto ciphertext = ExoSend::ProtectedBlob::fromBase64(b64);
            std::string decryptError;
            const std::string plaintext = ExoSend::ProtectedBlob::unprotect(ciphertext, decryptError);
            if (!plaintext.empty()) {
                try {
                    const auto jTrust = nlohmann::json::parse(plaintext);
                    m_trustStore = ExoSend::TrustStore::fromJson(jTrust);
                } catch (...) {
                    // Corrupted or tampered blob: start with empty trust store
                    ExoSend::ThreadSafeLog::log(
                        "TRUST_LOAD_ERROR: DPAPI blob parsed but JSON invalid; starting empty");
                    m_trustStore = ExoSend::TrustStore{};
                }
            } else {
                // DPAPI failed (different user profile, re-image, etc.)
                ExoSend::ThreadSafeLog::log(
                    "TRUST_LOAD_ERROR: DPAPI decrypt failed (" + decryptError +
                    "); trust store starting empty");
                m_trustStore = ExoSend::TrustStore{};
            }
        } else if (j.contains("trust_store") && j["trust_store"].is_object()) {
            // v0.2.0 migration path: import plaintext trust store once.
            // saveSettings() will re-save it as a DPAPI blob and drop this key.
            m_trustStore = ExoSend::TrustStore::fromJson(j["trust_store"]);
            ExoSend::ThreadSafeLog::log(
                "TRUST_MIGRATE: imported plaintext trust_store from v0.2; "
                "will be re-saved as DPAPI blob");
        }

        // Load max incoming size
        if (j.contains("max_incoming_size_bytes") && j["max_incoming_size_bytes"].is_number_unsigned()) {
            m_maxIncomingSizeBytes = j["max_incoming_size_bytes"].get<uint64_t>();
        } else if (j.contains("max_incoming_size_bytes") && j["max_incoming_size_bytes"].is_number_integer()) {
            const int64_t v = j["max_incoming_size_bytes"].get<int64_t>();
            if (v > 0) {
                m_maxIncomingSizeBytes = static_cast<uint64_t>(v);
            }
        }

        m_settingsLoaded = true;
        return true;

    } catch (const json::exception& e) {
        // JSON parse error - recreate with defaults
        m_deviceUuid = generateUuid();
        m_settingsLoaded = true;
        return saveSettings();
    }
}

bool SettingsManager::saveSettings()
{
    QString configPath = getConfigFilePath();

    // Ensure directory exists
    if (!ensureConfigDirectory()) {
        return false;
    }

    const std::string existingTrustStoreDpapiBase64 =
        readExistingTrustStoreDpapiBase64(configPath);

    // Build JSON object
    json j;
    j["device_uuid"] = m_deviceUuid.toStdString();
    j["display_name"] = m_displayName.toStdString();
    j["download_path"] = m_downloadPath.toStdString();
    j["window_geometry"] = m_windowGeometry.toBase64().toStdString();
    j["show_close_warning"] = m_showCloseWarning;
    j["enable_crash_dumps"] = m_enableCrashDumps;
    j["peer_timeout"] = m_peerTimeout;
    j["max_incoming_size_bytes"] = m_maxIncomingSizeBytes;

    // Save auto-accept preferences
    json autoAcceptObj;
    for (auto it = m_autoAcceptPeers.begin(); it != m_autoAcceptPeers.end(); ++it) {
        autoAcceptObj[it.key().toStdString()] = it.value();
    }
    j["auto_accept_peers"] = autoAcceptObj;

    // Save trust store encrypted with DPAPI (user-scoped, v0.3+)
    // The plaintext "trust_store" key from v0.2 is deliberately omitted here;
    // it will disappear from the file on the next save after migration.
    j["settings_version"] = "0.3";
    {
        const std::string trustJson = m_trustStore.toJson().dump();
        const bool trustStoreEmpty = m_trustStore.records().empty();

        const auto r = ExoSend::protectTrustStoreJsonToBase64(
            trustJson,
            existingTrustStoreDpapiBase64,
            [](const std::string& plaintext, std::string& errorMsg) -> std::vector<uint8_t> {
                return ExoSend::ProtectedBlob::protect(plaintext, errorMsg);
            }
        );

        if (r.ok) {
            j["trust_store_dpapi"] = r.trustStoreDpapiBase64;
            if (r.usedExisting) {
                ExoSend::ThreadSafeLog::log(
                    "TRUST_SAVE_ERROR: DPAPI protect failed (" + r.error +
                    "); preserving existing trust store on disk");
            }
        } else {
            // Fail closed: never write pinned fingerprints in plaintext.
            // If we cannot protect AND we have no existing encrypted trust store,
            // refuse to overwrite the settings file when the trust store is non-empty.
            if (!existingTrustStoreDpapiBase64.empty()) {
                j["trust_store_dpapi"] = existingTrustStoreDpapiBase64;
                ExoSend::ThreadSafeLog::log(
                    "TRUST_SAVE_ERROR: DPAPI protect failed (" + r.error +
                    "); preserving existing trust store on disk");
            } else if (!trustStoreEmpty) {
                ExoSend::ThreadSafeLog::log(
                    "TRUST_SAVE_ERROR: DPAPI protect failed (" + r.error +
                    "); refusing to write plaintext trust store");
                return false;
            }
        }
    }

    // Get JSON string
    std::string jsonString = j.dump(4);  // 4-space indentation for readability

    // Write atomically (same directory, durable rename semantics).
    // QSaveFile writes to a temp file in the destination directory and commits via rename.
    QSaveFile out(configPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return false;
    }

    const qint64 bytesWritten = out.write(jsonString.c_str(), jsonString.length());
    if (bytesWritten != static_cast<qint64>(jsonString.length())) {
        return false;
    }

    if (!out.commit()) {
        return false;
    }

    // Restrict config file ACL to the current Windows user (defense-in-depth).
    // Failure is non-fatal: the file is written correctly regardless.
#ifdef _WIN32
    std::wstring aclErr;
    if (!ExoSend::restrictPathToCurrentUser(configPath.toStdWString(), &aclErr)) {
        ExoSend::ThreadSafeLog::log(
            "SETTINGS_ACL_WARN: failed to restrict config.json ACL: " +
            std::string(aclErr.begin(), aclErr.end()));
    }
#endif

    return true;
}

void SettingsManager::resetToDefaults()
{
    // Note: We don't reset UUID - that should persist forever
    // But if m_settingsLoaded is false, we'll generate one on load

    // Get system hostname as default display name
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        m_displayName = QString::fromUtf8(hostname);
    } else {
        m_displayName = "ExoSend Device";
    }

    // Default download path: user's Downloads folder
    m_downloadPath = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (m_downloadPath.isEmpty()) {
        m_downloadPath = QDir::homePath() + "/Downloads";
    }

    m_windowGeometry.clear();

    // Crash dumps enabled by default (privacy control).
    m_enableCrashDumps = true;

    // Reset peer timeout to default
    m_peerTimeout = 10;  // Default 10 seconds (matches DiscoveryService PEER_TIMEOUT_MS)

    // Default max incoming size
    m_maxIncomingSizeBytes = ExoSend::DEFAULT_MAX_INCOMING_SIZE_BYTES;
}

// ========================================================================
// Private Methods
// ========================================================================

QString SettingsManager::generateUuid() const
{
    // Delegate to centralized UUID generator
    return QString::fromStdString(ExoSend::UuidGenerator::generate());
}

QString SettingsManager::getConfigFilePath() const
{
    // Developer/test override.
    const QString overrideDir = qEnvironmentVariable("EXOSEND_CONFIG_DIR").trimmed();
    if (!overrideDir.isEmpty()) {
        if (overrideDir.endsWith(".json", Qt::CaseInsensitive)) {
            return overrideDir;
        }
        return QDir(overrideDir).filePath("config.json");
    }

#ifdef _WIN32
    const auto p = ExoSend::AppPaths::configJsonPath();
    if (!p.empty()) {
        return QString::fromStdWString(p.wstring());
    }
#endif

    // Non-Windows fallback: keep Qt behavior for portability.
    QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (configDir.isEmpty()) {
        configDir = QDir::homePath() + "/.config/ExoSend";
    }
    return configDir + "/config.json";
}

bool SettingsManager::ensureConfigDirectory() const
{
    QString configPath = getConfigFilePath();
    QFileInfo fileInfo(configPath);
    QDir dir = fileInfo.dir();

    if (!dir.exists()) {
        return dir.mkpath(".");
    }
    return true;
}
