/**
 * @file SettingsManager.cpp
 * @brief Settings persistence manager implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/SettingsManager.h"
#include "exosend/UuidGenerator.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>
#include <QDateTime>
#include <QDebug>
#include <chrono>
#include <winsock2.h>  // For gethostname

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
    , m_peerTimeout(10)  // Default 10 seconds (matches DiscoveryService PEER_TIMEOUT_MS)
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

int SettingsManager::getPeerTimeout() const
{
    return m_peerTimeout;
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
    QString configPath = getConfigFilePath();
    QFile configFile(configPath);

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
                bool enabled = it.value().get<bool>();
                m_autoAcceptPeers[uuid] = enabled;
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

    // Build JSON object
    json j;
    j["device_uuid"] = m_deviceUuid.toStdString();
    j["display_name"] = m_displayName.toStdString();
    j["download_path"] = m_downloadPath.toStdString();
    j["window_geometry"] = m_windowGeometry.toBase64().toStdString();
    j["show_close_warning"] = m_showCloseWarning;
    j["peer_timeout"] = m_peerTimeout;

    // Save auto-accept preferences
    json autoAcceptObj;
    for (auto it = m_autoAcceptPeers.begin(); it != m_autoAcceptPeers.end(); ++it) {
        autoAcceptObj[it.key().toStdString()] = it.value();
    }
    j["auto_accept_peers"] = autoAcceptObj;

    // Get JSON string
    std::string jsonString = j.dump(4);  // 4-space indentation for readability

    // Write atomically: use temp file then rename
    // Use QTemporaryFile without template string for better Windows compatibility
    QTemporaryFile tempFile;
    tempFile.setAutoRemove(false);

    if (!tempFile.open()) {
        return false;
    }

    // Write JSON data
    qint64 bytesWritten = tempFile.write(jsonString.c_str(), jsonString.length());
    if (bytesWritten != static_cast<qint64>(jsonString.length())) {
        tempFile.close();
        return false;
    }

    // Ensure data is flushed to disk
    tempFile.flush();
    QString tempFilePath = tempFile.fileName();
    tempFile.close();

    // Remove existing config file if it exists
    if (QFile::exists(configPath)) {
        if (!QFile::remove(configPath)) {
            QFile::remove(tempFilePath);  // Clean up temp file
            return false;
        }
    }

    // Copy temp file to config location
    if (!QFile::copy(tempFilePath, configPath)) {
        QFile::remove(tempFilePath);  // Clean up temp file
        return false;
    }

    // Clean up temp file
    QFile::remove(tempFilePath);

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

    // Reset peer timeout to default
    m_peerTimeout = 10;  // Default 10 seconds (matches DiscoveryService PEER_TIMEOUT_MS)
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
