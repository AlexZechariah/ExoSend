/**
 * @file SettingsManager.h
 * @brief Settings persistence manager for ExoSend GUI application
 *
 * This class manages application settings persistence using JSON files.
 * Settings are stored in %APPDATA%\ExoSend\config.json on Windows.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_SETTINGSMANAGER_H
#define EXOSEND_QTUI_SETTINGSMANAGER_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QStandardPaths>
#include <QDir>
#include <QMap>
#include <fstream>
#include <unordered_set>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @class SettingsManager
 * @brief Manages persistent application settings
 *
 * This class handles loading, saving, and managing application settings.
 * Settings are persisted to a JSON file in the user's application data directory.
 *
 * Features:
 * - Automatic UUID generation on first run
 * - JSON-based configuration file
 * - Qt signal/slot integration for change notifications
 * - Thread-safe operations (main thread only)
 *
 * @note All operations should be called from the main (GUI) thread only
 */
class SettingsManager : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param parent Parent QObject (typically nullptr for application-level singleton)
     */
    explicit SettingsManager(QObject* parent = nullptr);

    /**
     * @brief Destructor - saves settings automatically
     */
    ~SettingsManager();

    // ========================================================================
    // Settings Accessors
    // ========================================================================

    /**
     * @brief Get the device UUID
     * @return Unique device identifier (generated once, never changes)
     *
     * The UUID is generated on first run and persisted forever.
     * This uniquely identifies this ExoSend instance on the network.
     */
    QString getDeviceUuid() const;

    /**
     * @brief Get the display name
     * @return Human-readable device name (e.g., "Alex's Surface Pro")
     */
    QString getDisplayName() const;

    /**
     * @brief Get the download directory path
     * @return Full path to where received files are saved
     */
    QString getDownloadPath() const;

    /**
     * @brief Get the main window geometry
     * @return Window geometry data for restoring window state
     */
    QByteArray getWindowGeometry() const;

    /**
     * @brief Get whether to show close warning
     * @return true if warning should be shown when minimizing to tray
     */
    bool getShowCloseWarning() const;

    /**
     * @brief Get the peer timeout in seconds
     * @return Peer timeout value (1-10 seconds, default 3)
     */
    int getPeerTimeout() const;

    /**
     * @brief Get auto-accept status for a specific peer
     * @param peerUuid UUID of the peer
     * @return true if auto-accept is enabled for this peer
     */
    bool getAutoAcceptForPeer(const QString& peerUuid) const;

    /**
     * @brief Set auto-accept status for a specific peer
     * @param peerUuid UUID of the peer
     * @param enabled true to enable auto-accept, false to disable
     *
     * Emits settingsChanged() signal if value actually changes.
     * Settings are auto-saved on change.
     */
    void setAutoAcceptForPeer(const QString& peerUuid, bool enabled);

    /**
     * @brief Get all auto-accept preferences
     * @return Map of peer UUID -> auto-accept enabled
     */
    QMap<QString, bool> getAllAutoAcceptPreferences() const;

    // ========================================================================
    // Settings Mutators
    // ========================================================================

    /**
     * @brief Set the display name
     * @param name New display name
     *
     * Emits displayNameChanged() signal if value actually changes.
     * Settings are auto-saved on change.
     */
    void setDisplayName(const QString& name);

    /**
     * @brief Set the download directory path
     * @param path Full path to download directory
     *
     * Emits downloadPathChanged() signal if value actually changes.
     * Settings are auto-saved on change.
     *
     * @note Caller should verify directory exists/writable before setting
     */
    void setDownloadPath(const QString& path);

    /**
     * @brief Set the main window geometry
     * @param geometry Window geometry from QWidget::saveGeometry()
     *
     * This is called automatically by MainWindow when closing.
     * Settings are auto-saved on change.
     */
    void setWindowGeometry(const QByteArray& geometry);

    /**
     * @brief Set whether to show close warning
     * @param show true to show warning when minimizing to tray
     *
     * Emits settingsChanged() signal if value actually changes.
     * Settings are auto-saved on change.
     */
    void setShowCloseWarning(bool show);

    /**
     * @brief Set the peer timeout in seconds
     * @param seconds Peer timeout value (1-10 seconds)
     *
     * Emits settingsChanged() signal if value actually changes.
     * Settings are auto-saved on change.
     */
    void setPeerTimeout(int seconds);

    // ========================================================================
    // Persistence Operations
    // ========================================================================

    /**
     * @brief Load settings from configuration file
     * @return true if loaded successfully, false otherwise
     *
     * If config file doesn't exist, creates it with defaults.
     * If config file is corrupt, recreates with defaults.
     *
     * This is typically called once at application startup.
     */
    bool loadSettings();

    /**
     * @brief Save current settings to configuration file
     * @return true if saved successfully, false otherwise
     *
     * Creates directory if it doesn't exist.
     * Writes atomically (writes to temp file, then renames).
     *
     * This is called automatically:
     * - On any setting change
     * - On destructor
     */
    bool saveSettings();

    /**
     * @brief Reset all settings to defaults
     *
     * Clears current values and resets to system defaults.
     * Does NOT save - caller must call saveSettings() explicitly.
     */
    void resetToDefaults();

signals:
    /**
     * @brief Emitted when any setting changes
     */
    void settingsChanged();

    /**
     * @brief Emitted when display name changes
     * @param name New display name
     */
    void displayNameChanged(const QString& name);

    /**
     * @brief Emitted when download path changes
     * @param path New download path
     */
    void downloadPathChanged(const QString& path);

private:
    /**
     * @brief Generate a new random UUID v4
     * @return UUID as QString (standard format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
     *
     * Uses crypto-grade random number generation for uniqueness.
     */
    QString generateUuid() const;

    /**
     * @brief Get the configuration file path
     * @return Full path to config.json
     *
     * Returns: %APPDATA%\ExoSend\config.json on Windows
     */
    QString getConfigFilePath() const;

    /**
     * @brief Ensure configuration directory exists
     * @return true if directory exists or was created successfully
     */
    bool ensureConfigDirectory() const;

    // ========================================================================
    // Member Variables
    // ========================================================================

    QString m_deviceUuid;        ///< Unique device identifier (never changes)
    QString m_displayName;       ///< Human-readable device name
    QString m_downloadPath;      ///< Where received files are saved
    QByteArray m_windowGeometry; ///< Main window state
    bool m_showCloseWarning;     ///< Whether to show close-to-tray warning
    int m_peerTimeout;           ///< Peer timeout in seconds (default 3, range 1-10)
    QMap<QString, bool> m_autoAcceptPeers;  ///< Auto-accept preferences by peer UUID
    bool m_settingsLoaded;       ///< True if loadSettings() was called
};

#endif // EXOSEND_QTUI_SETTINGSMANAGER_H
