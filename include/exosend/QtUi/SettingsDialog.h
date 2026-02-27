/**
 * @file SettingsDialog.h
 * @brief Settings dialog for ExoSend GUI application
 *
 * This class provides a dialog for editing application settings
 * including device name, download path, and displaying device UUID.
 * In v0.3.0 a "Trusted Peers" tab was added for viewing and revoking
 * paired peer trust records.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_SETTINGSDIALOG_H
#define EXOSEND_QTUI_SETTINGSDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QCheckBox>
#include <QSlider>
#include <QTabWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>

// Forward declarations
class SettingsManager;

/**
 * @class SettingsDialog
 * @brief Modal dialog for editing application settings
 *
 * Provides two tabs:
 * - General: display name, download path, UUID, preferences
 * - Trusted Peers: list of pinned peers with revoke / clear-all actions
 *
 * Usage:
 * ```cpp
 * SettingsDialog dlg(settingsManager, this);
 * if (dlg.exec() == QDialog::Accepted) {
 *     // Settings already saved
 * }
 * ```
 */
class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param settings Pointer to SettingsManager (not owned)
     * @param parent Parent widget
     *
     * The SettingsManager pointer must remain valid for the lifetime
     * of this dialog. Settings are loaded from and saved to this manager.
     */
    explicit SettingsDialog(SettingsManager* settings, QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~SettingsDialog() override = default;

    /**
     * @brief Whether the user requested a Factory Reset from this dialog.
     *
     * If true, the caller should execute the reset outside the dialog (typically
     * in MainWindow) and restart ExoSend.
     */
    bool factoryResetRequested() const { return m_factoryResetRequested; }

    /**
     * @brief Whether Factory Reset should also attempt to remove Windows Firewall rules.
     *
     * This requires Administrator approval (UAC) and is best-effort.
     */
    bool factoryResetRemoveFirewall() const { return m_factoryResetRemoveFirewall; }

private slots:
    /**
     * @brief Browse for download directory
     *
     * Opens QFileDialog to select a directory.
     * Updates the download path edit field if user selects a folder.
     */
    void onBrowsePath();

    /**
     * @brief Save settings and close dialog
     *
     * Validates inputs and saves to SettingsManager.
     * Shows error message if validation fails.
     * Closes dialog with Accepted result if save succeeds.
     */
    void onSave();

    /**
     * @brief Validate the download path
     *
     * Checks if the current download path exists and is writable.
     * Displays error message if validation fails.
     */
    void validatePath();

    /**
     * @brief Revert changes and close dialog
     *
     * Reloads original settings from SettingsManager
     * and closes dialog with Rejected result.
     */
    void onReject();

    /**
     * @brief Request a factory reset (settings + trust) and restart ExoSend.
     */
    void onFactoryReset();

    // ========================================================================
    // Trusted Peers tab slots (v0.3.0)
    // ========================================================================

    /**
     * @brief Revoke trust for the selected peer in the Trusted Peers list.
     *
     * Shows a confirmation before removing the peer from the trust store.
     * Refreshes the list on success.
     */
    void onRevokePeer();

    /**
     * @brief Remove all pinned peers from the trust store.
     *
     * Shows a confirmation before clearing the entire trust store.
     * Refreshes the list on success.
     */
    void onClearAllPeers();

    /**
     * @brief Repopulate the Trusted Peers list from the current trust store.
     */
    void refreshTrustedPeersList();

private:
    /**
     * @brief Set up the user interface (tabbed layout)
     */
    void setupUi();

    /**
     * @brief Build the General settings tab widget
     */
    QWidget* buildGeneralTab();

    /**
     * @brief Build the Trusted Peers management tab widget
     */
    QWidget* buildTrustedPeersTab();

    /**
     * @brief Load settings from SettingsManager into UI fields
     */
    void loadSettings();

    /**
     * @brief Check if display name is valid
     * @return true if name is not empty
     */
    bool isDisplayNameValid() const;

    /**
     * @brief Check if download path is valid
     * @return true if path exists and is writable
     */
    bool isDownloadPathValid() const;

private:
    SettingsManager* m_settings;      ///< Settings manager (not owned)

    bool m_factoryResetRequested{false};
    bool m_factoryResetRemoveFirewall{false};

    // ========================================================================
    // General tab widgets
    // ========================================================================
    QLineEdit* m_displayNameEdit;     ///< Device name edit field
    QLineEdit* m_downloadPathEdit;    ///< Download path edit field
    QLabel* m_uuidLabel;              ///< Device UUID display (read-only)
    QLabel* m_errorLabel;             ///< Validation error message
    QPushButton* m_browseButton;      ///< Browse button for download path
    QDialogButtonBox* m_buttonBox;    ///< Standard dialog buttons
    QCheckBox* m_showCloseWarningCheckBox;  ///< Checkbox for close warning preference
    QCheckBox* m_enableCrashDumpsCheckBox;  ///< Checkbox for crash dump writing (privacy)
    QSlider* m_peerTimeoutSlider;     ///< Peer timeout slider (unused, kept for compat)
    QLabel* m_peerTimeoutValueLabel;  ///< Label showing current timeout value (unused)
    QPushButton* m_factoryResetButton{nullptr}; ///< Button for factory reset UX

    // ========================================================================
    // Trusted Peers tab widgets (v0.3.0)
    // ========================================================================
    QListWidget* m_trustedPeersList{nullptr};     ///< List of pinned peers
    QPushButton* m_revokePeerButton{nullptr};     ///< Revoke selected peer
    QPushButton* m_clearAllPeersButton{nullptr};  ///< Clear all pairs
};

#endif // EXOSEND_QTUI_SETTINGSDIALOG_H
