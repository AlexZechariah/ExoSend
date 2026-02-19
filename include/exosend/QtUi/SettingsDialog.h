/**
 * @file SettingsDialog.h
 * @brief Settings dialog for ExoSend GUI application
 *
 * This class provides a dialog for editing application settings
 * including device name, download path, and displaying device UUID.
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

// Forward declarations
class SettingsManager;

/**
 * @class SettingsDialog
 * @brief Modal dialog for editing application settings
 *
 * This dialog allows users to configure:
 * - Display name (device name shown to other peers)
 * - Download path (where received files are saved)
 * - View device UUID (read-only, informational)
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

private:
    /**
     * @brief Set up the user interface
     *
     * Creates all widgets and layouts for the dialog.
     */
    void setupUi();

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

    // UI Widgets
    QLineEdit* m_displayNameEdit;     ///< Device name edit field
    QLineEdit* m_downloadPathEdit;    ///< Download path edit field
    QLabel* m_uuidLabel;              ///< Device UUID display (read-only)
    QLabel* m_errorLabel;             ///< Validation error message
    QPushButton* m_browseButton;      ///< Browse button for download path
    QDialogButtonBox* m_buttonBox;    ///< Standard dialog buttons
    QCheckBox* m_showCloseWarningCheckBox;  ///< Checkbox for close warning preference
    QSlider* m_peerTimeoutSlider;     ///< Peer timeout slider (1-10 seconds)
    QLabel* m_peerTimeoutValueLabel;  ///< Label showing current timeout value
};

#endif // EXOSEND_QTUI_SETTINGSDIALOG_H
