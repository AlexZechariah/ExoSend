/**
 * @file IncomingTransferDialog.h
 * @brief Incoming file transfer accept/reject dialog
 *
 * This class provides a professional dialog for users to accept
 * or reject incoming file transfers from other peers.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_INCOMINGTRANSFERDIALOG_H
#define EXOSEND_QTUI_INCOMINGTRANSFERDIALOG_H

#include <QDialog>
#include <QString>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QCheckBox>

/**
 * @class IncomingTransferDialog
 * @brief Modal dialog for accepting/rejecting incoming file transfers
 *
 * This dialog displays information about an incoming file transfer
 * and allows the user to:
 * - View file name, size, and sender information
 * - Choose where to save the file
 * - Accept or reject the transfer
 *
 * Usage:
 * ```cpp
 * IncomingTransferDialog dlg(peerName, filename, fileSize, downloadPath, this);
 * if (dlg.exec() == QDialog::Accepted) {
 *     QString savePath = dlg.getDownloadPath();
 *     // Proceed with transfer
 * }
 * ```
 */
class IncomingTransferDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param peerName Name of the peer sending the file
     * @param peerIp IP address of the peer
     * @param peerUuid UUID of the peer
     * @param filename Name of the file being sent
     * @param fileSize Size of the file in bytes
     * @param defaultPath Default download directory
     * @param parent Parent widget
     */
    explicit IncomingTransferDialog(const QString& peerName,
                                   const QString& peerIp,
                                   const QString& peerUuid,
                                   const QString& filename,
                                   qint64 fileSize,
                                   const QString& defaultPath,
                                   QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~IncomingTransferDialog() override = default;

    /**
     * @brief Get the download path selected by user
     * @return Full path where file will be saved
     */
    QString getDownloadPath() const;

    /**
     * @brief Check if transfer was accepted
     * @return true if user clicked Accept
     *
     * This is equivalent to checking (exec() == QDialog::Accepted)
     */
    bool isAccepted() const { return m_accepted; }

    /**
     * @brief Check if "Always accept" checkbox was checked
     * @return true if user checked "Always accept from this peer"
     */
    bool getAlwaysAcceptChecked() const { return m_alwaysAcceptChecked; }

private slots:
    /**
     * @brief Browse for download directory
     *
     * Opens QFileDialog to select a different save location.
     */
    void onBrowsePath();

    /**
     * @brief Accept the transfer
     *
     * Validates the download path and closes dialog with Accepted result.
     */
    void onAccept();

    /**
     * @brief Reject the transfer
     *
     * Closes dialog with Rejected result without saving.
     */
    void onReject();

    /**
     * @brief Validate the current download path
     *
     * Checks if path exists and is writable.
     * Shows warning message if validation fails.
     */
    void validatePath();

private:
    /**
     * @brief Set up the user interface
     */
    void setupUi();

    /**
     * @brief Format file size for human-readable display
     * @param size File size in bytes
     * @return Formatted string (e.g., "245.8 MB")
     */
    QString formatFileSize(qint64 size) const;

private:
    QString m_peerName;       ///< Name of sender
    QString m_peerIp;         ///< IP address of sender
    QString m_peerUuid;       ///< UUID of sender
    QString m_filename;       ///< File name
    qint64 m_fileSize;        ///< File size in bytes
    bool m_accepted;          ///< true if user accepted
    bool m_alwaysAcceptChecked; ///< State of "Always accept" checkbox

    // UI Widgets
    QLineEdit* m_pathEdit;    ///< Download path edit field
    QLabel* m_infoLabel;      ///< File information label
    QLabel* m_warningLabel;   ///< Warning/security label
    QLabel* m_errorLabel;     ///< Validation error message
    QPushButton* m_browseButton;
    QPushButton* m_acceptButton;   ///< Accept button (for signal disconnection)
    QPushButton* m_rejectButton;   ///< Reject button (for signal disconnection)
    QDialogButtonBox* m_buttonBox;
    QCheckBox* m_alwaysAcceptCheckBox;  ///< "Always accept from this peer" checkbox
};

#endif // EXOSEND_QTUI_INCOMINGTRANSFERDIALOG_H
