/**
 * @file CloseWarningDialog.h
 * @brief Dialog shown when user closes main window
 *
 * This dialog informs the user that the application minimizes to the
 * system tray instead of closing, and provides a checkbox option to
 * disable future warnings.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_CLOSEWARNINGDIALOG_H
#define EXOSEND_QTUI_CLOSEWARNINGDIALOG_H

#include <QDialog>
#include <QCheckBox>
#include <QPushButton>

/**
 * @class CloseWarningDialog
 * @brief Custom dialog for close warning with "Do not show again" checkbox
 *
 * This dialog is shown when the user attempts to close the main window
 * while the system tray icon is visible. It explains that the application
 * will continue running in the background and provides a checkbox to
 * disable future warnings.
 */
class CloseWarningDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param parent Parent widget (typically MainWindow)
     */
    explicit CloseWarningDialog(QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~CloseWarningDialog() override = default;

    /**
     * @brief Check if "Do not show this again" checkbox is checked
     * @return true if checkbox is checked, false otherwise
     */
    bool isDoNotShowAgainChecked() const;

private slots:
    /**
     * @brief Handle OK button click
     *
     * Accepts the dialog, allowing the caller to retrieve the
     * checkbox state via isDoNotShowAgainChecked().
     */
    void onOk();

private:
    /**
     * @brief Set up the user interface
     *
     * Creates all widgets and layouts for the dialog.
     * Matches QMessageBox Information style with custom checkbox.
     */
    void setupUi();

private:
    QCheckBox* m_doNotShowAgainCheckBox;  ///< "Do not show this again" checkbox
    QPushButton* m_okButton;              ///< OK button
};

#endif // EXOSEND_QTUI_CLOSEWARNINGDIALOG_H
