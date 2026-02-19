/**
 * @file CloseWarningDialog.cpp
 * @brief Close warning dialog implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/CloseWarningDialog.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStyle>

// ========================================================================
// Constructor / Destructor
// ========================================================================

/**
 * @brief Constructor
 *
 * Initializes the dialog and sets up all UI elements.
 */
CloseWarningDialog::CloseWarningDialog(QWidget* parent)
    : QDialog(parent)
    , m_doNotShowAgainCheckBox(nullptr)
    , m_okButton(nullptr)
{
    setupUi();
}

// ========================================================================
// Public Methods
// ========================================================================

/**
 * @brief Get the state of the "Do not show this again" checkbox
 * @return true if checkbox is checked, false otherwise
 *
 * This method should be called after the dialog is accepted
 * to determine whether the user wants to disable future warnings.
 */
bool CloseWarningDialog::isDoNotShowAgainChecked() const
{
    if (m_doNotShowAgainCheckBox) {
        return m_doNotShowAgainCheckBox->isChecked();
    }
    return false;
}

// ========================================================================
// Private Slots
// ========================================================================

/**
 * @brief Handle OK button click
 *
 * Accepts the dialog with QDialog::Accepted return value.
 * The caller can then check isDoNotShowAgainChecked() to get
 * the checkbox state.
 */
void CloseWarningDialog::onOk()
{
    accept();
}

// ========================================================================
// Private Methods
// ========================================================================

/**
 * @brief Set up the user interface
 *
 * Creates all widgets and layouts for the dialog:
 * - Information icon (standard Qt SP_MessageBoxInformation)
 * - Main text label (bold)
 * - Informative text label
 * - "Do not show this again" checkbox (unchecked by default)
 * - OK button (right-aligned)
 *
 * The layout mimics QMessageBox::Information style
 * but adds the custom checkbox functionality.
 */
void CloseWarningDialog::setupUi()
{
    setWindowTitle("ExoSend - Minimize to Tray");
    setMinimumWidth(400);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    QHBoxLayout* contentLayout = new QHBoxLayout();
    contentLayout->setSpacing(12);

    // Information icon (same as QMessageBox::Information)
    QLabel* iconLabel = new QLabel();
    QPixmap iconPixmap = style()->standardIcon(QStyle::SP_MessageBoxInformation).pixmap(48, 48);
    iconLabel->setPixmap(iconPixmap);
    contentLayout->addWidget(iconLabel);

    // Text layout
    QVBoxLayout* textLayout = new QVBoxLayout();
    textLayout->setSpacing(8);

    // Main text
    QLabel* mainTextLabel = new QLabel("ExoSend will continue running in the background.");
    QFont mainTextFont = mainTextLabel->font();
    mainTextFont.setBold(true);
    mainTextLabel->setFont(mainTextFont);
    mainTextLabel->setWordWrap(true);
    textLayout->addWidget(mainTextLabel);

    // Informative text
    QLabel* infoTextLabel = new QLabel(
        "You can find ExoSend in your system tray (bottom-right corner).\n\n"
        "Right-click the tray icon and select 'Quit' to exit the application."
    );
    infoTextLabel->setWordWrap(true);
    infoTextLabel->setStyleSheet("color: #555555;");
    textLayout->addWidget(infoTextLabel);

    contentLayout->addLayout(textLayout);
    mainLayout->addLayout(contentLayout);

    // Spacer
    mainLayout->addSpacing(10);

    // "Do not show this again" checkbox
    m_doNotShowAgainCheckBox = new QCheckBox("Do not show this again");
    m_doNotShowAgainCheckBox->setChecked(false);
    mainLayout->addWidget(m_doNotShowAgainCheckBox);

    // Spacer
    mainLayout->addSpacing(10);

    // Button layout
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();  // Push button to right

    // OK button
    m_okButton = new QPushButton("OK");
    m_okButton->setMinimumWidth(80);
    m_okButton->setDefault(true);
    buttonLayout->addWidget(m_okButton);

    mainLayout->addLayout(buttonLayout);

    // Connect signals
    connect(m_okButton, &QPushButton::clicked, this, &CloseWarningDialog::onOk);
}
