/**
 * @file SettingsDialog.cpp
 * @brief Settings dialog implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/SettingsDialog.h"
#include "exosend/QtUi/SettingsManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>

// ========================================================================
// Constructor / Destructor
// ========================================================================

SettingsDialog::SettingsDialog(SettingsManager* settings, QWidget* parent)
    : QDialog(parent)
    , m_settings(settings)
    , m_displayNameEdit(nullptr)
    , m_downloadPathEdit(nullptr)
    , m_uuidLabel(nullptr)
    , m_errorLabel(nullptr)
    , m_browseButton(nullptr)
    , m_buttonBox(nullptr)
    , m_showCloseWarningCheckBox(nullptr)
    , m_peerTimeoutSlider(nullptr)
    , m_peerTimeoutValueLabel(nullptr)
{
    setupUi();
    loadSettings();

    setWindowTitle("ExoSend Settings");
    setMinimumWidth(450);
}

// ========================================================================
// Private Slots
// ========================================================================

void SettingsDialog::onBrowsePath()
{
    QString currentPath = m_downloadPathEdit->text();

    // Open directory selection dialog
    QString newPath = QFileDialog::getExistingDirectory(
        this,
        "Select Download Folder",
        currentPath
    );

    if (!newPath.isEmpty()) {
        m_downloadPathEdit->setText(newPath);
        validatePath();
    }
}

void SettingsDialog::onSave()
{
    // Validate all inputs
    if (!isDisplayNameValid()) {
        m_errorLabel->setText("Error: Display name cannot be empty");
        return;
    }

    if (!isDownloadPathValid()) {
        m_errorLabel->setText("Error: Download path does not exist or is not writable");
        return;
    }

    // Save settings
    m_settings->setDisplayName(m_displayNameEdit->text());
    m_settings->setDownloadPath(m_downloadPathEdit->text());
    m_settings->setShowCloseWarning(m_showCloseWarningCheckBox->isChecked());
    // Peer timeout is fixed at 10 seconds - no need to save
    // m_settings->setPeerTimeout(m_peerTimeoutSlider->value());

    m_errorLabel->clear();
    accept();
}

void SettingsDialog::validatePath()
{
    if (isDownloadPathValid()) {
        m_errorLabel->clear();
    } else {
        m_errorLabel->setText("Warning: Path does not exist or is not writable");
    }
}

void SettingsDialog::onReject()
{
    // Reload original settings and reject
    loadSettings();
    m_errorLabel->clear();
    reject();
}

// ========================================================================
// Private Methods
// ========================================================================

void SettingsDialog::setupUi()
{
    // Create form layout
    QFormLayout* formLayout = new QFormLayout();

    // Display name field
    m_displayNameEdit = new QLineEdit();
    m_displayNameEdit->setPlaceholderText("My Device");
    m_displayNameEdit->setToolTip("The name shown to other peers on the network");
    formLayout->addRow("Display Name:", m_displayNameEdit);

    // Download path field with browse button
    QHBoxLayout* pathLayout = new QHBoxLayout();
    m_downloadPathEdit = new QLineEdit();
    m_downloadPathEdit->setToolTip("Where received files will be saved");
    m_downloadPathEdit->setReadOnly(false);  // Allow manual editing

    m_browseButton = new QPushButton("Browse...");
    m_browseButton->setMaximumWidth(100);

    pathLayout->addWidget(m_downloadPathEdit);
    pathLayout->addWidget(m_browseButton);

    formLayout->addRow("Download Path:", pathLayout);

    // Device UUID (read-only, informational)
    m_uuidLabel = new QLabel();
    m_uuidLabel->setStyleSheet("color: gray; font-size: 9pt;");
    m_uuidLabel->setWordWrap(true);
    m_uuidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    formLayout->addRow("Device UUID:", m_uuidLabel);

    // Spacer
    formLayout->addItem(new QSpacerItem(0, 10, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // "Show close warning" checkbox
    m_showCloseWarningCheckBox = new QCheckBox("Show warning when minimizing to tray");
    m_showCloseWarningCheckBox->setToolTip(
        "When checked, shows a warning the first time you close the window"
    );
    formLayout->addRow("", m_showCloseWarningCheckBox);

    // Spacer
    formLayout->addItem(new QSpacerItem(0, 10, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // Peer timeout is now fixed at 10 seconds to match DiscoveryService
    // Removed user-configurable slider to prevent timeout mismatch
    QLabel* timeoutLabel = new QLabel("10s (fixed)");
    timeoutLabel->setToolTip("Peers are marked inactive after 10 seconds of no beacon");
    formLayout->addRow("Peer Timeout (seconds):", timeoutLabel);

    // Keep the slider widgets for compatibility but hide them
    m_peerTimeoutSlider = new QSlider(Qt::Horizontal);
    m_peerTimeoutSlider->setRange(10, 10);  // Fixed at 10
    m_peerTimeoutSlider->setEnabled(false);  // Disabled
    m_peerTimeoutSlider->hide();  // Hidden
    m_peerTimeoutValueLabel = new QLabel("10s (fixed)");
    m_peerTimeoutValueLabel->hide();  // Hidden

    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setStyleSheet("color: red;");
    m_errorLabel->setWordWrap(true);
    formLayout->addRow("", m_errorLabel);

    // Spacer
    formLayout->addItem(new QSpacerItem(0, 10, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // Dialog buttons
    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    formLayout->addRow(m_buttonBox);

    // Main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addLayout(formLayout);

    // Connect signals
    connect(m_browseButton, &QPushButton::clicked,
            this, &SettingsDialog::onBrowsePath);
    connect(m_buttonBox->button(QDialogButtonBox::Save), &QPushButton::clicked,
            this, &SettingsDialog::onSave);
    connect(m_buttonBox->button(QDialogButtonBox::Cancel), &QPushButton::clicked,
            this, &SettingsDialog::onReject);

    // Validate path on text change
    connect(m_downloadPathEdit, &QLineEdit::textChanged,
            this, &SettingsDialog::validatePath);

    // Update timeout label when slider changes
    // Peer timeout is now fixed at 10 seconds - slider connection disabled
    // connect(m_peerTimeoutSlider, &QSlider::valueChanged,
    //         this, [this](int value) {
    //             m_peerTimeoutValueLabel->setText(QString("%1s").arg(value));
    //         });
}

void SettingsDialog::loadSettings()
{
    if (!m_settings) {
        return;
    }

    m_displayNameEdit->setText(m_settings->getDisplayName());
    m_downloadPathEdit->setText(m_settings->getDownloadPath());
    m_uuidLabel->setText(m_settings->getDeviceUuid());
    m_showCloseWarningCheckBox->setChecked(m_settings->getShowCloseWarning());

    // Peer timeout is fixed at 10 seconds - no need to load from settings
    // m_peerTimeoutSlider->setValue(m_settings->getPeerTimeout());
    // m_peerTimeoutValueLabel->setText(QString("%1s").arg(m_settings->getPeerTimeout()));
}

bool SettingsDialog::isDisplayNameValid() const
{
    QString name = m_displayNameEdit->text().trimmed();
    return !name.isEmpty();
}

bool SettingsDialog::isDownloadPathValid() const
{
    QString path = m_downloadPathEdit->text();

    if (path.isEmpty()) {
        return false;
    }

    QDir dir(path);
    if (!dir.exists()) {
        return false;
    }

    // Check if writable by testing file creation
    QFileInfo fi(path);
    if (!fi.isWritable()) {
        return false;
    }

    return true;
}
