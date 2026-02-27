/**
 * @file SettingsDialog.cpp
 * @brief Settings dialog implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/SettingsDialog.h"
#include "exosend/QtUi/SettingsManager.h"
#include "exosend/FingerprintUtils.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>
#include <QDateTime>
#include <QSpacerItem>

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
    setMinimumWidth(520);
    setMinimumHeight(400);
}

// ========================================================================
// Private Slots: General tab
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
    if (m_enableCrashDumpsCheckBox) {
        m_settings->setEnableCrashDumps(m_enableCrashDumpsCheckBox->isChecked());
    }

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

void SettingsDialog::onFactoryReset()
{
    QMessageBox dlg(this);
    dlg.setWindowTitle("Factory Reset");
    dlg.setIcon(QMessageBox::Warning);
    dlg.setText("Reset ExoSend settings and forget all paired peers?");
    dlg.setInformativeText(
        "This will:\n"
        "- Reset preferences to defaults\n"
        "- Forget all paired peers (clears trusted peers)\n"
        "- Clear per-peer auto-accept preferences\n"
        "- Restart ExoSend\n\n"
        "This cannot be undone."
    );

    QCheckBox* firewallCheck = new QCheckBox("Also remove Windows Firewall rules (Admin)", &dlg);
    firewallCheck->setChecked(true);
    firewallCheck->setToolTip(
        "Best-effort: this may prompt for Administrator approval (UAC).\n"
        "If denied, the reset will still complete but firewall rules may remain.");
    dlg.setCheckBox(firewallCheck);

    dlg.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    dlg.setDefaultButton(QMessageBox::Cancel);

    if (dlg.exec() != QMessageBox::Yes) {
        return;
    }

    m_factoryResetRequested = true;
    m_factoryResetRemoveFirewall = firewallCheck->isChecked();

    // Close the settings dialog. The caller (MainWindow) will perform reset + restart.
    reject();
}

// ========================================================================
// Private Slots: Trusted Peers tab (v0.3.0)
// ========================================================================

void SettingsDialog::onRevokePeer()
{
    if (!m_trustedPeersList || !m_settings) {
        return;
    }

    QListWidgetItem* item = m_trustedPeersList->currentItem();
    if (!item) {
        return;
    }

    const QString peerUuid = item->data(Qt::UserRole).toString();
    const QString displayName = item->data(Qt::UserRole + 1).toString();

    QMessageBox::StandardButton reply = QMessageBox::question(
        this,
        "Revoke Trust",
        QString("Remove trust for peer \"%1\"?\n\n"
                "The peer will need to be re-paired on the next connection.")
            .arg(displayName.isEmpty() ? peerUuid.left(8) : displayName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        m_settings->revokePeer(peerUuid);
        refreshTrustedPeersList();
    }
}

void SettingsDialog::onClearAllPeers()
{
    if (!m_settings) {
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::warning(
        this,
        "Clear All Trust",
        "Remove ALL trusted peers?\n\n"
        "Every peer will need to be re-paired on next connection.\n"
        "This cannot be undone.",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        m_settings->clearAllPeers();
        refreshTrustedPeersList();
    }
}

void SettingsDialog::refreshTrustedPeersList()
{
    if (!m_trustedPeersList || !m_settings) {
        return;
    }

    m_trustedPeersList->clear();

    const auto peers = m_settings->getTrustedPeers();
    if (peers.empty()) {
        QListWidgetItem* placeholder = new QListWidgetItem("(No trusted peers)");
        placeholder->setFlags(placeholder->flags() & ~Qt::ItemIsSelectable);
        placeholder->setForeground(Qt::gray);
        m_trustedPeersList->addItem(placeholder);
        if (m_revokePeerButton) m_revokePeerButton->setEnabled(false);
        if (m_clearAllPeersButton) m_clearAllPeersButton->setEnabled(false);
        return;
    }

    if (m_clearAllPeersButton) m_clearAllPeersButton->setEnabled(true);

    for (const auto& kv : peers) {
        const std::string& uuid = kv.first;
        const auto& rec = kv.second;

        // Build display text: "DisplayName | UUID[:8]... | Last seen: date"
        const QString displayName = QString::fromStdString(rec.displayName);
        const QString uuidShort = QString::fromStdString(uuid.substr(0, 8)) + "...";
        const QString lastSeen = rec.lastSeenIso8601.empty()
            ? "Unknown"
            : QString::fromStdString(rec.lastSeenIso8601).left(10);  // YYYY-MM-DD

        const QString labelText = QString("%1  [%2]  Last seen: %3")
            .arg(displayName.isEmpty() ? "(unnamed)" : displayName)
            .arg(uuidShort)
            .arg(lastSeen);

        // Show fingerprint on a second line (first 32 chars, formatted)
        const QString fpShort = QString::fromStdString(
            ExoSend::FingerprintUtils::formatForDisplay(rec.pinnedFingerprintSha256Hex)
        ).left(23) + "...";  // Show first 8 bytes (AA:BB:CC:DD:EE:FF:GG:HH...)

        QListWidgetItem* item = new QListWidgetItem(labelText + "\n  Fingerprint: " + fpShort);
        item->setData(Qt::UserRole, QString::fromStdString(uuid));
        item->setData(Qt::UserRole + 1, displayName);
        m_trustedPeersList->addItem(item);
    }

    if (m_revokePeerButton) m_revokePeerButton->setEnabled(false);  // Enabled on selection
}

// ========================================================================
// Private Methods
// ========================================================================

void SettingsDialog::setupUi()
{
    QTabWidget* tabWidget = new QTabWidget(this);
    tabWidget->addTab(buildGeneralTab(), "General");
    tabWidget->addTab(buildTrustedPeersTab(), "Trusted Peers");

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(tabWidget);

    // Dialog buttons (Save / Cancel) are part of the General tab form layout,
    // but we want them outside the tab for consistent dialog UX.
    // Re-wire: move the buttonBox row here, after the tabWidget.
    mainLayout->addWidget(m_buttonBox);

    // Connect signals
    connect(m_browseButton, &QPushButton::clicked,
            this, &SettingsDialog::onBrowsePath);
    connect(m_buttonBox->button(QDialogButtonBox::Save), &QPushButton::clicked,
            this, &SettingsDialog::onSave);
    connect(m_buttonBox->button(QDialogButtonBox::Cancel), &QPushButton::clicked,
            this, &SettingsDialog::onReject);
    if (m_factoryResetButton) {
        connect(m_factoryResetButton, &QPushButton::clicked,
                this, &SettingsDialog::onFactoryReset);
    }
    connect(m_downloadPathEdit, &QLineEdit::textChanged,
            this, &SettingsDialog::validatePath);
}

QWidget* SettingsDialog::buildGeneralTab()
{
    QWidget* tab = new QWidget();
    QFormLayout* formLayout = new QFormLayout(tab);

    // Display name field
    m_displayNameEdit = new QLineEdit();
    m_displayNameEdit->setPlaceholderText("My Device");
    m_displayNameEdit->setToolTip("The name shown to other peers on the network");
    formLayout->addRow("Display Name:", m_displayNameEdit);

    // Download path field with browse button
    QHBoxLayout* pathLayout = new QHBoxLayout();
    m_downloadPathEdit = new QLineEdit();
    m_downloadPathEdit->setToolTip("Where received files will be saved");
    m_downloadPathEdit->setReadOnly(false);

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

    formLayout->addItem(new QSpacerItem(0, 10, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // "Show close warning" checkbox
    m_showCloseWarningCheckBox = new QCheckBox("Show warning when minimizing to tray");
    m_showCloseWarningCheckBox->setToolTip(
        "When checked, shows a warning the first time you close the window");
    formLayout->addRow("", m_showCloseWarningCheckBox);

    // Crash dumps checkbox (privacy control)
    m_enableCrashDumpsCheckBox = new QCheckBox("Enable crash dumps (privacy-sensitive)");
    m_enableCrashDumpsCheckBox->setToolTip(
        "When enabled, ExoSend may write crash dumps and logs to help debugging.\n"
        "Crash dumps can contain sensitive in-memory data.\n\n"
        "Location: %LOCALAPPDATA%\\ExoSend\\crash_dumps\\");
    formLayout->addRow("", m_enableCrashDumpsCheckBox);

    formLayout->addItem(new QSpacerItem(0, 10, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // Peer timeout (fixed at 10s)
    QLabel* timeoutLabel = new QLabel("10s (fixed)");
    timeoutLabel->setToolTip("Peers are marked inactive after 10 seconds of no beacon");
    formLayout->addRow("Peer Timeout:", timeoutLabel);

    // Hidden slider widgets (kept for ABI compat with existing code that sets them)
    m_peerTimeoutSlider = new QSlider(Qt::Horizontal);
    m_peerTimeoutSlider->setRange(10, 10);
    m_peerTimeoutSlider->setEnabled(false);
    m_peerTimeoutSlider->hide();
    m_peerTimeoutValueLabel = new QLabel("10s (fixed)");
    m_peerTimeoutValueLabel->hide();

    formLayout->addItem(new QSpacerItem(0, 14, QSizePolicy::Minimum, QSizePolicy::Fixed));

    // Factory reset (settings + trust + restart).
    m_factoryResetButton = new QPushButton("Factory Reset...");
    m_factoryResetButton->setToolTip(
        "Reset settings to defaults, forget all paired peers, and restart ExoSend.");
    m_factoryResetButton->setStyleSheet("color: red;");
    formLayout->addRow("", m_factoryResetButton);

    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setStyleSheet("color: red;");
    m_errorLabel->setWordWrap(true);
    formLayout->addRow("", m_errorLabel);

    // Dialog button box (created here, moved to main layout in setupUi)
    m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);

    return tab;
}

QWidget* SettingsDialog::buildTrustedPeersTab()
{
    QWidget* tab = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(tab);

    // Description label
    QLabel* descLabel = new QLabel(
        "Peers you have paired with are listed below. "
        "Revoking a peer removes its pinned certificate fingerprint -- "
        "you will be prompted to re-pair on the next connection.");
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("color: gray; font-size: 9pt;");
    layout->addWidget(descLabel);

    // Trusted peers list
    m_trustedPeersList = new QListWidget();
    m_trustedPeersList->setAlternatingRowColors(true);
    m_trustedPeersList->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(m_trustedPeersList);

    // Action buttons
    QHBoxLayout* btnLayout = new QHBoxLayout();
    m_revokePeerButton = new QPushButton("Revoke Selected");
    m_revokePeerButton->setEnabled(false);
    m_revokePeerButton->setToolTip("Remove trust for the selected peer");

    m_clearAllPeersButton = new QPushButton("Clear All Pairs");
    m_clearAllPeersButton->setEnabled(false);
    m_clearAllPeersButton->setToolTip("Remove all trusted peers (requires re-pairing)");
    m_clearAllPeersButton->setStyleSheet("color: red;");

    btnLayout->addWidget(m_revokePeerButton);
    btnLayout->addStretch();
    btnLayout->addWidget(m_clearAllPeersButton);
    layout->addLayout(btnLayout);

    // Connect signals
    connect(m_revokePeerButton, &QPushButton::clicked,
            this, &SettingsDialog::onRevokePeer);
    connect(m_clearAllPeersButton, &QPushButton::clicked,
            this, &SettingsDialog::onClearAllPeers);
    connect(m_trustedPeersList, &QListWidget::currentItemChanged,
            this, [this](QListWidgetItem* current, QListWidgetItem*) {
                if (m_revokePeerButton) {
                    // Only enable revoke if a selectable item (not placeholder) is selected.
                    const bool hasSelection = current &&
                        (current->flags() & Qt::ItemIsSelectable);
                    m_revokePeerButton->setEnabled(hasSelection);
                }
            });

    return tab;
}

void SettingsDialog::loadSettings()
{
    if (!m_settings) {
        return;
    }

    if (m_displayNameEdit) m_displayNameEdit->setText(m_settings->getDisplayName());
    if (m_downloadPathEdit) m_downloadPathEdit->setText(m_settings->getDownloadPath());
    if (m_uuidLabel) m_uuidLabel->setText(m_settings->getDeviceUuid());
    if (m_showCloseWarningCheckBox) {
        m_showCloseWarningCheckBox->setChecked(m_settings->getShowCloseWarning());
    }
    if (m_enableCrashDumpsCheckBox) {
        m_enableCrashDumpsCheckBox->setChecked(m_settings->getEnableCrashDumps());
    }

    refreshTrustedPeersList();
}

bool SettingsDialog::isDisplayNameValid() const
{
    if (!m_displayNameEdit) return false;
    return !m_displayNameEdit->text().trimmed().isEmpty();
}

bool SettingsDialog::isDownloadPathValid() const
{
    if (!m_downloadPathEdit) return false;
    QString path = m_downloadPathEdit->text();
    if (path.isEmpty()) return false;

    QDir dir(path);
    if (!dir.exists()) return false;

    QFileInfo fi(path);
    return fi.isWritable();
}
