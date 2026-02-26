/**
 * @file IncomingTransferDialog.cpp
 * @brief Incoming transfer dialog implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/IncomingTransferDialog.h"
#include "exosend/Debug.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>
#include <QFrame>
#include <iostream>

// ========================================================================
// Constructor / Destructor
// ========================================================================

IncomingTransferDialog::IncomingTransferDialog(const QString& peerName,
                                               const QString& peerIp,
                                               const QString& peerUuid,
                                               quint16 peerPort,
                                               const QString& filename,
                                               qint64 fileSize,
                                               const QString& defaultPath,
                                               QWidget* parent)
    : QDialog(parent)
    , m_peerName(peerName)
    , m_peerIp(peerIp)
    , m_peerUuid(peerUuid)
    , m_peerPort(peerPort)
    , m_filename(filename)
    , m_fileSize(fileSize)
    , m_accepted(false)
    , m_alwaysAcceptChecked(false)  // Initialize checkbox state
    , m_pathEdit(nullptr)
    , m_infoLabel(nullptr)
    , m_warningLabel(nullptr)
    , m_errorLabel(nullptr)
    , m_browseButton(nullptr)
    , m_acceptButton(nullptr)
    , m_rejectButton(nullptr)
    , m_buttonBox(nullptr)
    , m_alwaysAcceptCheckBox(nullptr)
{
    setupUi();

    m_pathEdit->setText(defaultPath);

    setWindowTitle("Incoming File Transfer");
    setMinimumWidth(450);
}

// ========================================================================
// Public Methods
// ========================================================================

QString IncomingTransferDialog::getDownloadPath() const
{
    return m_pathEdit->text();
}

// ========================================================================
// Private Slots
// ========================================================================

void IncomingTransferDialog::onBrowsePath()
{
    QString currentPath = m_pathEdit->text();

    QString newPath = QFileDialog::getExistingDirectory(
        this,
        "Select Save Location",
        currentPath
    );

    if (!newPath.isEmpty()) {
        m_pathEdit->setText(newPath);
        validatePath();
    }
}

void IncomingTransferDialog::onAccept()
{
    // Validate download path
    QDir dir(m_pathEdit->text());
    if (!dir.exists()) {
        m_errorLabel->setText("Error: Path does not exist");
        return;
    }

    QFileInfo fi(m_pathEdit->text());
    if (!fi.isWritable()) {
        m_errorLabel->setText("Error: Path is not writable");
        return;
    }

    // Save checkbox state
    m_alwaysAcceptChecked = m_alwaysAcceptCheckBox->isChecked();

    m_accepted = true;
    m_errorLabel->clear();

    // FIXED: Don't disconnect signals - Qt handles cleanup automatically via parent-child mechanism
    // The previous disconnect() calls were causing Qt state corruption during dialog closure
    // This was the root cause of the crash after clicking Accept
    accept();
}

void IncomingTransferDialog::onReject()
{
    m_accepted = false;
    m_errorLabel->clear();
    reject();
}

void IncomingTransferDialog::validatePath()
{
    QDir dir(m_pathEdit->text());
    if (!dir.exists()) {
        m_errorLabel->setText("Warning: Path does not exist");
    } else {
        QFileInfo fi(m_pathEdit->text());
        if (!fi.isWritable()) {
            m_errorLabel->setText("Warning: Path is not writable");
        } else {
            m_errorLabel->clear();
        }
    }
}

// ========================================================================
// Private Methods
// ========================================================================

void IncomingTransferDialog::setupUi()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    // Info label with peer name and muted IP address
    m_infoLabel = new QLabel();
    QString sizeStr = formatFileSize(m_fileSize);

    // "<PeerName> (192.168.83.1:<port>)" with gray IP color (port omitted if unknown)
    QString peerAddress = m_peerIp;
    if (m_peerPort != 0) {
        peerAddress += ":" + QString::number(m_peerPort);
    }

    // Security: peer-controlled fields may contain HTML. Escape before using RichText.
    const QString safePeerName = m_peerName.toHtmlEscaped();
    const QString safePeerAddress = peerAddress.toHtmlEscaped();
    const QString safeFilename = m_filename.toHtmlEscaped();

    QString messageHtml = QString("<b>%1</b> <span style='color:#808080;'>(%2)</span> wants to send you a file:<br><br>"
                                  "File: <b>%3</b><br>"
                                  "Size: %4")
                              .arg(safePeerName)
                              .arg(safePeerAddress)
                              .arg(safeFilename)
                              .arg(sizeStr);
    m_infoLabel->setText(messageHtml);
    m_infoLabel->setTextFormat(Qt::RichText);
    m_infoLabel->setWordWrap(true);
    mainLayout->addWidget(m_infoLabel);

    // UUID display (monospace, gray color)
    QLabel* uuidLabel = new QLabel("UUID: " + m_peerUuid);
    uuidLabel->setTextFormat(Qt::PlainText);
    uuidLabel->setFont(QFont("Consolas", 8));
    uuidLabel->setStyleSheet("color: #808080;");
    uuidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mainLayout->addWidget(uuidLabel);

    // Separator
    QFrame* line = new QFrame();
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(line);

    // Download path
    QHBoxLayout* pathLayout = new QHBoxLayout();
    m_pathEdit = new QLineEdit();
    m_pathEdit->setToolTip("Where to save the file");

    m_browseButton = new QPushButton("Browse...");
    m_browseButton->setMaximumWidth(100);

    pathLayout->addWidget(new QLabel("Save to:"));
    pathLayout->addWidget(m_pathEdit);
    pathLayout->addWidget(m_browseButton);

    mainLayout->addLayout(pathLayout);

    // "Always accept from this peer" checkbox
    m_alwaysAcceptCheckBox = new QCheckBox("Always accept from this peer");
    m_alwaysAcceptCheckBox->setToolTip(
        "If checked, all future transfers from this peer will be accepted automatically."
    );
    mainLayout->addWidget(m_alwaysAcceptCheckBox);

    // Warning label
    m_warningLabel = new QLabel();
    m_warningLabel->setWordWrap(true);
    m_warningLabel->setStyleSheet("color: orange; padding: 5px; background-color: #FFF3CD; border-radius: 3px;");
    m_warningLabel->setText("Warning: Only accept files from trusted sources. "
                            "Ensure you recognize the sender before accepting.");
    mainLayout->addWidget(m_warningLabel);

    // Error label
    m_errorLabel = new QLabel();
    m_errorLabel->setWordWrap(true);
    m_errorLabel->setStyleSheet("color: red;");
    mainLayout->addWidget(m_errorLabel);

    // Spacer
    mainLayout->addSpacing(10);

    // Dialog buttons
    m_buttonBox = new QDialogButtonBox();
    m_acceptButton = m_buttonBox->addButton("Accept", QDialogButtonBox::AcceptRole);
    m_rejectButton = m_buttonBox->addButton("Reject", QDialogButtonBox::RejectRole);

    m_acceptButton->setDefault(true);
    m_acceptButton->setAutoDefault(true);

    mainLayout->addWidget(m_buttonBox);

    // Connect signals
    connect(m_browseButton, &QPushButton::clicked,
            this, &IncomingTransferDialog::onBrowsePath);

    connect(m_acceptButton, &QPushButton::clicked,
            this, &IncomingTransferDialog::onAccept);

    connect(m_rejectButton, &QPushButton::clicked,
            this, &IncomingTransferDialog::onReject);

    // Validate path on text change
    connect(m_pathEdit, &QLineEdit::textChanged,
            this, &IncomingTransferDialog::validatePath);
}

QString IncomingTransferDialog::formatFileSize(qint64 size) const
{
    const qint64 KB = 1024;
    const qint64 MB = 1024 * KB;
    const qint64 GB = 1024 * MB;

    if (size < KB) {
        return QString("%1 B").arg(size);
    } else if (size < MB) {
        return QString("%1 KB").arg(size / static_cast<double>(KB), 0, 'f', 1);
    } else if (size < GB) {
        return QString("%1 MB").arg(size / static_cast<double>(MB), 0, 'f', 2);
    } else {
        return QString("%1 GB").arg(size / static_cast<double>(GB), 0, 'f', 2);
    }
}
