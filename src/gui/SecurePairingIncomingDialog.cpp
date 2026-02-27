/**
 * @file SecurePairingIncomingDialog.cpp
 * @brief Incoming secure pairing dialog implementation.
 */

#include "exosend/QtUi/SecurePairingIncomingDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QMessageBox>
#include <QDateTime>

namespace {

static QString formatRemaining(qint64 remainingMs) {
    if (remainingMs < 0) remainingMs = 0;
    const qint64 totalSeconds = remainingMs / 1000;
    const qint64 minutes = totalSeconds / 60;
    const qint64 seconds = totalSeconds % 60;
    return QString("%1:%2")
        .arg(minutes, 2, 10, QLatin1Char('0'))
        .arg(seconds, 2, 10, QLatin1Char('0'));
}

}  // namespace

SecurePairingIncomingDialog::SecurePairingIncomingDialog(const QString& peerDisplayName,
                                                         const QString& peerIp,
                                                         const QString& peerUuid,
                                                         const QString& peerFingerprintDisplay,
                                                         const QString& localFingerprintDisplay,
                                                         uint32_t timeoutMs,
                                                         QWidget* parent)
    : QDialog(parent)
    , m_peerDisplayName(peerDisplayName)
    , m_peerIp(peerIp)
    , m_peerUuid(peerUuid)
    , m_peerFingerprintDisplay(peerFingerprintDisplay)
    , m_localFingerprintDisplay(localFingerprintDisplay)
    , m_timeoutMs(timeoutMs)
{
    setupUi();

    setWindowTitle("Secure Pairing Request");
    setMinimumWidth(520);

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    m_deadlineMsSinceEpoch = now + static_cast<qint64>(m_timeoutMs);

    m_timer = new QTimer(this);
    m_timer->setInterval(250);
    connect(m_timer, &QTimer::timeout, this, &SecurePairingIncomingDialog::onTick);
    m_timer->start();

    updateCountdown();
}

void SecurePairingIncomingDialog::setValidateFn(ValidateFn fn) {
    m_validateFn = std::move(fn);
}

QString SecurePairingIncomingDialog::getUserText() const {
    return m_inputEdit ? m_inputEdit->text() : QString();
}

void SecurePairingIncomingDialog::onTryPair() {
    if (!m_validateFn) {
        QMessageBox::critical(this, "Pairing Failed", "Internal error: pairing validation callback is not set.");
        return;
    }

    const QString userText = getUserText();
    QString userMsg;
    QString details;
    if (m_validateFn(userText, userMsg, details)) {
        accept();
        return;
    }

    QMessageBox box(QMessageBox::Warning,
                    "Pairing Failed",
                    userMsg.isEmpty() ? "Pairing failed." : userMsg,
                    QMessageBox::Ok,
                    this);
    if (!details.isEmpty()) {
        box.setDetailedText(details);
    }
    box.exec();
}

void SecurePairingIncomingDialog::onCancel() {
    reject();
}

void SecurePairingIncomingDialog::onToggleShow(bool checked) {
    if (!m_inputEdit) return;
    m_inputEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
}

void SecurePairingIncomingDialog::onTick() {
    updateCountdown();
}

void SecurePairingIncomingDialog::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    m_titleLabel = new QLabel(
        "A peer is requesting secure pairing.\n\n"
        "Enter the pairing phrase shown on the other device.",
        this);
    m_titleLabel->setWordWrap(true);
    mainLayout->addWidget(m_titleLabel);

    m_detailsLabel = new QLabel(this);
    m_detailsLabel->setTextFormat(Qt::PlainText);
    m_detailsLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_detailsLabel->setWordWrap(true);

    const QString details =
        "Peer: " + m_peerDisplayName + "\n" +
        "IP: " + m_peerIp + "\n" +
        "UUID: " + m_peerUuid + "\n\n" +
        "Peer certificate fingerprint (SHA-256):\n" + m_peerFingerprintDisplay + "\n\n" +
        "Local certificate fingerprint (SHA-256):\n" + m_localFingerprintDisplay;
    m_detailsLabel->setText(details);
    mainLayout->addWidget(m_detailsLabel);

    QFrame* line = new QFrame(this);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(line);

    m_countdownLabel = new QLabel(this);
    m_countdownLabel->setTextFormat(Qt::PlainText);
    mainLayout->addWidget(m_countdownLabel);

    QHBoxLayout* inputLayout = new QHBoxLayout();

    m_inputEdit = new QLineEdit(this);
    m_inputEdit->setEchoMode(QLineEdit::Password);
    m_inputEdit->setPlaceholderText("Paste the pairing phrase or message here");
    m_inputEdit->setClearButtonEnabled(true);
    inputLayout->addWidget(m_inputEdit, 1);

    m_showCheck = new QCheckBox("Show", this);
    m_showCheck->setChecked(false);
    connect(m_showCheck, &QCheckBox::toggled, this, &SecurePairingIncomingDialog::onToggleShow);
    inputLayout->addWidget(m_showCheck);

    mainLayout->addLayout(inputLayout);

    m_hintLabel = new QLabel(
        "Format: word1-word2-...-word12\n"
        "You can also paste a message that contains the phrase.",
        this);
    m_hintLabel->setWordWrap(true);
    m_hintLabel->setStyleSheet("color: #808080;");
    mainLayout->addWidget(m_hintLabel);

    m_buttonBox = new QDialogButtonBox(this);
    m_pairButton = m_buttonBox->addButton("Pair", QDialogButtonBox::AcceptRole);
    m_cancelButton = m_buttonBox->addButton("Cancel", QDialogButtonBox::RejectRole);
    mainLayout->addWidget(m_buttonBox);

    connect(m_pairButton, &QPushButton::clicked, this, &SecurePairingIncomingDialog::onTryPair);
    connect(m_cancelButton, &QPushButton::clicked, this, &SecurePairingIncomingDialog::onCancel);
}

void SecurePairingIncomingDialog::updateCountdown() {
    if (!m_countdownLabel) return;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 remaining = m_deadlineMsSinceEpoch - now;

    m_countdownLabel->setText("Time remaining: " + formatRemaining(remaining));

    if (remaining <= 0 && !m_timedOut) {
        m_timedOut = true;
        reject();
    }
}

