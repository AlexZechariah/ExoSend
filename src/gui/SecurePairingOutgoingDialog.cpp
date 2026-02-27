/**
 * @file SecurePairingOutgoingDialog.cpp
 * @brief Outgoing secure pairing dialog implementation.
 */

#include "exosend/QtUi/SecurePairingOutgoingDialog.h"

#include "exosend/ErrorCodes.h"
#include "exosend/PairingConfirm.h"
#include "exosend/PairingPhrase.h"
#include "exosend/PairingSecret.h"
#include "exosend/FileTransfer.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"
#include "exosend/TransferHeader.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QMessageBox>
#include <QDateTime>
#include <QGuiApplication>
#include <QClipboard>
#include <QPointer>
#include <QMetaObject>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <vector>

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

SecurePairingOutgoingDialog::SecurePairingOutgoingDialog(const QString& peerUuid,
                                                         const QString& peerName,
                                                         const QString& peerIp,
                                                         quint16 peerPort,
                                                         const QString& localUuid,
                                                         uint32_t timeoutMs,
                                                         QWidget* parent)
    : QDialog(parent)
    , m_peerUuid(peerUuid)
    , m_peerName(peerName)
    , m_peerIp(peerIp)
    , m_peerPort(peerPort)
    , m_localUuid(localUuid)
    , m_timeoutMs(timeoutMs)
{
    setupUi();

    setWindowTitle("Secure Pairing");
    setMinimumWidth(560);

    std::string genErr;
    if (!ExoSend::PairingSecret::generate128(m_secret, genErr)) {
        // If this fails, pairing cannot proceed; show a non-retryable error.
        QMessageBox::critical(this,
                              "Pairing Failed",
                              QString("[%1] Failed to generate pairing secret.")
                                  .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR));
        m_finished = true;
        return;
    }

    std::array<std::string, 12> words{};
    std::string phraseErr;
    if (!ExoSend::PairingPhrase::encodeRfc1751(m_secret, words, phraseErr)) {
        QMessageBox::critical(this,
                              "Pairing Failed",
                              QString("[%1] Failed to encode pairing phrase.")
                                  .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR));
        m_finished = true;
        return;
    }

    m_phraseLine = QString::fromStdString(ExoSend::PairingPhrase::formatHyphenLine(words));
    if (m_phraseEdit) {
        m_phraseEdit->setText(m_phraseLine);
    }

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    m_deadlineMsSinceEpoch = now + static_cast<qint64>(m_timeoutMs);

    m_timer = new QTimer(this);
    m_timer->setInterval(250);
    connect(m_timer, &QTimer::timeout, this, &SecurePairingOutgoingDialog::onTick);
    m_timer->start();

    updateCountdown();
    setUiRunning(false);
}

SecurePairingOutgoingDialog::~SecurePairingOutgoingDialog() {
    requestCancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void SecurePairingOutgoingDialog::onStart() {
    if (m_finished || m_started) return;
    if (m_phraseLine.isEmpty()) {
        QMessageBox::warning(this, "Pairing Failed", "Pairing phrase is not available.");
        return;
    }

    if (m_worker.joinable()) {
        m_worker.join();
    }

    m_cancelRequested.store(false);
    m_started = true;
    setUiRunning(true);
    m_statusLabel->setText("Waiting for the peer to confirm the phrase...");

    QPointer<SecurePairingOutgoingDialog> safeThis(this);
    m_worker = std::thread([safeThis]() {
        if (!safeThis) return;
        Result r = safeThis->runPairingWorker();
        if (!safeThis) return;
        QMetaObject::invokeMethod(safeThis,
                                  [safeThis, r = std::move(r)]() mutable {
                                      if (!safeThis) return;
                                      safeThis->postResult(std::move(r));
                                  },
                                  Qt::QueuedConnection);
    });
}

void SecurePairingOutgoingDialog::onCancel() {
    requestCancel();
    reject();
}

void SecurePairingOutgoingDialog::onToggleShow(bool checked) {
    if (!m_phraseEdit) return;
    m_phraseEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
}

void SecurePairingOutgoingDialog::onCopy() {
    if (m_phraseLine.isEmpty()) return;
    if (QGuiApplication::clipboard()) {
        QGuiApplication::clipboard()->setText(m_phraseLine);
    }
}

void SecurePairingOutgoingDialog::onTick() {
    updateCountdown();
}

void SecurePairingOutgoingDialog::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    m_titleLabel = new QLabel(
        "Share this pairing phrase with the peer using a separate channel.\n"
        "Then click Start to begin pairing.",
        this);
    m_titleLabel->setWordWrap(true);
    mainLayout->addWidget(m_titleLabel);

    QLabel* peerLabel = new QLabel(this);
    peerLabel->setTextFormat(Qt::PlainText);
    peerLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    peerLabel->setWordWrap(true);
    peerLabel->setText("Peer: " + m_peerName + "\nIP: " + m_peerIp + "\nUUID: " + m_peerUuid);
    mainLayout->addWidget(peerLabel);

    QFrame* line = new QFrame(this);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(line);

    m_countdownLabel = new QLabel(this);
    m_countdownLabel->setTextFormat(Qt::PlainText);
    mainLayout->addWidget(m_countdownLabel);

    QHBoxLayout* phraseLayout = new QHBoxLayout();
    m_phraseEdit = new QLineEdit(this);
    m_phraseEdit->setReadOnly(true);
    m_phraseEdit->setEchoMode(QLineEdit::Password);
    phraseLayout->addWidget(m_phraseEdit, 1);

    m_showCheck = new QCheckBox("Show", this);
    m_showCheck->setChecked(false);
    connect(m_showCheck, &QCheckBox::toggled, this, &SecurePairingOutgoingDialog::onToggleShow);
    phraseLayout->addWidget(m_showCheck);

    m_copyButton = new QPushButton("Copy", this);
    connect(m_copyButton, &QPushButton::clicked, this, &SecurePairingOutgoingDialog::onCopy);
    phraseLayout->addWidget(m_copyButton);

    mainLayout->addLayout(phraseLayout);

    m_statusLabel = new QLabel("Ready.", this);
    m_statusLabel->setWordWrap(true);
    mainLayout->addWidget(m_statusLabel);

    m_buttonBox = new QDialogButtonBox(this);
    m_startButton = m_buttonBox->addButton("Start", QDialogButtonBox::AcceptRole);
    m_cancelButton = m_buttonBox->addButton("Cancel", QDialogButtonBox::RejectRole);
    mainLayout->addWidget(m_buttonBox);

    connect(m_startButton, &QPushButton::clicked, this, &SecurePairingOutgoingDialog::onStart);
    connect(m_cancelButton, &QPushButton::clicked, this, &SecurePairingOutgoingDialog::onCancel);
}

void SecurePairingOutgoingDialog::updateCountdown() {
    if (!m_countdownLabel) return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 remaining = m_deadlineMsSinceEpoch - now;
    m_countdownLabel->setText("Time remaining: " + formatRemaining(remaining));

    if (remaining <= 0 && !m_timedOut) {
        m_timedOut = true;
        requestCancel();
        QMessageBox::warning(this,
                             "Pairing Failed",
                             QString("[%1] Pairing timed out.")
                                 .arg(ExoSend::ErrorCodes::PAIRING_TIMED_OUT));
        reject();
    }
}

void SecurePairingOutgoingDialog::setUiRunning(bool running) {
    if (m_startButton) m_startButton->setEnabled(!running && !m_finished);
    if (m_phraseEdit) m_phraseEdit->setEnabled(!running);
    if (m_showCheck) m_showCheck->setEnabled(!running);
    if (m_copyButton) m_copyButton->setEnabled(!running);
}

void SecurePairingOutgoingDialog::requestCancel() {
    m_cancelRequested.store(true);
    std::lock_guard<std::mutex> lock(m_socketMutex);
    const SOCKET s = static_cast<SOCKET>(m_activeSocketHandle);
    if (s != INVALID_SOCKET && s != 0) {
        (void)::shutdown(s, SD_BOTH);
    }
}

void SecurePairingOutgoingDialog::postResult(Result r) {
    if (m_finished) return;

    m_finished = true;
    setUiRunning(false);

    if (m_worker.joinable()) {
        m_worker.join();
    }
    {
        std::lock_guard<std::mutex> lock(m_socketMutex);
        m_activeSocketHandle = 0;
    }

    if (m_cancelRequested.load()) {
        reject();
        return;
    }

    if (r.ok) {
        m_peerFingerprint = r.peerFingerprint;
        accept();
        return;
    }

    m_statusLabel->setText("Pairing failed.");
    QMessageBox box(QMessageBox::Critical,
                    "Pairing Failed",
                    r.userMessage.isEmpty() ? "Pairing failed." : r.userMessage,
                    QMessageBox::Ok,
                    this);
    if (!r.details.isEmpty()) {
        box.setDetailedText(r.details);
    }
    box.exec();

    // Allow retry with the same phrase.
    m_started = false;
    m_finished = false;
    setUiRunning(false);
    m_statusLabel->setText("Ready.");
}

SecurePairingOutgoingDialog::Result SecurePairingOutgoingDialog::runPairingWorker() {
    Result r;

    if (m_cancelRequested.load()) {
        r.ok = false;
        r.userMessage = QString("[%1] Pairing cancelled.").arg(ExoSend::ErrorCodes::PAIRING_CANCELLED);
        return r;
    }

    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to create socket.")
            .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR);
        r.details = "socket() failed: WSAGetLastError()=" + QString::number(WSAGetLastError());
        return r;
    }

    const auto clearActiveSocket = [this]() {
        std::lock_guard<std::mutex> lock(m_socketMutex);
        m_activeSocketHandle = 0;
    };

    {
        std::lock_guard<std::mutex> lock(m_socketMutex);
        m_activeSocketHandle = static_cast<uintptr_t>(sock);
    }

    const uint32_t timeoutMs = m_timeoutMs;
    if (!ExoSend::setSocketRecvTimeout(sock, timeoutMs)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to set socket timeout.")
            .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR);
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_peerPort);
    if (::inet_pton(AF_INET, m_peerIp.toStdString().c_str(), &addr.sin_addr) <= 0) {
        r.ok = false;
        r.userMessage = QString("[%1] Invalid peer IP address.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int wsaError = WSAGetLastError();
        r.ok = false;
        r.userMessage = QString("[%1] Failed to connect to peer.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        r.details =
            "Peer: " + m_peerName + "\n" +
            "IP: " + m_peerIp + "\n" +
            "Port: " + QString::number(m_peerPort) + "\n\n" +
            "WSAGetLastError()=" + QString::number(wsaError);
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    std::string tlsErr;
    ExoSend::TlsSocket tls(sock, ExoSend::TlsRole::CLIENT);
    if (!tls.handshake(tlsErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] TLS handshake failed.")
            .arg(ExoSend::ErrorCodes::PAIRING_TLS_ERROR);
        r.details = QString::fromStdString(tlsErr);
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    ExoSend::TlsTransportStream stream(tls);

    std::array<uint8_t, 32> exporter{};
    if (!tls.getTlsExporterChannelBinding(exporter, tlsErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to compute TLS channel binding.")
            .arg(ExoSend::ErrorCodes::PAIRING_TLS_ERROR);
        r.details = QString::fromStdString(tlsErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    std::string fpErr;
    const std::string localFp = tls.getLocalFingerprint(fpErr);
    const std::string peerFp = tls.getPeerFingerprint(fpErr);
    if (localFp.empty() || peerFp.empty()) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to obtain certificate fingerprints.")
            .arg(ExoSend::ErrorCodes::PAIRING_TLS_ERROR);
        r.details = QString::fromStdString(fpErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    std::array<uint8_t, 32> confirmKey{};
    std::string confirmErr;
    if (!ExoSend::PairingConfirm::deriveConfirmKey(m_secret, exporter, confirmKey, confirmErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to derive pairing key.")
            .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR);
        r.details = QString::fromStdString(confirmErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    std::array<uint8_t, 32> clientTag{};
    if (!ExoSend::PairingConfirm::computeTag(
            confirmKey,
            ExoSend::PairingRole::Client,
            m_localUuid.toStdString(),
            localFp,
            m_peerUuid.toStdString(),
            peerFp,
            clientTag,
            confirmErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to compute pairing tag.")
            .arg(ExoSend::ErrorCodes::PAIRING_INTERNAL_ERROR);
        r.details = QString::fromStdString(confirmErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    ExoSend::ExoHeader req(ExoSend::PacketType::PAIR_REQ, 0, "");
    req.setSenderUuid(m_localUuid.toStdString());
    req.setSha256Bytes(clientTag.data());

    std::vector<uint8_t> reqBuf(ExoSend::HEADER_SIZE);
    (void)req.serializeToBuffer(reqBuf.data());

    std::string ioErr;
    if (!stream.sendExact(reqBuf.data(), reqBuf.size(), ioErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to send pairing request.")
            .arg(ExoSend::ErrorCodes::PAIRING_TLS_ERROR);
        r.details = QString::fromStdString(ioErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    std::vector<uint8_t> respBuf(ExoSend::HEADER_SIZE);
    if (!stream.recvExact(respBuf.data(), respBuf.size(), ioErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Failed to receive pairing response.")
            .arg(ExoSend::ErrorCodes::PAIRING_TLS_ERROR);
        r.details = QString::fromStdString(ioErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    ExoSend::ExoHeader resp;
    if (!resp.deserializeFromBuffer(respBuf.data()) || !resp.isValid()) {
        r.ok = false;
        r.userMessage = QString("[%1] Invalid pairing response.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    if (resp.getPacketType() == ExoSend::PacketType::REJECT) {
        const std::string reason = resp.getFilename();
        r.ok = false;
        r.userMessage = QString("[%1] Peer rejected pairing.")
            .arg(ExoSend::ErrorCodes::PAIRING_REJECTED_REMOTE);
        r.details = QString::fromStdString(reason);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    if (resp.getPacketType() != ExoSend::PacketType::PAIR_RESP) {
        r.ok = false;
        r.userMessage = QString("[%1] Peer returned an unexpected response.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    if (resp.getSenderUuid() != m_peerUuid.toStdString()) {
        r.ok = false;
        r.userMessage = QString("[%1] Peer identity mismatch during pairing.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        r.details = "Expected UUID: " + m_peerUuid + "\nActual UUID: " +
                    QString::fromStdString(resp.getSenderUuid());
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    const auto serverTag = resp.getSha256Bytes();
    if (!ExoSend::PairingConfirm::verifyTag(
            confirmKey,
            ExoSend::PairingRole::Server,
            m_peerUuid.toStdString(),
            peerFp,
            m_localUuid.toStdString(),
            localFp,
            serverTag,
            confirmErr)) {
        r.ok = false;
        r.userMessage = QString("[%1] Pairing confirmation failed.")
            .arg(ExoSend::ErrorCodes::PAIRING_PROTOCOL_ERROR);
        r.details = QString::fromStdString(confirmErr);
        stream.shutdown();
        clearActiveSocket();
        closesocket(sock);
        return r;
    }

    stream.shutdown();
    clearActiveSocket();
    closesocket(sock);

    r.ok = true;
    r.peerFingerprint = QString::fromStdString(peerFp);
    return r;
}
