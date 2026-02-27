/**
 * @file SecurePairingOutgoingDialog.h
 * @brief Modal dialog for initiating secure pairing with a peer.
 */

#ifndef EXOSEND_QTUI_SECUREPAIRINGOUTGOINGDIALOG_H
#define EXOSEND_QTUI_SECUREPAIRINGOUTGOINGDIALOG_H

#include <QDialog>
#include <QString>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QTimer>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>

class SecurePairingOutgoingDialog : public QDialog {
    Q_OBJECT

public:
    explicit SecurePairingOutgoingDialog(const QString& peerUuid,
                                         const QString& peerName,
                                         const QString& peerIp,
                                         quint16 peerPort,
                                         const QString& localUuid,
                                         uint32_t timeoutMs,
                                         QWidget* parent = nullptr);

    ~SecurePairingOutgoingDialog() override;

    QString getPeerFingerprint() const { return m_peerFingerprint; }

private slots:
    void onStart();
    void onCancel();
    void onToggleShow(bool checked);
    void onCopy();
    void onTick();

private:
    struct Result {
        bool ok{false};
        QString peerFingerprint;
        QString userMessage;
        QString details;
    };

    void setupUi();
    void updateCountdown();
    void setUiRunning(bool running);
    void postResult(Result r);
    Result runPairingWorker();
    void requestCancel();

private:
    QString m_peerUuid;
    QString m_peerName;
    QString m_peerIp;
    quint16 m_peerPort;
    QString m_localUuid;
    uint32_t m_timeoutMs;

    QString m_peerFingerprint;

    std::array<uint8_t, 16> m_secret{};
    QString m_phraseLine;

    std::atomic_bool m_cancelRequested{false};
    std::thread m_worker;

    std::mutex m_socketMutex;
    uintptr_t m_activeSocketHandle{0};  // SOCKET stored as uintptr_t (winsock type in .cpp)

    bool m_started{false};
    bool m_finished{false};
    bool m_timedOut{false};

    // UI
    QLabel* m_titleLabel{nullptr};
    QLabel* m_statusLabel{nullptr};
    QLabel* m_countdownLabel{nullptr};
    QLineEdit* m_phraseEdit{nullptr};
    QCheckBox* m_showCheck{nullptr};
    QPushButton* m_copyButton{nullptr};
    QDialogButtonBox* m_buttonBox{nullptr};
    QPushButton* m_startButton{nullptr};
    QPushButton* m_cancelButton{nullptr};
    QTimer* m_timer{nullptr};
    qint64 m_deadlineMsSinceEpoch{0};
};

#endif  // EXOSEND_QTUI_SECUREPAIRINGOUTGOINGDIALOG_H

