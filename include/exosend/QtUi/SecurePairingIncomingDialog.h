/**
 * @file SecurePairingIncomingDialog.h
 * @brief Modal dialog for incoming secure pairing (PAIR_REQ / PAIR_RESP).
 */

#ifndef EXOSEND_QTUI_SECUREPAIRINGINCOMINGDIALOG_H
#define EXOSEND_QTUI_SECUREPAIRINGINCOMINGDIALOG_H

#include <QDialog>
#include <QString>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QTimer>

#include <cstdint>
#include <functional>

class SecurePairingIncomingDialog : public QDialog {
    Q_OBJECT

public:
    using ValidateFn = std::function<bool(const QString& userText,
                                          QString& outUserMessage,
                                          QString& outDetails)>;

    explicit SecurePairingIncomingDialog(const QString& peerDisplayName,
                                         const QString& peerIp,
                                         const QString& peerUuid,
                                         const QString& peerFingerprintDisplay,
                                         const QString& localFingerprintDisplay,
                                         uint32_t timeoutMs,
                                         QWidget* parent = nullptr);

    ~SecurePairingIncomingDialog() override = default;

    void setValidateFn(ValidateFn fn);

    QString getUserText() const;

    bool timedOut() const { return m_timedOut; }

private slots:
    void onTryPair();
    void onCancel();
    void onToggleShow(bool checked);
    void onTick();

private:
    void setupUi();
    void updateCountdown();

private:
    QString m_peerDisplayName;
    QString m_peerIp;
    QString m_peerUuid;
    QString m_peerFingerprintDisplay;
    QString m_localFingerprintDisplay;
    uint32_t m_timeoutMs;

    bool m_timedOut{false};

    ValidateFn m_validateFn;

    // UI
    QLabel* m_titleLabel{nullptr};
    QLabel* m_detailsLabel{nullptr};
    QLabel* m_countdownLabel{nullptr};
    QLineEdit* m_inputEdit{nullptr};
    QCheckBox* m_showCheck{nullptr};
    QLabel* m_hintLabel{nullptr};
    QDialogButtonBox* m_buttonBox{nullptr};
    QPushButton* m_pairButton{nullptr};
    QPushButton* m_cancelButton{nullptr};

    QTimer* m_timer{nullptr};
    qint64 m_deadlineMsSinceEpoch{0};
};

#endif  // EXOSEND_QTUI_SECUREPAIRINGINCOMINGDIALOG_H

