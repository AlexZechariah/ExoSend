/**
 * @file MainWindow.h
 * @brief Main application window for ExoSend GUI
 *
 * This file defines the main window class that coordinates
 * all GUI components and core services for the ExoSend application.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_MAINWINDOW_H
#define EXOSEND_QTUI_MAINWINDOW_H

#include <QMainWindow>
#include <QListView>
#include <QLabel>
#include "exosend/QtUi/DragDropListView.h"
#include "exosend/PairingPromptLimiter.h"
#include <QSplitter>
#include <QMenuBar>
#include <QStatusBar>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QPushButton>
#include <QProgressBar>
#include <QTimer>
#include <QMouseEvent>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <condition_variable>

// Forward declarations
class SettingsManager;
class PeerListModel;
class TransferListModel;
class TrayIcon;
class SettingsDialog;
class IncomingTransferDialog;
class CloseWarningDialog;

namespace ExoSend {
class DiscoveryService;
class TransferServer;
class TransferQueueManager;
}

/**
 * @class MainWindow
 * @brief Main application window for ExoSend
 *
 * This is the primary GUI window that:
 * - Displays discovered peers
 * - Shows active and completed transfers
 * - Handles drag-and-drop file transfer
 * - Integrates with system tray
 * - Persists settings
 *
 * Architecture:
 * - Owns all GUI models and core services
 * - Uses Qt signals/slots for event handling
 * - Coordinates between UI and backend
 *
 * Thread Safety:
 * - All GUI operations on main thread
 * - Core services run on worker threads
 * - Qt queued connections ensure thread safety
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param settings SettingsManager instance (will be owned)
     * @param parent Parent widget
     *
     * The SettingsManager pointer is owned by MainWindow.
     * All other services are created internally.
     */
    explicit MainWindow(SettingsManager* settings, QWidget* parent = nullptr);

    /**
     * @brief Destructor
     *
     * Stops all services and saves settings.
     */
    ~MainWindow() override;

protected:
    /**
     * @brief Handle window close event
     * @param event Close event
     *
     * Overrides default behavior to minimize to tray
     * instead of closing application.
     */
    void closeEvent(QCloseEvent* event) override;

    /**
     * @brief Handle window state change event
     * @param event State change event
     *
     * Handles minimization to tray.
     */
    void changeEvent(QEvent* event) override;

    /**
     * @brief Handle mouse press events for logging
     * @param event Mouse event
     */
    void mousePressEvent(QMouseEvent* event) override;

private slots:
    // ========================================================================
    // File Menu
    // ========================================================================

    /**
     * @brief Open settings dialog
     */
    void onOpenSettings();

    /**
     * @brief Exit application
     */
    void onExit();

    /**
     * @brief Sync display name from settings to DiscoveryService
     *
     * This ensures the DiscoveryService broadcasts the user's configured
     * display name instead of the system hostname.
     */
    void syncDisplayNameToDiscovery();

    // ========================================================================
    // Discovery Events
    // ========================================================================

    /**
     * @brief Called when a new peer is discovered
     * @param peerName Display name of the new peer
     */
    void onPeerDiscovered(const QString& peerName);

    /**
     * @brief Called when a peer times out
     * @param peerName Display name of peer
     */
    void onPeerRemoved(const QString& peerName);

    /**
     * @brief Handle double-click on peer in list
     * @param index Model index of clicked peer
     *
     * Shows feedback in status bar about selected peer.
     */
    void onPeerDoubleClicked(const QModelIndex& index);

    /**
     * @brief Handle single-click on peer in list
     * @param index Model index of clicked peer
     *
     * Shows feedback in status bar about selected peer.
     */
    void onPeerClicked(const QModelIndex& index);

    /**
     * @brief Handle files dropped on peer list
     * @param urls List of dropped file URLs
     */
    void onFilesDropped(const QList<QUrl>& urls);

    // ========================================================================
    // Transfer Events
    // ========================================================================

    /**
     * @brief Called when incoming transfer is received
     * @param peerName Sender's display name
     * @param filename File name
     * @param fileSize File size in bytes
     */
    void onIncomingTransfer(const QString& peerName, const QString& filename,
                           qint64 fileSize);

    /**
     * @brief Called when transfer makes progress
     * @param sessionId Session ID
     * @param bytes Bytes transferred
     * @param total Total bytes
     * @param speed Speed (bytes/sec)
     * @param eta ETA (seconds)
     */
    void onTransferProgress(const QString& sessionId, qint64 bytes,
                           qint64 total, double speed, qint64 eta);

    /**
     * @brief Called when transfer completes
     * @param sessionId Session ID
     */
    void onTransferCompleted(const QString& sessionId);

    /**
     * @brief Called when transfer fails
     * @param sessionId Session ID
     * @param error Error message
     */
    void onTransferFailed(const QString& sessionId, const QString& error);

    // ========================================================================
    // UI Updates
    // ========================================================================

    /**
     * @brief Update status bar with current state
     */
    void updateStatusBar();

    /**
     * @brief Update transfer summary label
     */
    void updateTransferSummary();

private:
    /**
     * @brief Initialize the user interface
     */
    void setupUi();

    /**
     * @brief Create menu bar
     */
    void createMenuBar();

    /**
     * @brief Create toolbar (optional)
     */
    void createToolBar();

    /**
     * @brief Create status bar
     */
    void createStatusBar();

    /**
     * @brief Connect signals/slots between components
     */
    void connectSignals();

    /**
     * @brief Initialize core services
     * @return true if successful, false otherwise
     */
    bool initializeServices();

    /**
     * @brief Stop all core services
     */
    void stopServices();

    /**
     * @brief Perform a factory reset (settings + trust) and restart ExoSend.
     *
     * This clears trusted peers, per-peer auto-accept preferences, and resets
     * general settings to defaults (while keeping UUID and TLS cert identity).
     */
    void performFactoryReset(bool removeFirewallRules);

    /**
     * @brief Check for firewall issues
     * @return true if no issues, false if firewall may be blocking
     */
    bool checkFirewall();

    /**
     * @brief Show firewall blocked dialog
     */
    void showFirewallDialog();

    // ========================================================================
    // Security Methods
    // ========================================================================

    /**
     * @brief Handle pending incoming transfer (shows dialog)
     * @param clientIp Sender's IP address
     * @param peerName Best-effort display name (for UX only)
     * @param peerUuid Sender device UUID (identity key for trust and auto-accept)
     * @param peerPort Sender's advertised TCP port (for display)
     * @param peerFingerprintSha256Hex Peer TLS certificate fingerprint (canonical hex)
     * @param filename File name
     * @param fileSize File size in bytes
     * @param pendingSessionId Pending session ID
     * @return true if user accepted, false if rejected
     */
    bool handlePendingIncomingTransfer(
        const QString& clientIp,
        const QString& peerName,
        const QString& peerUuid,
        quint16 peerPort,
        const QString& peerFingerprintSha256Hex,
        const QString& filename,
        qint64 fileSize,
        const QString& pendingSessionId
    );

    /**
     * @brief Perform secure pairing with a peer (PAIR_REQ/PAIR_RESP over TLS).
     *
     * Pairing uses an out-of-band shared secret represented as a 12-word phrase,
     * bound to the TLS channel binding (RFC 9266 tls-exporter) for confirmation.
     *
     * On success, this pins the peer certificate fingerprint in SettingsManager.
     *
     * @param peerUuid Peer UUID from discovery.
     * @param peerName Display name (UX only).
     * @param peerIp Peer IP address.
     * @param peerPort Peer TCP port.
     * @param outPinnedFingerprint Output pinned fingerprint (canonical SHA-256 hex).
     * @return true if pairing succeeded and peer is now pinned.
     */
    bool pairPeerSecurely(
        const QString& peerUuid,
        const QString& peerName,
        const QString& peerIp,
        quint16 peerPort,
        QString& outPinnedFingerprint
    );

    /**
     * @brief Validate download path for security
     * @param path Path to validate
     * @return true if path is safe and valid
     */
    bool validateDownloadPath(const QString& path);

    /**
     * @brief Check if path contains traversal sequences
     * @param path Path to check
     * @return true if path is safe (no traversal)
     */
    bool isPathTraversalSafe(const QString& path);

private:
    // ========================================================================
    // Core Services (owned)
    // ========================================================================
    std::unique_ptr<SettingsManager> m_settings;
    std::unique_ptr<ExoSend::DiscoveryService> m_discovery;
    std::unique_ptr<ExoSend::TransferServer> m_transferServer;
    std::unique_ptr<ExoSend::TransferQueueManager> m_queueManager;

    // ========================================================================
    // GUI Components (owned)
    // ========================================================================
    PeerListModel* m_peerModel;       ///< Peer list model
    TransferListModel* m_transferModel; ///< Transfer list model
    TrayIcon* m_trayIcon;             ///< System tray icon

    // UI Widgets
    QSplitter* m_splitter;            ///< Main splitter (peers | transfers)
    DragDropListView* m_peerListView; ///< Peer list view with drag-drop support
    QListView* m_transferListView;    ///< Transfer list view
    QWidget* m_peerListWidget;        ///< Peer list container (for drag-drop)
    QLabel* m_statusLabel;            ///< Status bar label (transient messages)
    QLabel* m_portInfoLabel;          ///< Port info label (Discovery: UDP N | Transfer: TCP M)
    QLabel* m_networkWarningLabel;    ///< Warning icon shown when on a Public network
    QLabel* m_peerCountLabel;         ///< Peer count label (permanent)
    QLabel* m_transferSummaryLabel;   ///< Transfer summary label

    // Menu actions
    QAction* m_settingsAction;
    QAction* m_exitAction;
    QAction* m_aboutAction;

    // State
    std::atomic<bool> m_closing{false}; ///< True if closing (not minimizing to tray) - Thread-safe!
    QTimer* m_peerRefreshTimer;       ///< Timer for periodic peer list refresh
    QString m_selectedPeerUuid;       ///< Persist selected peer UUID across model resets
    mutable std::mutex m_selectedPeerUuidMutex; ///< Protect m_selectedPeerUuid from concurrent access

    // ========================================================================
    // Pending Transfer (for security validation)
    // ========================================================================

    /**
     * @struct PendingTransfer
     * @brief Stores info about a pending incoming transfer
     */
    struct PendingTransfer {
        QString clientIp;
        QString filename;
        qint64 fileSize;
        QString pendingSessionId;  // Temporary session ID for promise tracking
    };

    PendingTransfer m_pendingTransfer;     ///< Current pending transfer
    mutable std::mutex m_pendingTransferMutex; ///< Protects m_pendingTransfer from concurrent access

    // Session tracking for GUI updates (prevents race conditions)
    std::unordered_map<std::string, PendingTransfer> m_pendingSessions;
    std::mutex m_pendingSessionsMutex;

    // ========================================================================
    // Pending Transfer Synchronization (safety)
    // ========================================================================
    // Condition variable and mutex for synchronizing pending transfer decision
    // These are member variables (not local) to ensure they live long enough
    // for the queued lambda to access them safely.
    std::condition_variable m_pendingTransferCV;
    std::mutex m_pendingTransferCVMutex;
    bool m_pendingTransferDecisionReady = false;
    bool m_pendingTransferAccepted = false;

    // Status update timer for peer indicators
    QTimer* m_statusUpdateTimer; ///< Timer for updating peer status indicators

    // Note: Completion tracking to prevent duplicate callbacks
    std::unordered_set<std::string> m_completedSessions;  ///< Track completed sessions
    std::mutex m_completedSessionsMutex;  ///< Protects m_completedSessions

    // Cleanup timer for completed sessions tracker
    QTimer* m_cleanupTimer; ///< Timer for cleaning up completed sessions tracker

    // ========================================================================
    // Security: Pairing dialog rate-limiter (v0.3.0)
    // ========================================================================
    ExoSend::PairingPromptLimiter m_pairingLimiter; ///< Prevents pairing dialog flooding

signals:
    /**
     * @brief Signal to clean up completed sessions tracker
     */
    void cleanupCompletedSessions();
};

#endif // EXOSEND_QTUI_MAINWINDOW_H
