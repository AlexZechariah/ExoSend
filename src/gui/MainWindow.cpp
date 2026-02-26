/**
 * @file MainWindow.cpp
 * @brief Main application window implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/MainWindow.h"
#include "exosend/QtUi/SettingsManager.h"
#include "exosend/QtUi/SettingsDialog.h"
#include "exosend/QtUi/CloseWarningDialog.h"
#include "exosend/QtUi/IncomingTransferDialog.h"
#include "exosend/QtUi/PeerListModel.h"
#include "exosend/QtUi/PeerListItemDelegate.h"
#include "exosend/QtUi/TransferListModel.h"
#include "exosend/QtUi/TrayIcon.h"
#include "exosend/QtUi/PlaceholderListView.h"
#include "exosend/config.h"
#include "exosend/PeerInfo.h"
#include "exosend/DiscoveryService.h"
#include "exosend/FileTransfer.h"
#include "exosend/TransferServer.h"
#include "exosend/TransferQueueManager.h"
#include "exosend/TransferHeader.h"
#include "exosend/CertificateManager.h"
#include "exosend/IncomingTransferPolicy.h"
#include "exosend/PairingConfirm.h"
#include "exosend/PairingSecret.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"
#include "exosend/Debug.h"
#include "exosend/ThreadSafeLog.h"
#include "exosend/AppPaths.h"
#include "exosend/FingerprintUtils.h"
#ifdef _WIN32
#include "exosend/WindowsAcl.h"
#endif
// Qt logging category removed - was causing DBG_PRINTEXCEPTION
// Use LogCrash() macro (ThreadSafeLog) instead
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QHeaderView>
#include <QFileInfo>
#include <QTimer>
#include <QThread>
#include <QPointer>
#include <QProcess>
#include <QDebug>
#include <QInputDialog>
#include <iostream>
#include <thread>  // For std::this_thread::get_id()
#include <condition_variable>  // For thread synchronization without Qt BlockingQueuedConnection
#include <chrono>  // For timeout on condition variable wait
#include <fstream>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <netlistmgr.h>
#endif

// ========================================================================
// Crash-Safe File Logging (Release Build Diagnostics)
// ========================================================================

namespace {
    // Thread-safe logging macro - uses ThreadSafeLog for all crash logging
    #define LogCrash(msg) ExoSend::ThreadSafeLog::log(msg)

    static std::filesystem::path crashTracePathFs()
    {
        return ExoSend::AppPaths::crashTraceLogPath();
    }

    static void ensureCrashTracePathSecured(const std::filesystem::path& logPath)
    {
        if (logPath.empty()) {
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(logPath.parent_path(), ec);

        // Best-effort create file so ACL can be applied to the file path.
        std::ofstream f(logPath, std::ios::app);
        f.close();

#ifdef _WIN32
        std::wstring aclErr;
        (void)ExoSend::restrictPathToCurrentUser(logPath.parent_path().wstring(), &aclErr);
        (void)ExoSend::restrictPathToCurrentUser(logPath.wstring(), &aclErr);
#endif
    }
} // anonymous namespace

// ========================================================================
// Helpers
// ========================================================================

#ifdef _WIN32
// Returns true if any connected network is categorised as Public.
// Must be called from the Qt main thread (STA COM apartment, set by QApplication).
// Returns false on any COM failure (fail-safe: do not warn when detection fails).
static bool activeNetworkIsPublic() {
    INetworkListManager* pNLM = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_NetworkListManager, nullptr,
        CLSCTX_ALL, IID_INetworkListManager,
        reinterpret_cast<LPVOID*>(&pNLM));
    if (FAILED(hr) || !pNLM) return false;
    struct Guard { INetworkListManager* p; ~Guard() { if (p) p->Release(); } } g{pNLM};

    IEnumNetworks* pEnum = nullptr;
    hr = pNLM->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &pEnum);
    if (FAILED(hr) || !pEnum) return false;
    struct EnumGuard { IEnumNetworks* p; ~EnumGuard() { if (p) p->Release(); } } eg{pEnum};

    bool foundPublic = false;
    INetwork* pNet = nullptr;
    ULONG fetched = 0;
    while (!foundPublic && pEnum->Next(1, &pNet, &fetched) == S_OK && fetched > 0) {
        NLM_NETWORK_CATEGORY cat;
        if (SUCCEEDED(pNet->GetCategory(&cat)) && cat == NLM_NETWORK_CATEGORY_PUBLIC) {
            foundPublic = true;
        }
        pNet->Release();
        fetched = 0;
    }
    return foundPublic;
}
#endif // _WIN32

// ========================================================================
// Constructor / Destructor
// ========================================================================

MainWindow::MainWindow(SettingsManager* settings, QWidget* parent)
    : QMainWindow(parent)
    , m_settings(settings)  // Takes ownership of settings pointer
    , m_discovery()
    , m_transferServer()
    , m_queueManager()
    , m_peerModel(nullptr)
    , m_transferModel(nullptr)
    , m_trayIcon(nullptr)
    , m_splitter(nullptr)
    , m_peerListView(nullptr)
    , m_transferListView(nullptr)
    , m_peerListWidget(nullptr)
    , m_statusLabel(nullptr)
    , m_transferSummaryLabel(nullptr)
    , m_settingsAction(nullptr)
    , m_exitAction(nullptr)
    , m_aboutAction(nullptr)
    , m_closing{false}  // std::atomic<bool> initialization
    , m_pendingTransferDecisionReady(false)
    , m_pendingTransferAccepted(false)
    , m_cleanupTimer(nullptr)
{
    setWindowTitle(QString("ExoSend - %1").arg(m_settings->getDisplayName()));

    // Set window icon
    setWindowIcon(QIcon(":/assets/icon.png"));
    setMinimumSize(800, 500);

    setupUi();
    connectSignals();

    // Initialize ThreadSafeLog with a pre-computed path BEFORE any worker threads start.
    // This prevents log() from calling Qt APIs from non-Qt threads, and avoids writing
    // crash logs into a shared install directory.
    const auto crashTracePath = crashTracePathFs();
    ensureCrashTracePathSecured(crashTracePath);
    ExoSend::ThreadSafeLog::initialize(crashTracePath);
    LogCrash("=== ExoSend START ===");

    // Initialize core services
    if (!initializeServices()) {
        QMessageBox::critical(this, "Initialization Error",
                            "Failed to initialize core services. "
                            "The application may not function correctly.");
    }

    LogCrash("MainWindow constructed successfully");

    updateStatusBar();
}

MainWindow::~MainWindow()
{
    LogCrash("MainWindow destructor called");
    LogCrash("=== NORMAL SHUTDOWN ===");
    stopServices();
}

// ========================================================================
// Window Events
// ========================================================================

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_closing.load(std::memory_order_relaxed)) {
        // Really closing - save settings and accept
        m_settings->setWindowGeometry(saveGeometry());
        event->accept();
        return;
    }

    // Note: Protect against closing during active transfers
    // This prevents the application from exiting while transfers are in progress
    if (m_transferModel) {
        int active, completed;
        m_transferModel->getTransferCounts(active, completed);
        if (active > 0) {
            event->ignore();
            m_statusLabel->setText("Cannot close during active transfer");
            return;
        }
    }

    // Check if we should show close warning
    if (m_trayIcon && m_trayIcon->isVisible() && m_settings->getShowCloseWarning()) {
        CloseWarningDialog dlg(this);
        if (dlg.exec() == QDialog::Accepted) {
            // Only disable if user explicitly checked the checkbox
            if (dlg.isDoNotShowAgainChecked()) {
                m_settings->setShowCloseWarning(false);
            }
        }
    }

    // Minimize to tray instead
    if (m_trayIcon && m_trayIcon->isVisible()) {
        hide();
        event->ignore();
        m_trayIcon->showMessage("ExoSend", "Application minimized to tray");
    } else {
        // No tray icon - actually close
        m_closing.store(true, std::memory_order_relaxed);
        m_settings->setWindowGeometry(saveGeometry());
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);

    if (event->type() == QEvent::WindowStateChange) {
        if (isMinimized() && m_trayIcon && m_trayIcon->isVisible()) {
            // Hide when minimized (go to tray)
            QTimer::singleShot(0, this, [this]() {
                // Note: Validate before accessing members
                if (!QCoreApplication::instance() || m_closing.load(std::memory_order_acquire)) {
                    return;
                }
                if (m_trayIcon && isMinimized()) {
                    hide();
                }
            });
        }
    }
}

// ========================================================================
// Mouse Events
// ========================================================================

void MainWindow::mousePressEvent(QMouseEvent* event)
{
    QString button;
    switch (event->button()) {
        case Qt::LeftButton: button = "Left"; break;
        case Qt::RightButton: button = "Right"; break;
        case Qt::MiddleButton: button = "Middle"; break;
        default: button = "Unknown"; break;
    }

    QMainWindow::mousePressEvent(event);
}

// ========================================================================
// File Menu
// ========================================================================

void MainWindow::onOpenSettings()
{
    SettingsDialog dlg(m_settings.get(), this);
    if (dlg.exec() == QDialog::Accepted) {
        // Settings already saved by dialog
        // Update window title with new display name
        setWindowTitle(QString("ExoSend - %1").arg(m_settings->getDisplayName()));
    }
}

void MainWindow::onExit()
{
    LogCrash("=== onExit START ===");

    // For explicit Exit/Quit, prompt if transfers are still active.
    if (m_transferModel) {
        int active = 0, completed = 0;
        m_transferModel->getTransferCounts(active, completed);
        Q_UNUSED(completed);
        LogCrash("  Active transfers: " + QString::number(active));

        if (active > 0) {
            QMessageBox::StandardButton response = QMessageBox::question(
                this,
                "Quit ExoSend",
                QString("There %1 %2 active transfer%3.\n\n"
                        "Quit now and cancel %4?")
                    .arg(active == 1 ? "is" : "are")
                    .arg(active)
                    .arg(active == 1 ? "" : "s")
                    .arg(active == 1 ? "it" : "them"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No
            );

            if (response != QMessageBox::Yes) {
                m_statusLabel->setText("Exit cancelled");
                LogCrash("  onExit cancelled by user");
                return;
            }
        }
    }

    const bool wasClosing = m_closing.exchange(true, std::memory_order_acq_rel);
    if (wasClosing) {
        LogCrash("  onExit ignored: shutdown already in progress");
        return;
    }

    m_settings->setWindowGeometry(saveGeometry());
    LogCrash("  onExit: m_closing set true");

    if (m_trayIcon) {
        m_trayIcon->hide();
        LogCrash("  onExit: tray icon hidden");
    }

    // Hide the window immediately so tray and window disappear together.
    // Defer blocking shutdown work to the next event-loop turn so hide/close
    // can be processed before stopServices() starts joining worker threads.
    hide();
    close();
    LogCrash("  onExit: main window close requested");

    QTimer::singleShot(0, this, [this]() {
        LogCrash("  onExit(deferred): stopping services");
        stopServices();
        LogCrash("  onExit(deferred): services stopped");

        LogCrash("  onExit(deferred): dispatching QApplication::quit()");
        QApplication::quit();
    });
}

// ========================================================================
// Settings Sync
// ========================================================================

void MainWindow::syncDisplayNameToDiscovery()
{
    if (m_discovery && m_settings) {
        m_discovery->setDisplayName(m_settings->getDisplayName().toStdString());
    }
}

// ========================================================================
// Discovery Events
// ========================================================================

void MainWindow::onPeerDiscovered(const QString& peerName)
{
    updateStatusBar();

    if (m_trayIcon) {
        m_trayIcon->showMessage("Peer Discovered",
                              QString("%1 has joined the network").arg(peerName));
    }
}

void MainWindow::onPeerRemoved(const QString& peerName)
{
    updateStatusBar();
}

void MainWindow::onPeerDoubleClicked(const QModelIndex& index)
{
    if (!index.isValid()) {
        return;
    }

    // Save selected peer UUID BEFORE any model operations (thread-safe)
    {
        std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
        m_selectedPeerUuid = index.data(PeerListModel::UuidRole).toString();
    }

    // Explicitly maintain selection state
    QItemSelectionModel* selectionModel = m_peerListView->selectionModel();
    selectionModel->select(index, QItemSelectionModel::Select | QItemSelectionModel::ClearAndSelect);

    QString peerName = index.data(PeerListModel::NameRole).toString();
    QString peerIp = index.data(PeerListModel::IpRole).toString();

    // Show selection feedback in status bar (avoid duplicating drag/drop hints).
    m_statusLabel->setText(QString("Selected: %1 (%2)")
                          .arg(peerName).arg(peerIp));
}

void MainWindow::onPeerClicked(const QModelIndex& index)
{
    if (!index.isValid()) {
        // Clear selection when clicking empty space (thread-safe)
        {
            std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
            m_selectedPeerUuid.clear();
        }
        m_statusLabel->setText("Ready");
        return;
    }

    // Check if peer is inactive
    bool isActive = index.data(PeerListModel::IsActiveRole).toBool();

    if (!isActive) {
        // Show popup dialog for inactive peer
        int timeRemaining = index.data(PeerListModel::TimeRemainingRole).toInt();
        QString peerName = index.data(PeerListModel::NameRole).toString();

        // Clear selection (don't allow selecting inactive peers)
        QItemSelectionModel* selectionModel = m_peerListView->selectionModel();
        selectionModel->clearSelection();

        {
            std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
            m_selectedPeerUuid.clear();
        }

        QMessageBox::information(this, "Peer Offline",
            QString("%1 is offline.\n\nPlease wait %2 second(s) for the peer to time out.")
            .arg(peerName).arg(timeRemaining));

        m_statusLabel->setText("Ready");
        return;
    }

    // Save selected peer UUID BEFORE any model operations (thread-safe)
    {
        std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
        m_selectedPeerUuid = index.data(PeerListModel::UuidRole).toString();
    }

    // Explicitly maintain selection state
    QItemSelectionModel* selectionModel = m_peerListView->selectionModel();
    selectionModel->select(index, QItemSelectionModel::Select | QItemSelectionModel::ClearAndSelect);

    QString peerName = index.data(PeerListModel::NameRole).toString();
    QString peerIp = index.data(PeerListModel::IpRole).toString();

    // Show selection feedback in status bar (avoid duplicating drag/drop hints).
    m_statusLabel->setText(QString("Selected: %1 (%2)")
                          .arg(peerName).arg(peerIp));
}

// ========================================================================
// Transfer Events
// ========================================================================

void MainWindow::onIncomingTransfer(const QString& peerName, const QString& filename,
                                   qint64 fileSize)
{
    // Note: This legacy method should not be called
    // The new implementation uses handlePendingIncomingTransfer() instead
    // If this executes, it indicates a signal connection issue or wrong code path
    LogCrash("ERROR: Legacy onIncomingTransfer called - this indicates a bug!");
    LogCrash("  Peer: " + peerName.toStdString() + " File: " + filename.toStdString() + " Size: " + QString::number(fileSize).toStdString());

    // Do not create dialog here - we might be on wrong thread which causes crashes
    // The new implementation uses handlePendingIncomingTransfer with proper threading

    // Only update status label if we're on main thread and widget is valid
    if (QThread::currentThread() == this->thread() &&
        m_statusLabel &&
        !m_closing.load(std::memory_order_acquire)) {
        m_statusLabel->setText("ERROR: Invalid code path - restart ExoSend");
        m_statusLabel->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    }

    Q_UNUSED(peerName);
    Q_UNUSED(filename);
    Q_UNUSED(fileSize);
}

void MainWindow::onTransferProgress(const QString& sessionId, qint64 bytes,
                                   qint64 total, double speed, qint64 eta)
{
    Q_UNUSED(sessionId);
    Q_UNUSED(bytes);
    Q_UNUSED(total);
    Q_UNUSED(speed);
    Q_UNUSED(eta);
    // Progress is handled via TransferListModel
}

void MainWindow::onTransferCompleted(const QString& sessionId)
{
    Q_UNUSED(sessionId);
    updateTransferSummary();
    m_statusLabel->setText("Transfer completed");
}

void MainWindow::onTransferFailed(const QString& sessionId, const QString& error)
{
    Q_UNUSED(sessionId);
    updateTransferSummary();
    m_statusLabel->setText("Transfer failed: " + error);

    if (m_trayIcon) {
        m_trayIcon->showMessage("Transfer Failed", error);
    }
}

// ========================================================================
// UI Updates
// ========================================================================

void MainWindow::updateStatusBar()
{
    if (m_peerCountLabel && m_peerModel) {
        int peerCount = m_peerModel->getPeerCount();
        m_peerCountLabel->setText(QString("Peers: %1").arg(peerCount));
    }
}

void MainWindow::updateTransferSummary()
{
    if (m_transferModel) {
        int active, completed;
        m_transferModel->getTransferCounts(active, completed);
        m_transferSummaryLabel->setText(
            QString("Active: %1 | Completed: %2").arg(active).arg(completed)
        );
    }
}

// ========================================================================
// UI Setup
// ========================================================================

void MainWindow::setupUi()
{
    // Create central widget
    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Create main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(6, 6, 6, 6);
    mainLayout->setSpacing(6);

    // Create splitter for peers and transfers
    m_splitter = new QSplitter(Qt::Horizontal, centralWidget);

    // Create peer list
    m_peerListWidget = new QWidget();
    m_peerListWidget->setAcceptDrops(true);
    QVBoxLayout* peerLayout = new QVBoxLayout(m_peerListWidget);
    peerLayout->setContentsMargins(0, 0, 0, 0);

    QLabel* peerLabel = new QLabel("Discovered Peers");
    peerLabel->setStyleSheet("font-weight: bold;");
    peerLayout->addWidget(peerLabel);

    m_peerListView = new DragDropListView();
    m_peerListView->setToolTip("Select a peer, then drag files here to send.");

    // Add visual selection styling
    m_peerListView->setStyleSheet(
        "QListView {"
        "   border: 1px solid #cccccc;"
        "   background-color: white;"
        "}"
        "QListView::item {"
        "   padding: 5px;"
        "   border-radius: 3px;"
        "}"
        "QListView::item:hover {"
        "   background-color: #e8f4fd;"
        "}"
        "QListView::item:selected {"
        "   background-color: #0078d4;"
        "   color: white;"
        "}"
    );
    m_peerListView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_peerListView->setSelectionBehavior(QAbstractItemView::SelectRows);

    // Set custom delegate for status indicators
    m_peerListView->setItemDelegate(new PeerListItemDelegate(this));

    peerLayout->addWidget(m_peerListView);

    m_splitter->addWidget(m_peerListWidget);

    // Create transfer list
    QWidget* transferWidget = new QWidget();
    QVBoxLayout* transferLayout = new QVBoxLayout(transferWidget);
    transferLayout->setContentsMargins(0, 0, 0, 0);

    QLabel* transferLabel = new QLabel("File Transfers");
    transferLabel->setStyleSheet("font-weight: bold;");
    transferLayout->addWidget(transferLabel);

    m_transferListView = new PlaceholderListView("No transfers yet");
    transferLayout->addWidget(m_transferListView);

    // Transfer summary
    m_transferSummaryLabel = new QLabel("Active: 0 | Completed: 0");
    m_transferSummaryLabel->setStyleSheet("color: gray; font-size: 10pt;");
    transferLayout->addWidget(m_transferSummaryLabel);

    m_splitter->addWidget(transferWidget);

    // Set initial splitter sizes (40% peers, 60% transfers)
    m_splitter->setStretchFactor(0, 4);
    m_splitter->setStretchFactor(1, 6);

    mainLayout->addWidget(m_splitter);

    // Create menu bar
    createMenuBar();

    // Create status bar
    createStatusBar();
}

void MainWindow::createMenuBar()
{
    QMenuBar* menuBar = new QMenuBar(this);

    // File menu
    QMenu* fileMenu = menuBar->addMenu("&File");

    m_settingsAction = fileMenu->addAction("&Settings...");
    m_settingsAction->setShortcut(QKeySequence("Ctrl+,"));
    connect(m_settingsAction, &QAction::triggered, this, &MainWindow::onOpenSettings);

    fileMenu->addSeparator();

    m_exitAction = fileMenu->addAction("E&xit");
    m_exitAction->setShortcut(QKeySequence("Ctrl+Q"));
    connect(m_exitAction, &QAction::triggered, this, &MainWindow::onExit);

    // Help menu
    QMenu* helpMenu = menuBar->addMenu("&Help");

    m_aboutAction = helpMenu->addAction("&About ExoSend");
    connect(m_aboutAction, &QAction::triggered, [this]() {
        QMessageBox::about(this, "About ExoSend",
                          "ExoSend v0.3.0\n\n"
                          "Decentralized Local File Transfer\n"
                          "Built with Qt 6 and Modern C++\n\n"
                          "(c) 2026 ExoSend Project");
    });

    setMenuBar(menuBar);
}

void MainWindow::createToolBar()
{
}

void MainWindow::createStatusBar()
{
    QStatusBar* statusBar = new QStatusBar(this);

    // Transient status messages (left side, e.g. "Ready", "Sending...")
    m_statusLabel = new QLabel("Ready");
    statusBar->addWidget(m_statusLabel);

    // Dynamic port info — updated after services start (permanent, left of peers)
    m_portInfoLabel = new QLabel();
    m_portInfoLabel->setStyleSheet("color: gray; font-size: 10pt;");
    statusBar->addPermanentWidget(m_portInfoLabel);

    // Network warning icon — shown only when connected to a Public network
    m_networkWarningLabel = new QLabel("\u26a0");
    m_networkWarningLabel->setStyleSheet(
        "color: #cc7700; font-weight: bold; padding: 0 4px;");
    m_networkWarningLabel->setToolTip(
        "Warning: Connected to a Public network.\n"
        "ExoSend firewall rules are installed for Private/Domain networks only.\n"
        "Discovery and incoming transfers may be blocked by Windows Firewall.\n\n"
        "Fix: Change this network profile to Private in Windows settings.");
    m_networkWarningLabel->setVisible(false);
    statusBar->addPermanentWidget(m_networkWarningLabel);

    // Peer count (permanent)
    m_peerCountLabel = new QLabel("Peers: 0");
    m_peerCountLabel->setStyleSheet("color: gray; font-size: 10pt;");
    statusBar->addPermanentWidget(m_peerCountLabel);

    setStatusBar(statusBar);
}

// ========================================================================
// Signal Connections
// ========================================================================

void MainWindow::connectSignals()
{
    // Peer model signals
    if (m_peerModel) {
        connect(m_peerModel, &PeerListModel::peerCountChanged,
                this, &MainWindow::updateStatusBar);
        connect(m_peerModel, &PeerListModel::peerDiscovered,
                this, &MainWindow::onPeerDiscovered);
        connect(m_peerModel, &PeerListModel::peerRemoved,
                this, &MainWindow::onPeerRemoved);
    }

    // Peer list view interactions
    connect(m_peerListView, &QListView::clicked,
            this, &MainWindow::onPeerClicked);
    connect(m_peerListView, &QListView::doubleClicked,
            this, &MainWindow::onPeerDoubleClicked);

    // Drag-drop signal
    connect(m_peerListView, &DragDropListView::filesDropped,
            this, &MainWindow::onFilesDropped);

    // Transfer model signals are now connected in initializeServices()
    // after m_transferModel is created (see initializeServices line ~575)
}

// ========================================================================
// Service Initialization
// ========================================================================

bool MainWindow::initializeServices()
{
    // Create DiscoveryService FIRST (before PeerListModel)
    m_discovery = std::make_unique<ExoSend::DiscoveryService>();

    // Ensure discovery uses the persisted device UUID for stable identity.
    if (m_settings && m_discovery) {
        m_discovery->setDeviceUuid(m_settings->getDeviceUuid().toStdString());
    }

    // Ensure TLS certificate exists on startup (v0.2.0+ requirement).
    {
        std::string certError;
        if (!ExoSend::CertificateManager::ensureCertificateExists(certError)) {
            QMessageBox::critical(
                this,
                "TLS Certificate Error",
                QString("Failed to initialize TLS certificate.\n\nError: %1").arg(QString::fromStdString(certError)),
                QMessageBox::Ok
            );
            return false;
        }

        std::string fpError;
        const std::string certPath = ExoSend::CertificateManager::getCertFilePath();
        const std::string fp = ExoSend::CertificateManager::getCertificateFingerprint(certPath, fpError);
        if (!fp.empty()) {
            m_discovery->setCertificateFingerprintSha256Hex(fp);
        }
    }

    // Sync display name from settings
    syncDisplayNameToDiscovery();

    // NOTE: Discovery will start AFTER the transfer server so we know the TCP
    // port to advertise in beacons. See the block below m_transferServer->start().

    // Create peer model WITH DiscoveryService and SettingsManager pointers
    m_peerModel = new PeerListModel(m_discovery.get(), m_settings.get(), this);
    m_peerListView->setModel(m_peerModel);

    // Restore selection after model resets (e.g., from refreshPeerList)
    // Note: Use QTimer::singleShot to avoid deadlock:
    // - refreshPeerList() holds m_mutex while emitting modelReset
    // - We defer the restore until after refreshPeerList() releases its lock
    connect(m_peerModel, &QAbstractListModel::modelReset, this, [this]() {
        QString currentUuid;
        {
            std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
            currentUuid = m_selectedPeerUuid;
        }
        if (currentUuid.isEmpty()) {
            return;  // No selection to restore
        }

        // Defer selection restore to next event loop iteration
        // to avoid deadlock: refreshPeerList() holds m_mutex while emitting modelReset,
        // and findPeerByUuid() needs to acquire the same mutex
        QTimer::singleShot(0, this, [this, currentUuid]() {
            // Note: Validate before accessing members
            if (!QCoreApplication::instance() ||
                m_closing.load(std::memory_order_acquire) ||
                !m_peerModel || !m_transferModel) {
                return;  // Object being destroyed or models invalid
            }

            QModelIndex restoredIndex = m_peerModel->findPeerByUuid(currentUuid);

            if (restoredIndex.isValid()) {
                // Restore selection
                QItemSelectionModel* selectionModel = m_peerListView->selectionModel();
                if (selectionModel) {
                    selectionModel->select(restoredIndex,
                                          QItemSelectionModel::Select | QItemSelectionModel::ClearAndSelect);

                    // Update status bar to reflect restored selection
                    QString peerName = restoredIndex.data(PeerListModel::NameRole).toString();
                    QString peerIp = restoredIndex.data(PeerListModel::IpRole).toString();

                    // Re-check m_statusLabel before use
                    if (m_statusLabel) {
                        m_statusLabel->setText(QString("Selected: %1 (%2)")
                                              .arg(peerName).arg(peerIp));
                    }
                }
            } else {
                // Peer no longer exists (removed from network), clear saved UUID (thread-safe)
                {
                    std::lock_guard<std::mutex> lock(m_selectedPeerUuidMutex);
                    m_selectedPeerUuid.clear();
                }
                // Re-check m_statusLabel before use
                if (m_statusLabel) {
                    m_statusLabel->setText("Ready");
                }
            }
        });
    });

    // Create transfer model
    m_transferModel = new TransferListModel(this);
    m_transferListView->setModel(m_transferModel);

    // Note: Connect transfer model signals AFTER model creation
    // (Previously in connectSignals() which was called before model existed)
    connect(m_transferModel, &TransferListModel::transferCountChanged,
            this, &MainWindow::updateTransferSummary);
    connect(m_transferModel, &TransferListModel::transferFinished,
            this, [this](const QString& filename, bool success) {
                // Trace: Log transfer completion
                LogCrash("=== transferFinished SIGNAL START ===");
                LogCrash("  Filename: " + filename);
                LogCrash("  Success: " + QString(success ? "true" : "false"));

                // Note: Validate MainWindow state before accessing members
                // This prevents crash when transfer completes during application shutdown
                if (!QCoreApplication::instance()) {
                    LogCrash("  EARLY RETURN: Application shutting down");
                    return;  // Application shutting down
                }
                if (m_closing.load(std::memory_order_acquire)) {
                    LogCrash("  EARLY RETURN: MainWindow closing");
                    return;  // MainWindow closing
                }
                if (!m_statusLabel) {
                    LogCrash("  EARLY RETURN: Widget destroyed");
                    return;  // Widget destroyed
                }

                m_statusLabel->setText(success ? "Completed: " + filename : "Failed: " + filename);
                LogCrash("=== transferFinished SIGNAL END ===");
            });

    // Connect peer model signals to our slots
    connect(m_peerModel, &PeerListModel::peerDiscovered,
            this, &MainWindow::onPeerDiscovered);
    connect(m_peerModel, &PeerListModel::peerRemoved,
            this, &MainWindow::onPeerRemoved);

    // Add timer for periodic peer list refresh
    m_peerRefreshTimer = new QTimer(this);
    m_peerRefreshTimer->setInterval(5000);  // Refresh every 5 seconds (reduced frequency)
    connect(m_peerRefreshTimer, &QTimer::timeout, m_peerModel, &PeerListModel::refreshPeerList);
    m_peerRefreshTimer->start();

    // Add status update timer for peer status indicators
    // This timer is NOW COORDINATED with refresh timer to avoid conflicts
    m_statusUpdateTimer = new QTimer(this);
    m_statusUpdateTimer->setInterval(1000);  // Update every second
    connect(m_statusUpdateTimer, &QTimer::timeout, this, [this]() {
        // Note: Check if model is still valid
        if (!m_peerModel || !m_transferModel) {
            return;
        }

        // Update peer status
        if (m_peerModel) {
            uint32_t timeoutMs = m_settings->getPeerTimeout() * 1000;
            m_peerModel->updatePeerStatuses(timeoutMs);
        }
    });
    m_statusUpdateTimer->start();

    // IMPORTANT: The refresh timer is now slower (5s) than status updates (1s)
    // This reduces the frequency of model resets, minimizing flicker
    // Peer status updates happen every second without model disruption

    // Note: Add cleanup timer for completed sessions tracker
    m_cleanupTimer = new QTimer(this);
    m_cleanupTimer->setInterval(60000);  // Every minute
    connect(m_cleanupTimer, &QTimer::timeout, this, [this]() {
        std::lock_guard<std::mutex> lock(m_completedSessionsMutex);
        if (m_completedSessions.size() > 100) {
            m_completedSessions.clear();
        }
    });
    m_cleanupTimer->start();

    // Create TransferServer (port only)
    m_transferServer = std::make_unique<ExoSend::TransferServer>(
        ExoSend::TCP_PORT_DEFAULT
    );

    // Set download directory from settings
    m_transferServer->setDownloadDir(m_settings->getDownloadPath().toStdString());
    m_transferServer->setMaxIncomingSizeBytes(m_settings->getMaxIncomingSizeBytes());
    m_transferServer->setLocalDeviceUuid(m_settings->getDeviceUuid().toStdString());

    // Set up incoming connection callback
    // Called from a dedicated client thread (spawned by listenerThreadFunc).
    // Blocks the client thread until the user accepts or rejects via the dialog.
    m_transferServer->setIncomingConnectionCallback(
        [this](const std::string& clientIp, const ExoSend::ExoHeader& header,
               const std::string& pendingSessionId,
               const std::string& peerFingerprintSha256Hex) -> bool {

            // Extract transfer information
            QString qClientIp = QString::fromStdString(clientIp);
            QString qFilename = QString::fromStdString(header.getFilename());
            qint64 qFileSize = static_cast<qint64>(header.fileSize);
            QString qPendingSessionId = QString::fromStdString(pendingSessionId);
            QString qPeerFingerprint = QString::fromStdString(peerFingerprintSha256Hex);
            QString qSenderUuid = QString::fromStdString(header.getSenderUuid());

            // Note: Use per-transfer heap-allocated sync primitives instead of
            // shared member variables. This eliminates the race condition when two transfers
            // arrive concurrently (now possible since handleClient() is spawned as a thread).
            // The shared_ptrs keep the objects alive until both the client thread (waiting)
            // and the Qt main thread (signalling) are done with them.
            auto cv       = std::make_shared<std::condition_variable>();
            auto cvMutex  = std::make_shared<std::mutex>();
            auto ready    = std::make_shared<bool>(false);
            auto accepted = std::make_shared<bool>(false);

            // Queue dialog to main thread with QueuedConnection (non-blocking)
            // The lambda captures the shared_ptrs by value so they stay alive.
             QMetaObject::invokeMethod(this,
                [this, qClientIp, qFilename, qFileSize, qPendingSessionId, qPeerFingerprint, qSenderUuid,
                 cv, cvMutex, ready, accepted]() {
                    // Store pending transfer info for the session event callback
                    {
                        std::lock_guard<std::mutex> lock(m_pendingTransferMutex);
                        m_pendingTransfer.clientIp = qClientIp;
                        m_pendingTransfer.filename = qFilename;
                        m_pendingTransfer.fileSize = qFileSize;
                        m_pendingTransfer.pendingSessionId = qPendingSessionId;
                    }

                    // Rate-limit pairing dialogs: reject if another dialog is already showing
                    // or if this peer is within the post-rejection cooldown window.
                    if (!m_pairingLimiter.beginPrompt(qSenderUuid.toStdString())) {
                        ExoSend::ThreadSafeLog::log(
                            "TRUST_RATE_LIMITED peer=" + qSenderUuid.toStdString() +
                            " ip=" + qClientIp.toStdString());
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    // Pairing + pinning (v0.2.0+)
                    // Best-effort display name lookup from current peer model (even if unpaired).
                    QString displayName = qClientIp;
                    quint16 peerPortForDisplay = 0;
                    if (m_peerModel && !qSenderUuid.isEmpty()) {
                        QModelIndex idx = m_peerModel->findPeerByUuid(qSenderUuid);
                        if (idx.isValid()) {
                            displayName = idx.data(PeerListModel::NameRole).toString();
                            peerPortForDisplay = static_cast<quint16>(
                                idx.data(PeerListModel::PortRole).toUInt());
                        }
                    }

                    if (m_settings) {
                        if (qSenderUuid.isEmpty() || qPeerFingerprint.isEmpty()) {
                            ExoSend::ThreadSafeLog::log(
                                "TRUST_REJECTED_NO_IDENTITY ip=" + qClientIp.toStdString());

                            QMessageBox::critical(
                                this,
                                "Untrusted Peer",
                                "Incoming transfer rejected because the peer did not provide a valid identity.",
                                QMessageBox::Ok
                            );

                            m_pairingLimiter.endPrompt(qSenderUuid.toStdString(), false);
                            {
                                std::lock_guard<std::mutex> lock(*cvMutex);
                                *accepted = false;
                                *ready = true;
                            }
                            cv->notify_one();
                            return;
                        }

                        // Format fingerprint for human-readable display (colon-separated).
                        const QString fpDisplay = QString::fromStdString(
                            ExoSend::FingerprintUtils::formatForDisplay(qPeerFingerprint.toStdString()));

                        if (m_settings->isPeerPinned(qSenderUuid)) {
                            const QString expected = m_settings->getPinnedFingerprint(qSenderUuid);
                            if (expected.isEmpty() || expected != qPeerFingerprint) {
                                const QString expectedDisplay = QString::fromStdString(
                                    ExoSend::FingerprintUtils::formatForDisplay(expected.toStdString()));

                                QMessageBox::critical(
                                    this,
                                    "Security Warning: Untrusted Certificate",
                                    "Incoming transfer rejected because the peer certificate fingerprint does not match the pinned value.\n\n"
                                    "This may indicate the peer was reinstalled, or a MITM attempt.\n\n"
                                    "Expected (pinned):\n" + expectedDisplay + "\n\n"
                                    "Actual (peer):\n" + fpDisplay + "\n\n"
                                    "To restore trust, perform secure pairing again using a pairing code."
                                );

                                ExoSend::ThreadSafeLog::log(
                                    "TRUST_MISMATCH_REJECTED peer=" + qSenderUuid.toStdString() +
                                    " session=" + qPendingSessionId.toStdString() +
                                    " expected_fp=" + expected.toStdString().substr(0, 16) + "...");

                                m_pairingLimiter.endPrompt(qSenderUuid.toStdString(), false);
                                {
                                    std::lock_guard<std::mutex> lock(*cvMutex);
                                    *accepted = false;
                                    *ready = true;
                                }
                                cv->notify_one();
                                return;
                            }
                        } else {
                            QMessageBox::information(
                                this,
                                "Unpaired Peer",
                                "Incoming transfer rejected because this peer is not paired yet.\n\n"
                                "For maximum security, ExoSend requires secure pairing (pairing code + TLS channel binding) before accepting transfers.\n\n"
                                "Ask the sender to pair first, then retry the transfer."
                            );

                            ExoSend::ThreadSafeLog::log(
                                "TRUST_REJECTED_UNPAIRED peer=" + qSenderUuid.toStdString() +
                                " ip=" + qClientIp.toStdString());

                            m_pairingLimiter.endPrompt(qSenderUuid.toStdString(), false);
                            {
                                std::lock_guard<std::mutex> lock(*cvMutex);
                                *accepted = false;
                                *ready = true;
                            }
                            cv->notify_one();
                            return;
                        }

                        // Update trust metadata
                        m_settings->updatePeerSeen(qSenderUuid, displayName);
                    }

                    const bool result = handlePendingIncomingTransfer(
                        qClientIp,
                        displayName,
                        qSenderUuid,
                        peerPortForDisplay,
                        qPeerFingerprint,
                        qFilename,
                        qFileSize,
                        qPendingSessionId
                    );
                    m_pairingLimiter.endPrompt(qSenderUuid.toStdString(), result);

                    // Signal the client thread that the decision is ready
                    {
                        std::lock_guard<std::mutex> lock(*cvMutex);
                        *accepted = result;
                        *ready = true;
                    }
                    cv->notify_one();
                },
                Qt::QueuedConnection
            );

            // Block the client thread until the user makes a decision (or timeout)
            std::unique_lock<std::mutex> lock(*cvMutex);
            if (!cv->wait_for(lock, std::chrono::seconds(30),
                [&ready] { return *ready; })) {
                LogCrash("=== pendingTransferCallback TIMEOUT ===");
                LogCrash("Dialog decision timeout - rejecting transfer");
                return false;
            }

            LogCrash("=== pendingTransferCallback After wait ===");
            LogCrash(std::string("  Returning: ") + (*accepted ? "true" : "false"));
            return *accepted;
        }
    );

    // Set up incoming secure pairing callback (PAIR_REQ / PAIR_RESP).
    // Called from TransferServer's client thread when it receives PacketType::PAIR_REQ.
    // The callback queues UI prompting to the Qt thread and blocks until the user approves.
    m_transferServer->setIncomingPairingCallback(
        [this](
            const std::string& clientIp,
            const std::string& clientUuid,
            const std::string& clientFingerprintSha256Hex,
            const std::string& serverUuid,
            const std::string& serverFingerprintSha256Hex,
            const std::array<uint8_t, 32>& tlsExporterChannelBinding,
            const std::array<uint8_t, 32>& clientTag,
            std::array<uint8_t, 32>& outServerTag,
            std::string& errorMsg
        ) -> bool {
            auto cv = std::make_shared<std::condition_variable>();
            auto cvMutex = std::make_shared<std::mutex>();
            auto ready = std::make_shared<bool>(false);
            auto accepted = std::make_shared<bool>(false);
            auto outTag = std::make_shared<std::array<uint8_t, 32>>();
            auto outErr = std::make_shared<std::string>();

            const QString qClientIp = QString::fromStdString(clientIp);
            const QString qClientUuid = QString::fromStdString(clientUuid);
            const QString qClientFp = QString::fromStdString(clientFingerprintSha256Hex);
            const QString qServerUuid = QString::fromStdString(serverUuid);
            const QString qServerFp = QString::fromStdString(serverFingerprintSha256Hex);

            QMetaObject::invokeMethod(this,
                [this, qClientIp, qClientUuid, qClientFp, qServerUuid, qServerFp,
                 tlsExporterChannelBinding, clientTag,
                 cv, cvMutex, ready, accepted, outTag, outErr]() {
                    // Rate-limit pairing dialogs.
                    if (!m_pairingLimiter.beginPrompt(qClientUuid.toStdString())) {
                        ExoSend::ThreadSafeLog::log(
                            "TRUST_RATE_LIMITED peer=" + qClientUuid.toStdString() +
                            " ip=" + qClientIp.toStdString());
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *outErr = "Pairing prompt rate-limited";
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    QString displayName = qClientIp;
                    if (m_peerModel && !qClientUuid.isEmpty()) {
                        QModelIndex idx = m_peerModel->findPeerByUuid(qClientUuid);
                        if (idx.isValid()) {
                            displayName = idx.data(PeerListModel::NameRole).toString();
                        }
                    }

                    if (!m_settings || qClientUuid.isEmpty() || qClientFp.isEmpty() ||
                        qServerUuid.isEmpty() || qServerFp.isEmpty()) {
                        *outErr = "Missing pairing identity fields";
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    const QString clientFpDisplay = QString::fromStdString(
                        ExoSend::FingerprintUtils::formatForDisplay(qClientFp.toStdString()));
                    const QString serverFpDisplay = QString::fromStdString(
                        ExoSend::FingerprintUtils::formatForDisplay(qServerFp.toStdString()));

                    bool ok = false;
                    const QString codeQ = QInputDialog::getText(
                        this,
                        "Secure Pairing Request",
                        "A peer is requesting secure pairing.\n\n"
                        "Peer: " + displayName + "\n"
                        "IP: " + qClientIp + "\n"
                        "UUID: " + qClientUuid + "\n\n"
                        "Peer certificate fingerprint (SHA-256):\n" + clientFpDisplay + "\n\n"
                        "Local certificate fingerprint (SHA-256):\n" + serverFpDisplay + "\n\n"
                        "Enter the secure pairing code shown on the other device:",
                        QLineEdit::Normal,
                        "",
                        &ok
                    );

                    if (!ok) {
                        *outErr = "User cancelled pairing";
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    std::array<uint8_t, 16> secret{};
                    std::string parseErr;
                    if (!ExoSend::PairingSecret::parse128Base32Crockford(codeQ.toStdString(), secret, parseErr)) {
                        QMessageBox::warning(this, "Invalid Pairing Code",
                                             "The pairing code is invalid.\n\n" + QString::fromStdString(parseErr));
                        *outErr = parseErr;
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    std::array<uint8_t, 32> confirmKey{};
                    std::string confirmErr;
                    if (!ExoSend::PairingConfirm::deriveConfirmKey(secret, tlsExporterChannelBinding, confirmKey, confirmErr)) {
                        QMessageBox::critical(this, "Pairing Failed",
                                              "Failed to derive pairing key.\n\n" + QString::fromStdString(confirmErr));
                        *outErr = confirmErr;
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    // Verify the client tag (computed by the requester).
                    if (!ExoSend::PairingConfirm::verifyTag(
                            confirmKey,
                            ExoSend::PairingRole::Client,
                            qClientUuid.toStdString(),
                            qClientFp.toStdString(),
                            qServerUuid.toStdString(),
                            qServerFp.toStdString(),
                            clientTag,
                            confirmErr)) {
                        QMessageBox::critical(this, "Pairing Failed",
                                              "Pairing confirmation failed.\n\n" + QString::fromStdString(confirmErr));
                        *outErr = confirmErr;
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    // Compute the server response tag.
                    if (!ExoSend::PairingConfirm::computeTag(
                            confirmKey,
                            ExoSend::PairingRole::Server,
                            qServerUuid.toStdString(),
                            qServerFp.toStdString(),
                            qClientUuid.toStdString(),
                            qClientFp.toStdString(),
                            *outTag,
                            confirmErr)) {
                        QMessageBox::critical(this, "Pairing Failed",
                                              "Failed to compute pairing response.\n\n" + QString::fromStdString(confirmErr));
                        *outErr = confirmErr;
                        m_pairingLimiter.endPrompt(qClientUuid.toStdString(), false);
                        {
                            std::lock_guard<std::mutex> lock(*cvMutex);
                            *accepted = false;
                            *ready = true;
                        }
                        cv->notify_one();
                        return;
                    }

                    // Pin after cryptographic confirmation succeeded.
                    m_settings->pinPeerFingerprint(qClientUuid, qClientFp, displayName);
                    m_settings->updatePeerSeen(qClientUuid, displayName);

                    ExoSend::ThreadSafeLog::log(
                        "TRUST_PIN peer=" + qClientUuid.toStdString() +
                        " fp=" + qClientFp.toStdString().substr(0, 16) + "...");

                    m_pairingLimiter.endPrompt(qClientUuid.toStdString(), true);
                    {
                        std::lock_guard<std::mutex> lock(*cvMutex);
                        *accepted = true;
                        *ready = true;
                    }
                    cv->notify_one();
                },
                Qt::QueuedConnection
            );

            std::unique_lock<std::mutex> lock(*cvMutex);
            if (!cv->wait_for(lock, std::chrono::seconds(30), [&ready] { return *ready; })) {
                errorMsg = "Pairing prompt timeout";
                return false;
            }

            if (*accepted) {
                outServerTag = *outTag;
            }
            errorMsg = *outErr;
            return *accepted;
        }
    );

    // Set up session event callback to update TransferListModel
    // Note: Use QPointer to guard against MainWindow destruction during callback execution
    // The callback is invoked from TransferServer's std::thread, not Qt's event loop
    QPointer<MainWindow> safeThis(this);
    m_transferServer->setSessionEventCallback(
        [safeThis](const std::string& sessionId, ExoSend::SessionStatus status) {
            // Note: Check if MainWindow was destroyed before accessing any members
            if (safeThis.isNull()) {
                return;  // MainWindow destroyed, skip callback
            }

            // Trace: Log session event callback entry
            LogCrash("=== Session Event Callback START ===");
            LogCrash("  Session ID: " + QString::fromStdString(sessionId));
            LogCrash("  Status: " + QString::number(static_cast<int>(status)));

            // Note: Check if MainWindow is still valid before invoking
            // Use Qt::QueuedConnection for non-Qt threads to prevent event loop state corruption
            // This prevents the application from exiting unexpectedly after transfer completion
            QMetaObject::invokeMethod(safeThis, [safeThis, sessionId, status]() {
                // Note: Double-check safety in inner lambda
                if (safeThis.isNull() || !QCoreApplication::instance()) {
                    return;
                }

                // Trace: Log inner lambda execution
                LogCrash("=== Session Event Inner Lambda START ===");
                LogCrash("  Session ID: " + QString::fromStdString(sessionId));
                LogCrash("  Status: " + QString::number(static_cast<int>(status)));

                // Note: Check if MainWindow is being destroyed
                if (!QCoreApplication::instance()) {
                    return;  // Application is shutting down, abort
                }

                // Note: Check if MainWindow is closing (thread-safe atomic read)
                // This prevents callbacks from executing during shutdown, avoiding use-after-free
                if (safeThis->m_closing.load(std::memory_order_acquire)) {
                    LogCrash("MainWindow closing, ignoring callback");
                    return;
                }

                // Note: Re-validate models after each operation
                if (!safeThis->m_transferModel || !safeThis->m_peerModel) {
                    return;
                }

                QString qSessionId = QString::fromStdString(sessionId);

                switch (status) {
                case ExoSend::SessionStatus::NEGOTIATING:
                {
                    // Copy m_pendingTransfer under lock to prevent race conditions
                    PendingTransfer pendingCopy;
                    {
                        std::lock_guard<std::mutex> lock(safeThis->m_pendingTransferMutex);
                        pendingCopy = safeThis->m_pendingTransfer;
                    }

                    // Store session info for later use (prevents race conditions)
                    {
                        std::lock_guard<std::mutex> lock(safeThis->m_pendingSessionsMutex);
                        safeThis->m_pendingSessions[sessionId] = pendingCopy;
                    }

                    // Track incoming transfer in model
                    QString peerName = pendingCopy.clientIp;
                    QString filename = pendingCopy.filename;

                    safeThis->m_transferModel->onTransferStarted(
                        qSessionId,
                        filename,
                        peerName,
                        TransferItem::Incoming
                    );
                    break;
                }

                case ExoSend::SessionStatus::TRANSFERRING:
                {
                    // Note: Get filename from TransferServer's pending filename storage
                    // The incomingConnectionCallback has now been called (in TransferServer::handleClient)
                    // and m_pendingTransfer.filename should be populated, but to be safe we also
                    // retrieve from TransferServer's direct storage
                    QString filename;

                    // First try m_pendingTransfer (populated by incomingConnectionCallback)
                    // NOTE: Protected by mutex to prevent data races
                    {
                        std::lock_guard<std::mutex> lock(safeThis->m_pendingTransferMutex);
                        filename = safeThis->m_pendingTransfer.filename;
                    }

                    // If empty, try to get from TransferServer's pending storage
                    if (filename.isEmpty() && safeThis->m_transferServer) {
                        std::string serverFilename = safeThis->m_transferServer->getPendingFilename(sessionId);
                        if (!serverFilename.empty()) {
                            filename = QString::fromStdString(serverFilename);
                        }
                    }

                    // Update filename if we have it (fix for missing filename bug)
                    if (!filename.isEmpty()) {
                        safeThis->m_transferModel->updateFilename(qSessionId, filename);
                    }

                    // Progress updates handled by progress callback
                    break;
                }

                case ExoSend::SessionStatus::COMPLETED:
                {
                    // qCInfo removed - was causing DBG_PRINTEXCEPTION
                    LogCrash("=== Session COMPLETED event ===");
                    LogCrash("  Session ID: " + qSessionId);

                    // Note: Check if we already processed this completion
                    {
                        std::lock_guard<std::mutex> lock(safeThis->m_completedSessionsMutex);
                        if (safeThis->m_completedSessions.count(sessionId) > 0) {
                            // qCWarning removed - was causing DBG_PRINTEXCEPTION
                            LogCrash("  Session COMPLETED: Duplicate, ignoring");
                            break;  // Already processed, ignore duplicate
                        }
                        safeThis->m_completedSessions.insert(sessionId);
                    }

                    // Note: Call directly instead of deferring with QTimer::singleShot
                    // This ensures the callback executes synchronously before the worker thread continues
                    // eliminating the race condition that causes SIGSEGV
                    LogCrash("  Session COMPLETED: About to call onTransferCompleted");

                    // Note: Validate m_transferModel before calling
                    if (safeThis->m_transferModel) {
                        safeThis->m_transferModel->onTransferCompleted(qSessionId, "");
                        LogCrash("  Session COMPLETED: onTransferCompleted returned");
                    }
                    break;
                }

                case ExoSend::SessionStatus::FAILED:
                    safeThis->m_transferModel->onTransferFailed(qSessionId, "Transfer failed");
                    break;

                case ExoSend::SessionStatus::CANCELLED:
                    safeThis->m_transferModel->onTransferCancelled(qSessionId);
                    break;

                default:
                    break;
                }

                // Trace: Log inner lambda completion
                LogCrash("=== Session Event Inner Lambda END ===");
            }, Qt::QueuedConnection);  // FIX: Use QueuedConnection (non-blocking) to prevent crash from non-Qt thread
            // The TransferServer listener thread is a std::thread, not a Qt thread
            // BlockingQueuedConnection from non-Qt threads causes Qt event loop corruption
            // This matches the working pattern used for outgoing transfers (line 896)

            // Trace: Log session event callback exit
            LogCrash("=== Session Event Callback END (invokeMethod returned) ===");
        }
    );

    // Start transfer server (binds to OS-assigned ephemeral TCP port via bind(0)+getsockname).
    if (!m_transferServer->start()) {
        return false;
    }

    // Wire IP validator: reject TCP connections from IPs not in the discovery peer list.
    // Defense-in-depth: TLS + ExoSend protocol still authenticate all peers.
    m_transferServer->setIpValidatorCallback(
        [this](const std::string& ip) {
            return m_discovery->hasPeerByIp(ip);
        }
    );

    // Advertise the OS-assigned TCP port in discovery beacons BEFORE starting discovery.
    m_discovery->setTcpPort(m_transferServer->getTcpPort());

    // Start discovery (binds first available port from pool 41000-48100).
    if (!m_discovery->start()) {
        QMessageBox::critical(this, "ExoSend",
            "Failed to start the discovery service.\n"
            "All discovery ports (41000, 42100, 43210, 43500, 45100,\n"
            "46000, 46100, 47100, 47500, 48100) may already be in use.\n"
            "Check if another ExoSend instance is already running.");
        m_transferServer->stop();
        return false;
    }

    // Show dynamic ports in the dedicated status bar label (avoids showMessage overlap).
    m_portInfoLabel->setText(
        QString("Discovery: UDP %1  |  Transfer: TCP %2")
            .arg(m_discovery->getBoundDiscoveryPort())
            .arg(m_transferServer->getTcpPort())
    );

#ifdef _WIN32
    // Warn if connected to a Public network via a compact icon in the status bar.
    if (activeNetworkIsPublic()) {
        m_networkWarningLabel->setVisible(true);
    }
#endif

    // Create TransferQueueManager (max concurrent only)
    m_queueManager = std::make_unique<ExoSend::TransferQueueManager>(
        ExoSend::MAX_CONCURRENT_TRANSFERS
    );
    m_queueManager->setLocalDeviceUuid(m_settings->getDeviceUuid().toStdString());

    // Set up callbacks for outgoing transfer status updates
    m_queueManager->setStatusCallback(
        [this](const std::string& sessionId, ExoSend::SessionStatus status) {
            // Note: Check if MainWindow is still valid before invoking
            // Use Qt::QueuedConnection to allow network thread to continue immediately
            QMetaObject::invokeMethod(this, [this, sessionId, status]() {
                // Note: Additional safety check - m_transferModel might be invalid
                if (!m_transferModel) {
                    return;
                }

                QString qSessionId = QString::fromStdString(sessionId);

                switch (status) {
                case ExoSend::SessionStatus::NEGOTIATING:
                    // Update to negotiating status
                    m_transferModel->updateStatus(qSessionId, TransferItem::Negotiating);
                    break;

                case ExoSend::SessionStatus::TRANSFERRING:
                    // Progress updates handled separately
                    break;

                case ExoSend::SessionStatus::COMPLETED:
                    LogCrash("=== Session COMPLETED event (status update) ===");
                    LogCrash("  Session ID: " + qSessionId);
                    m_transferModel->onTransferCompleted(qSessionId, "");
                    break;

                case ExoSend::SessionStatus::FAILED:
                    m_transferModel->onTransferFailed(qSessionId, "Transfer failed");
                    break;

                case ExoSend::SessionStatus::CANCELLED:
                    m_transferModel->onTransferCancelled(qSessionId);
                    break;

                default:
                    break;
                }
            }, Qt::QueuedConnection);  // Note: Use QueuedConnection to prevent crash
        }
    );

    m_queueManager->setProgressCallback(
        [this](const std::string& sessionId,
               uint64_t bytesTransferred,
               uint64_t totalBytes,
               double percentage) {
            QMetaObject::invokeMethod(this, [this, sessionId, bytesTransferred, totalBytes, percentage]() {
                QString qSessionId = QString::fromStdString(sessionId);
                m_transferModel->onTransferProgress(
                    qSessionId,
                    static_cast<qint64>(bytesTransferred),
                    static_cast<qint64>(totalBytes),
                    0.0,  // speed - can be calculated later
                    -1    // eta - can be calculated later
                );
            }, Qt::QueuedConnection);  // Note: Explicit QueuedConnection for thread safety
        }
    );

    // Start the queue manager
    if (!m_queueManager->start()) {
        return false;
    }

    // Create tray icon
    m_trayIcon = new TrayIcon(this, this);

    // Connect tray icon signals
    connect(m_trayIcon, &TrayIcon::quitRequested, this, &MainWindow::onExit);

    // Show tray icon
    m_trayIcon->show();

    // Check firewall
    checkFirewall();

    return true;
}

void MainWindow::stopServices()
{
    const auto stopBegin = std::chrono::steady_clock::now();

    // Note: Clear callbacks BEFORE stopping services
    if (m_transferServer) {
        m_transferServer->setSessionEventCallback(nullptr);
        m_transferServer->setIncomingConnectionCallback(nullptr);
    }

    // Stop timers
    if (m_peerRefreshTimer) {
        m_peerRefreshTimer->stop();
    }

    if (m_statusUpdateTimer) {
        m_statusUpdateTimer->stop();
    }

    if (m_cleanupTimer) {
        m_cleanupTimer->stop();
    }

    // Now stop services
    // Stop queue manager
    if (m_queueManager) {
        const auto queueStart = std::chrono::steady_clock::now();
        m_queueManager->stop();
        const auto queueMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - queueStart).count();
        LogCrash("  stopServices: queue manager stopped in " + std::to_string(queueMs) + "ms");
    }

    // Stop transfer server
    if (m_transferServer) {
        const auto transferStart = std::chrono::steady_clock::now();
        m_transferServer->stop();
        const auto transferMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - transferStart).count();
        LogCrash("  stopServices: transfer server stopped in " + std::to_string(transferMs) + "ms");
    }

    // Stop discovery
    if (m_discovery) {
        const auto discoveryStart = std::chrono::steady_clock::now();
        m_discovery->stop();
        const auto discoveryMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - discoveryStart).count();
        LogCrash("  stopServices: discovery stopped in " + std::to_string(discoveryMs) + "ms");
    }

    // Hide tray icon
    if (m_trayIcon) {
        m_trayIcon->hide();
    }

    const auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - stopBegin).count();
    LogCrash("  stopServices: total " + std::to_string(totalMs) + "ms");
}

// ========================================================================
// Firewall Detection
// ========================================================================

bool MainWindow::checkFirewall()
{
    const QString helperPath = QCoreApplication::applicationDirPath() + "/ExoSendFirewallHelper.exe";
    if (!QFileInfo::exists(helperPath)) {
        return true;
    }

    QProcess proc;
    proc.setProgram(helperPath);
    proc.setArguments(QStringList() << "--check");
    proc.start();

    if (!proc.waitForFinished(5000)) {
        proc.kill();
        proc.waitForFinished(1000);
        return true;
    }

    const int exitCode = proc.exitCode();
    if (exitCode == 0) {
        return true;
    }

    if (exitCode == 2) {
        showFirewallDialog();
        return false;
    }

    return true;
}

void MainWindow::showFirewallDialog()
{
    const QString helperPath = QCoreApplication::applicationDirPath() + "/ExoSendFirewallHelper.exe";

    QMessageBox dlg(this);
    dlg.setWindowTitle("Firewall Rules Needed");
    dlg.setIcon(QMessageBox::Warning);
    dlg.setText("Windows Firewall rules are missing for ExoSend.");
    dlg.setInformativeText(
        "ExoSend needs inbound firewall rules to:\n"
        "- Discover peers (UDP, auto-selects from port pool 41000-48100)\n"
        "- Receive transfers (TCP, OS-assigned port)\n\n"
        "You can fix this automatically (requires Administrator approval), "
        "or open Windows Firewall settings and add rules manually."
    );

    QPushButton* fixBtn = dlg.addButton("Fix Automatically (Admin)", QMessageBox::AcceptRole);
    QPushButton* openBtn = dlg.addButton("Open Firewall Settings", QMessageBox::ActionRole);
    dlg.addButton(QMessageBox::Cancel);

    dlg.exec();

    if (dlg.clickedButton() == openBtn) {
#ifdef _WIN32
        (void)ShellExecuteW(nullptr, L"open", L"wf.msc", nullptr, nullptr, SW_SHOWNORMAL);
#endif
        return;
    }

    if (dlg.clickedButton() != fixBtn) {
        return;
    }

    if (!QFileInfo::exists(helperPath)) {
        QMessageBox::warning(this, "Helper Missing",
                             "ExoSendFirewallHelper.exe was not found next to ExoSend.exe.\n"
                             "Rebuild or reinstall, then try again.");
        return;
    }

#ifdef _WIN32
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";

    const std::wstring fileW = helperPath.toStdWString();
    const std::wstring paramsW = L"--install";
    sei.lpFile = fileW.c_str();
    sei.lpParameters = paramsW.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        const DWORD err = GetLastError();
        QMessageBox::critical(this, "Firewall Fix Failed",
                              "Failed to start elevated helper.\n"
                              "Error code: " + QString::number(static_cast<qulonglong>(err)));
        return;
    }

    (void)WaitForSingleObject(sei.hProcess, 60000);
    DWORD exitCode = 0;
    (void)GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    if (exitCode == 0) {
        QMessageBox::information(this, "Firewall Updated",
                                 "Firewall rules were added successfully.\n"
                                 "Discovery and incoming transfers should now work.");
    } else {
        QMessageBox::critical(this, "Firewall Fix Failed",
                              "The elevated helper reported failure.\n"
                              "Exit code: " + QString::number(static_cast<qulonglong>(exitCode)));
    }
#else
    QMessageBox::information(this, "Not Supported",
                             "Automatic firewall configuration is only supported on Windows.");
#endif
}

// ========================================================================
// Drag and Drop
// ========================================================================

void MainWindow::onFilesDropped(const QList<QUrl>& urls)
{
    // Get selected peer (verify actual selection, not just current index)
    QItemSelectionModel* selectionModel = m_peerListView->selectionModel();
    QModelIndexList selectedIndexes = selectionModel->selectedIndexes();

    if (selectedIndexes.isEmpty()) {
        QMessageBox::information(this, "No Peer Selected",
                               "Please select a peer to send files to.");
        return;
    }

    QModelIndex selected = selectedIndexes.first();  // Single selection mode

    QString peerUuid = selected.data(PeerListModel::UuidRole).toString();
    QString peerIp = selected.data(PeerListModel::IpRole).toString();
    quint16 peerPort = selected.data(PeerListModel::PortRole).toUInt();
    QString peerName = selected.data(PeerListModel::NameRole).toString();
    QString peerFingerprint = selected.data(PeerListModel::FingerprintRole).toString();

    QString pinnedFingerprint;

    // Maximum-security model: require secure pairing (PAIR_REQ/PAIR_RESP) before first transfer.
    if (!m_settings) {
        QMessageBox::critical(this, "Internal Error", "Settings manager not initialized.");
        return;
    }

    if (peerUuid.isEmpty() || peerIp.isEmpty() || peerPort == 0) {
        QMessageBox::warning(this, "Cannot Send",
                             "Missing peer identity or network information.");
        return;
    }

    if (m_settings->isPeerPinned(peerUuid)) {
        pinnedFingerprint = m_settings->getPinnedFingerprint(peerUuid);
    }

    if (pinnedFingerprint.isEmpty()) {
        if (!pairPeerSecurely(peerUuid, peerName, peerIp, peerPort, pinnedFingerprint)) {
            return;
        }
    } else {
        // Best-effort trust metadata update (does not change trust decisions).
        m_settings->updatePeerSeen(peerUuid, peerName);

        // Discovery fingerprint is untrusted. Display-only warning if it conflicts.
        if (!peerFingerprint.isEmpty() && peerFingerprint != pinnedFingerprint) {
            const QString pinnedDisplay = QString::fromStdString(
                ExoSend::FingerprintUtils::formatForDisplay(pinnedFingerprint.toStdString()));
            const QString actualDisplay = QString::fromStdString(
                ExoSend::FingerprintUtils::formatForDisplay(peerFingerprint.toStdString()));
            QMessageBox::warning(this, "Discovery Mismatch",
                                 "The peer advertised a different certificate fingerprint via discovery.\n\n"
                                 "Pinned (trusted):\n" + pinnedDisplay + "\n\n"
                                 "Discovery (untrusted):\n" + actualDisplay + "\n\n"
                                 "ExoSend will use the pinned fingerprint during TLS and will block mismatches.");
        }
    }

    int queuedCount = 0;

    for (const QUrl& url : urls) {
        if (!url.isLocalFile()) {
            continue;
        }

        QString filePath = url.toLocalFile();
        QFileInfo fileInfo(filePath);

        if (!fileInfo.exists()) {
            QMessageBox::warning(this, "File Not Found",
                               QString("File not found: %1").arg(filePath));
            continue;
        }

        // Create TransferRequest
        ExoSend::TransferRequest request;
        request.filePath = filePath.toStdString();
        request.peerUuid = peerUuid.toStdString();
        request.peerIpAddress = peerIp.toStdString();
        request.peerPort = peerPort;
        request.peerPinnedFingerprintSha256Hex = pinnedFingerprint.toStdString();
        request.priority = 1;  // Normal priority

        // Enqueue the transfer
        std::string requestId = m_queueManager->enqueue(request);

        if (!requestId.empty()) {
            // Add to transfer model
            QString sessionId = QString::fromStdString(requestId);
            m_transferModel->onTransferStarted(
                sessionId,
                fileInfo.fileName(),
                peerName,
                TransferItem::Outgoing
            );
            queuedCount++;
        }
    }

    if (queuedCount > 0) {
        m_statusLabel->setText(QString("Queued %1 file(s) for sending to %2")
                            .arg(queuedCount).arg(peerName));
    }
}

// ========================================================================
// Security Methods
// ========================================================================

bool MainWindow::pairPeerSecurely(
    const QString& peerUuid,
    const QString& peerName,
    const QString& peerIp,
    quint16 peerPort,
    QString& outPinnedFingerprint)
{
    outPinnedFingerprint.clear();

    if (!m_settings) {
        QMessageBox::critical(this, "Pairing Failed", "Internal error: settings not initialized.");
        return false;
    }

    const QString localUuidQ = m_settings->getDeviceUuid();
    const std::string localUuid = localUuidQ.toStdString();
    const std::string peerUuidStd = peerUuid.toStdString();

    if (localUuid.empty()) {
        QMessageBox::critical(this, "Pairing Failed", "Internal error: local device UUID is empty.");
        return false;
    }

    if (peerUuidStd.empty() || peerIp.isEmpty() || peerPort == 0) {
        QMessageBox::warning(this, "Pairing Failed",
                             "Cannot pair: missing peer identity or network information.");
        return false;
    }

    std::array<uint8_t, 16> generated{};
    std::string genErr;
    (void)ExoSend::PairingSecret::generate128(generated, genErr);
    const QString defaultCode = QString::fromStdString(ExoSend::PairingSecret::toBase32Crockford(generated));

    bool ok = false;
    const QString codeQ = QInputDialog::getText(
        this,
        "Secure Pairing Code",
        "Enter the secure pairing code.\n\n"
        "For maximum security, this code must be shared out-of-band.\n"
        "If you do not have one, use the pre-filled code and share it with the peer.\n\n"
        "Click OK to start pairing now. The peer will be prompted to enter the same code.",
        QLineEdit::Normal,
        defaultCode,
        &ok
    );

    if (!ok) {
        return false;
    }

    std::array<uint8_t, 16> secret{};
    std::string parseErr;
    if (!ExoSend::PairingSecret::parse128Base32Crockford(codeQ.toStdString(), secret, parseErr)) {
        QMessageBox::warning(this, "Invalid Pairing Code",
                             "The pairing code is invalid.\n\n" + QString::fromStdString(parseErr));
        return false;
    }

    // Establish a TLS connection to the peer, then run PAIR_REQ/PAIR_RESP.
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        QMessageBox::critical(this, "Pairing Failed",
                              "socket() failed: " + QString::number(WSAGetLastError()));
        return false;
    }

    const uint32_t timeoutMs = ExoSend::CONNECTION_TIMEOUT_MS;
    if (!ExoSend::setSocketRecvTimeout(sock, timeoutMs)) {
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed", "Failed to set socket timeout.");
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peerPort);
    if (::inet_pton(AF_INET, peerIp.toStdString().c_str(), &addr.sin_addr) <= 0) {
        closesocket(sock);
        QMessageBox::warning(this, "Pairing Failed", "Invalid peer IP address.");
        return false;
    }

    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int wsaError = WSAGetLastError();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to connect to peer.\n\n"
                              "Peer: " + peerName + "\n"
                              "IP: " + peerIp + "\n"
                              "Port: " + QString::number(peerPort) + "\n\n"
                              "WSAGetLastError(): " + QString::number(wsaError));
        return false;
    }

    std::string tlsErr;
    ExoSend::TlsSocket tls(sock, ExoSend::TlsRole::CLIENT);
    if (!tls.handshake(tlsErr)) {
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "TLS handshake failed:\n\n" + QString::fromStdString(tlsErr));
        return false;
    }

    ExoSend::TlsTransportStream stream(tls);

    std::array<uint8_t, 32> exporter{};
    if (!tls.getTlsExporterChannelBinding(exporter, tlsErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to compute TLS channel binding:\n\n" + QString::fromStdString(tlsErr));
        return false;
    }

    std::string fpErr;
    const std::string localFp = tls.getLocalFingerprint(fpErr);
    const std::string peerFp = tls.getPeerFingerprint(fpErr);
    if (localFp.empty() || peerFp.empty()) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to obtain certificate fingerprints:\n\n" + QString::fromStdString(fpErr));
        return false;
    }

    std::array<uint8_t, 32> confirmKey{};
    std::string confirmErr;
    if (!ExoSend::PairingConfirm::deriveConfirmKey(secret, exporter, confirmKey, confirmErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to derive pairing key:\n\n" + QString::fromStdString(confirmErr));
        return false;
    }

    std::array<uint8_t, 32> clientTag{};
    if (!ExoSend::PairingConfirm::computeTag(
            confirmKey,
            ExoSend::PairingRole::Client,
            localUuid,
            localFp,
            peerUuidStd,
            peerFp,
            clientTag,
            confirmErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to compute pairing tag:\n\n" + QString::fromStdString(confirmErr));
        return false;
    }

    ExoSend::ExoHeader req(ExoSend::PacketType::PAIR_REQ, 0, "");
    req.setSenderUuid(localUuid);
    req.setSha256Bytes(clientTag.data());

    std::vector<uint8_t> reqBuf(ExoSend::HEADER_SIZE);
    (void)req.serializeToBuffer(reqBuf.data());

    std::string ioErr;
    if (!stream.sendExact(reqBuf.data(), reqBuf.size(), ioErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to send pairing request:\n\n" + QString::fromStdString(ioErr));
        return false;
    }

    std::vector<uint8_t> respBuf(ExoSend::HEADER_SIZE);
    if (!stream.recvExact(respBuf.data(), respBuf.size(), ioErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Failed to receive pairing response:\n\n" + QString::fromStdString(ioErr));
        return false;
    }

    ExoSend::ExoHeader resp;
    if (!resp.deserializeFromBuffer(respBuf.data()) || !resp.isValid()) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed", "Invalid pairing response header.");
        return false;
    }

    if (resp.getPacketType() != ExoSend::PacketType::PAIR_RESP) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::warning(this, "Pairing Rejected",
                             "Peer rejected pairing (no response tag).");
        return false;
    }

    if (resp.getSenderUuid() != peerUuidStd) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Peer identity mismatch during pairing.\n\n"
                              "Expected UUID: " + peerUuid + "\n"
                              "Actual UUID: " + QString::fromStdString(resp.getSenderUuid()));
        return false;
    }

    const auto serverTag = resp.getSha256Bytes();
    if (!ExoSend::PairingConfirm::verifyTag(
            confirmKey,
            ExoSend::PairingRole::Server,
            peerUuidStd,
            peerFp,
            localUuid,
            localFp,
            serverTag,
            confirmErr)) {
        stream.shutdown();
        closesocket(sock);
        QMessageBox::critical(this, "Pairing Failed",
                              "Pairing confirmation failed:\n\n" + QString::fromStdString(confirmErr));
        return false;
    }

    stream.shutdown();
    closesocket(sock);

    // Pin after cryptographic confirmation succeeded.
    m_settings->pinPeerFingerprint(peerUuid, QString::fromStdString(peerFp), peerName);
    m_settings->updatePeerSeen(peerUuid, peerName);

    outPinnedFingerprint = QString::fromStdString(peerFp);

    ExoSend::ThreadSafeLog::log(
        "TRUST_PIN peer=" + peerUuidStd +
        " fp=" + outPinnedFingerprint.toStdString().substr(0, 16) + "...");

    return true;
}

bool MainWindow::handlePendingIncomingTransfer(
    const QString& clientIp,
    const QString& peerName,
    const QString& peerUuid,
    quint16 peerPort,
    const QString& peerFingerprintSha256Hex,
    const QString& filename,
    qint64 fileSize,
    const QString& pendingSessionId)
{
    // Trace: Log entry to help diagnose crash
    LogCrash("=== START handlePendingIncomingTransfer ===");
    LogCrash("  Client IP: " + clientIp);
    LogCrash("  Filename: " + filename);
    LogCrash("  File size: " + QString::number(fileSize));
    LogCrash("  Session ID: " + pendingSessionId);
    LogCrash("  Thread: " + QString::number(reinterpret_cast<quintptr>(QThread::currentThreadId()), 16));

    Q_UNUSED(pendingSessionId);  // Not needed for dialog, but kept for future use

    const QString effectivePeerName = peerName.isEmpty() ? clientIp : peerName;

    // Check auto-accept setting for this peer
    bool autoAcceptEnabled = false;
    QString pinnedFingerprint;
    if (!peerUuid.isEmpty()) {
        autoAcceptEnabled = m_settings->getAutoAcceptForPeer(peerUuid);
        pinnedFingerprint = m_settings->getPinnedFingerprint(peerUuid);
    }

    QString downloadPath = m_settings->getDownloadPath();

    // Skip dialog if auto-accept is enabled
    if (ExoSend::shouldAutoAcceptIncoming(
            autoAcceptEnabled,
            pinnedFingerprint.toStdString(),
            peerFingerprintSha256Hex.toStdString())) {
        if (validateDownloadPath(downloadPath)) {
            m_statusLabel->setText("Auto-accepted: " + filename);
            LogCrash("=== END handlePendingIncomingTransfer (AUTO-ACCEPT) ===");
            return true;  // ACCEPT automatically
        } else {
            // Fall through to show dialog
        }
    }

    // Show accept/reject dialog with peer info
    IncomingTransferDialog dlg(
        effectivePeerName,
        clientIp,
        peerUuid,
        peerPort,
        filename,
        fileSize,
        downloadPath,
        this  // Parent widget
    );

    // Dialog is modal - this call BLOCKS until user clicks Accept or Reject
    int result = dlg.exec();

    if (result == QDialog::Accepted) {
        downloadPath = dlg.getDownloadPath();

        // Check if "Always accept from this peer" was checked
        if (dlg.getAlwaysAcceptChecked() &&
            !peerUuid.isEmpty() &&
            ExoSend::shouldAutoAcceptIncoming(
                true,
                m_settings->getPinnedFingerprint(peerUuid).toStdString(),
                peerFingerprintSha256Hex.toStdString())) {
            m_settings->setAutoAcceptForPeer(peerUuid, true);
        }

        if (validateDownloadPath(downloadPath)) {
            m_statusLabel->setText("Accepted: " + filename);
            LogCrash("=== END handlePendingIncomingTransfer (ACCEPT) ===");
            return true;  // ACCEPT the transfer
        } else {
            QMessageBox::warning(this, "Invalid Path",
                "The selected download path is invalid or contains "
                "path traversal sequences.");
            m_statusLabel->setText("Rejected: Invalid path");
            LogCrash("=== END handlePendingIncomingTransfer (INVALID PATH) ===");
            return false;  // REJECT due to invalid path
        }
    } else {
        // User clicked Reject or closed dialog
        m_statusLabel->setText("Rejected: " + filename);
        LogCrash("=== END handlePendingIncomingTransfer (REJECTED) ===");
        return false;  // REJECT the transfer
    }
}

bool MainWindow::validateDownloadPath(const QString& path)
{
    if (path.isEmpty()) {
        return false;
    }

    QString absolutePath = QDir(path).absolutePath();

    // Check for path traversal
    if (!isPathTraversalSafe(absolutePath)) {
        return false;
    }

    // Verify directory exists and is writable
    QDir dir(path);
    return dir.exists();
}

bool MainWindow::isPathTraversalSafe(const QString& path)
{
    QString absolutePath = QDir(path).absolutePath();

    // Check for traversal patterns
    if (absolutePath.contains("../") || absolutePath.contains("..\\")) {
        return false;
    }

    // Check for encoded traversal attempts
    if (absolutePath.contains("%2e%2e", Qt::CaseInsensitive)) {
        return false;
    }

    // Note: Removed the restriction that path must start with settings download path
    // This was causing Desktop and other valid paths to be rejected
    // The original code checked:
    //   QString expectedDir = QDir(m_settings->getDownloadPath()).absolutePath();
    //   return absolutePath.startsWith(expectedDir);
    // This prevented users from selecting Desktop or other locations in the dialog.

    return true;
}
