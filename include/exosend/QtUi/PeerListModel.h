/**
 * @file PeerListModel.h
 * @brief Qt list model for discovered peers
 *
 * This class provides a Qt model interface for displaying discovered peers
 * in a QListView or other Qt view classes.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_PEERLISTMODEL_H
#define EXOSEND_QTUI_PEERLISTMODEL_H

#include <QAbstractListModel>
#include <QObject>
#include <QString>
#include <QVariant>
#include <QVector>
#include <QHash>
#include <QByteArray>
#include <vector>
#include <shared_mutex>
#include "exosend/DiscoveryService.h"
#include "exosend/PeerInfo.h"

// Forward declarations
class SettingsManager;

/**
 * @class PeerListModel
 * @brief Qt model wrapper for DiscoveryService peer list
 *
 * This class wraps the DiscoveryService peer list and provides
 * a Qt Model/View interface for displaying peers in the GUI.
 *
 * Thread Safety:
 * - The model maintains its own cache of peers for thread-safe access
 * - Updates from DiscoveryService are queued via Qt signals
 * - UI can safely access data() from main thread without blocking
 *
 * Usage:
 * ```cpp
 * PeerListModel* model = new PeerListModel(discoveryService);
 * QListView* view = new QListView();
 * view->setModel(model);
 * ```
 */
class PeerListModel : public QAbstractListModel {
    Q_OBJECT

public:
    /**
     * @brief Custom data roles for peer data access
     *
     * These roles extend Qt::DisplayRole and Qt::DecorationRole
     * to provide structured access to peer properties.
     */
    enum PeerRoles {
        NameRole = Qt::UserRole + 1,    ///< Peer display name
        IpRole = Qt::UserRole + 2,      ///< Peer IP address
        PortRole = Qt::UserRole + 3,    ///< Peer TCP port
        LastSeenRole = Qt::UserRole + 4, ///< Last seen timestamp (ms since epoch)
        UuidRole = Qt::UserRole + 5,     ///< Peer unique identifier
        StatusRole = Qt::UserRole + 6,   ///< Peer status (int: Active=0, Warning=1, Inactive=2)
        TimeRemainingRole = Qt::UserRole + 7, ///< Seconds until timeout (0 if inactive)
        IsActiveRole = Qt::UserRole + 8,   ///< Boolean: true if peer is active (not inactive)
        AutoAcceptRole = Qt::UserRole + 9,  ///< Auto-accept enabled for this peer
        FingerprintRole = Qt::UserRole + 10 ///< Peer cert fingerprint (SHA-256 hex) for pairing UX
    };

    /**
     * @brief Constructor
     * @param discovery Pointer to DiscoveryService (must not be null)
     * @param settings Pointer to SettingsManager (must not be null)
     * @param parent Parent QObject
     *
     * The DiscoveryService and SettingsManager pointers are stored but NOT owned.
     * These services must remain valid for the lifetime of this model.
     */
    explicit PeerListModel(ExoSend::DiscoveryService* discovery,
                           SettingsManager* settings,
                           QObject* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~PeerListModel() override = default;

    // ========================================================================
    // QAbstractListModel Interface
    // ========================================================================

    /**
     * @brief Get the number of rows (peers) in the model
     * @param parent Parent index (unused for list models)
     * @return Number of peers currently in the list
     */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    /**
     * @brief Get data for a given role and index
     * @param index Model index specifying peer
     * @param role Data role (e.g., DisplayRole, NameRole, IpRole, etc.)
     * @return QVariant containing the requested data
     *
     * Supported roles:
     * - Qt::DisplayRole: Returns "DisplayName (IP:Port)" format
     * - Qt::ToolTipRole: Returns detailed peer info
     * - NameRole: Returns display name only
     * - IpRole: Returns IP address only
     * - PortRole: Returns TCP port as integer
     * - LastSeenRole: Returns last seen timestamp
     * - UuidRole: Returns UUID string
     * - AutoAcceptRole: Returns true if auto-accept is enabled
     */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Set data for a given role and index
     * @param index Model index specifying peer
     * @param value Value to set
     * @param role Data role
     * @return true if data was set successfully
     *
     * Supports:
     * - AutoAcceptRole: Set auto-accept preference for peer
     */
    bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

    /**
     * @brief Get the role mapping for this model
     * @return Hash mapping role enum to string identifiers
     *
     * This allows QML and dynamic UI systems to access roles by name.
     */
    QHash<int, QByteArray> roleNames() const override;

    // ========================================================================
    // Public Slots for DiscoveryService Integration
    // ========================================================================

public slots:
    /**
     * @brief Called when a new peer is discovered
     * @param peer The newly discovered peer
     *
     * Adds peer to the model and notifies views.
     * If peer already exists (by UUID), updates existing entry.
     */
    void onPeerAdded(const ExoSend::PeerInfo& peer);

    /**
     * @brief Called when an existing peer is updated
     * @param peer The updated peer info
     *
     * Updates existing peer entry and notifies views.
     * If peer doesn't exist, adds it.
     */
    void onPeerUpdated(const ExoSend::PeerInfo& peer);

    /**
     * @brief Called when a peer times out and is removed
     * @param uuid The UUID of the peer to remove
     *
     * Removes peer from the model and notifies views.
     * Silently ignores unknown UUIDs.
     */
    void onPeerRemoved(const std::string& uuid);

    /**
     * @brief Refresh the entire peer list from DiscoveryService
     *
     * Fetches current peer list from DiscoveryService and replaces
     * the model's cache. Emits model reset signal.
     *
     * Use this for initial load or after large-scale changes.
     */
    void refreshPeerList();

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * @brief Find a peer by UUID
     * @param uuid Peer UUID to find
     * @return Model index of the peer, or invalid index if not found
     */
    QModelIndex findPeerByUuid(const QString& uuid) const;

    /**
     * @brief Get peer info at a given index
     * @param index Model index
     * @return Peer info copy, or empty PeerInfo if index invalid
     */
    ExoSend::PeerInfo getPeerInfo(const QModelIndex& index) const;

    /**
     * @brief Get the number of active peers
     * @return Number of peers currently in the list
     */
    int getPeerCount() const { return static_cast<int>(m_peers.size()); }

    /**
     * @brief Calculate and update status for all peers
     * @param timeoutMs Timeout in milliseconds
     *
     * This method recalculates the status of all peers based on the
     * current time and the specified timeout. Emits dataChanged signals
     * for any peers whose status has changed.
     */
    void updatePeerStatuses(uint32_t timeoutMs);

    /**
     * @brief Set the peer timeout for status calculation
     * @param timeoutMs Timeout in milliseconds
     */
    void setTimeoutMs(uint32_t timeoutMs) { m_timeoutMs = timeoutMs; }

    /**
     * @brief Get the current peer timeout
     * @return Timeout in milliseconds
     */
    uint32_t getTimeoutMs() const { return m_timeoutMs; }

    /**
     * @brief Set auto-accept preference for a peer
     * @param uuid Peer UUID
     * @param enabled true to enable auto-accept
     *
     * Updates the model and notifies views.
     * Emits dataChanged signal for the affected peer.
     */
    void setAutoAccept(const QString& uuid, bool enabled);

    /**
     * @brief Get auto-accept preference for a peer
     * @param uuid Peer UUID
     * @return true if auto-accept is enabled
     */
    bool getAutoAccept(const QString& uuid) const;

signals:
    /**
     * @brief Emitted when peer count changes
     * @param count New peer count
     */
    void peerCountChanged(int count);

    /**
     * @brief Emitted when a new peer is discovered
     * @param peerName Display name of new peer
     */
    void peerDiscovered(const QString& peerName);

    /**
     * @brief Emitted when a peer times out
     * @param peerName Display name of peer that left
     */
    void peerRemoved(const QString& peerName);

private:
    /**
     * @brief Internal helper to find peer index by UUID
     * @param uuid UUID to find
     * @return Index in m_peers vector, or -1 if not found
     */
    int findPeerIndexByUuid(const std::string& uuid) const;

    /**
     * @brief Format peer info for display
     * @param peer Peer to format
     * @return Formatted string "DisplayName (IP:Port)"
     */
    QString formatPeerDisplay(const ExoSend::PeerInfo& peer) const;

    /**
     * @brief Format peer info for tooltip
     * @param peer Peer to format
     * @return Detailed multi-line tooltip
     */
    QString formatPeerTooltip(const ExoSend::PeerInfo& peer) const;

private:
    ExoSend::DiscoveryService* m_discovery;  ///< DiscoveryService (not owned)
    SettingsManager* m_settings;             ///< SettingsManager (not owned)
    std::vector<ExoSend::PeerInfo> m_peers;  ///< Cached peer list
    mutable std::shared_mutex m_mutex;        ///< Thread-safe peer access
    uint32_t m_timeoutMs;                     ///< Peer timeout in milliseconds (default 3000)
};

#endif // EXOSEND_QTUI_PEERLISTMODEL_H
