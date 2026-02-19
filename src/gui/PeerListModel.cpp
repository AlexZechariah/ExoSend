/**
 * @file PeerListModel.cpp
 * @brief Qt list model for discovered peers implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/PeerListModel.h"
#include "exosend/QtUi/SettingsManager.h"
#include <QDateTime>

// ========================================================================
// Constructor / Destructor
// ========================================================================

PeerListModel::PeerListModel(ExoSend::DiscoveryService* discovery,
                               SettingsManager* settings,
                               QObject* parent)
    : QAbstractListModel(parent)
    , m_discovery(discovery)
    , m_settings(settings)
    , m_peers()
    , m_mutex()
    // Note: This MUST match PEER_TIMEOUT_MS in config.h (10000ms)
    // Mismatch causes peer status cycling (Green/Red flickering)
    , m_timeoutMs(10000)  // Fixed at 10 seconds (matches DiscoveryService)
{
    // Initial load of peer list
    refreshPeerList();
}

// ========================================================================
// QAbstractListModel Interface
// ========================================================================

int PeerListModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return static_cast<int>(m_peers.size());
}

QVariant PeerListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= rowCount()) {
        return QVariant();
    }

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const ExoSend::PeerInfo& peer = m_peers[index.row()];

    switch (role) {
    case Qt::DisplayRole:
        return formatPeerDisplay(peer);

    case Qt::ToolTipRole:
        {
            QString baseTooltip = formatPeerTooltip(peer);
            QString uuid = QString::fromStdString(peer.uuid);
            bool autoAccept = m_settings ? m_settings->getAutoAcceptForPeer(uuid) : false;
            return baseTooltip + "\n\nCheckbox: Auto-accept files from this peer (" +
                   (autoAccept ? "ENABLED" : "disabled") + ")";
        }

    case NameRole:
        return QString::fromStdString(peer.displayName);

    case IpRole:
        return QString::fromStdString(peer.ipAddress);

    case PortRole:
        return static_cast<uint>(peer.tcpPort);

    case LastSeenRole:
        // Convert time_point to milliseconds since epoch (for display purposes)
        return static_cast<qint64>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                peer.lastSeen.time_since_epoch()
            ).count()
        );

    case UuidRole:
        return QString::fromStdString(peer.uuid);

    case StatusRole:
        return static_cast<int>(peer.getStatus(m_timeoutMs));

    // TimeRemainingRole removed - binary status doesn't show countdown

    case IsActiveRole:
        return peer.getStatus(m_timeoutMs) != ExoSend::PeerStatus::Inactive;

    case AutoAcceptRole:
        {
            QString uuid = QString::fromStdString(peer.uuid);
            return m_settings ? m_settings->getAutoAcceptForPeer(uuid) : false;
        }

    default:
        return QVariant();
    }
}

QHash<int, QByteArray> PeerListModel::roleNames() const
{
    QHash<int, QByteArray> roles;
    roles[Qt::DisplayRole] = "display";
    roles[Qt::ToolTipRole] = "tooltip";
    roles[NameRole] = "name";
    roles[IpRole] = "ip";
    roles[PortRole] = "port";
    roles[LastSeenRole] = "lastSeen";
    roles[UuidRole] = "uuid";
    roles[StatusRole] = "status";
    // TimeRemainingRole removed - binary status doesn't show countdown
    roles[IsActiveRole] = "isActive";
    roles[AutoAcceptRole] = "autoAccept";
    return roles;
}

// ========================================================================
// Public Slots for DiscoveryService Integration
// ========================================================================

void PeerListModel::onPeerAdded(const ExoSend::PeerInfo& peer)
{
    int existingIndex = -1;
    size_t newSize = 0;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        existingIndex = findPeerIndexByUuid(peer.uuid);

        if (existingIndex >= 0) {
            // Peer exists - update it instead
            lock.unlock();
            onPeerUpdated(peer);
            return;
        }

        // Add new peer
        newSize = m_peers.size() + 1;
        m_peers.push_back(peer);
    }

    // Call begin/endInsertRows OUTSIDE the lock to prevent re-entrant deadlock
    beginInsertRows(QModelIndex(), static_cast<int>(newSize) - 1, static_cast<int>(newSize) - 1);
    endInsertRows();

    emit peerCountChanged(static_cast<int>(newSize));
    emit peerDiscovered(QString::fromStdString(peer.displayName));
}

void PeerListModel::onPeerUpdated(const ExoSend::PeerInfo& peer)
{
    int index = -1;
    bool needsAdd = false;
    QModelIndex modelIndex;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findPeerIndexByUuid(peer.uuid);

        if (index < 0) {
            // Peer doesn't exist - add it
            needsAdd = true;
        } else {
            // Update existing peer
            m_peers[index] = peer;
            // Create index while holding the lock (uses the index value)
            modelIndex = createIndex(index, 0);
        }
    }

    if (needsAdd) {
        onPeerAdded(peer);
        return;
    }

    // Emit notification OUTSIDE the lock
    emit dataChanged(modelIndex, modelIndex);
}

void PeerListModel::onPeerRemoved(const std::string& uuid)
{
    int index = -1;
    QString peerName;
    size_t newSize = 0;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findPeerIndexByUuid(uuid);

        if (index < 0) {
            return;
        }

        peerName = QString::fromStdString(m_peers[index].displayName);

        // Remove peer
        m_peers.erase(m_peers.begin() + index);
        newSize = m_peers.size();
    }

    // Call begin/endRemoveRows OUTSIDE the lock to prevent re-entrant deadlock
    beginRemoveRows(QModelIndex(), index, index);
    endRemoveRows();

    emit peerCountChanged(static_cast<int>(newSize));
    emit peerRemoved(peerName);
}

void PeerListModel::refreshPeerList()
{
    if (!m_discovery) {
        return;
    }

    // Get current peers from DiscoveryService
    auto peerList = m_discovery->getPeers();

    std::vector<std::string> newPeerUuids;
    std::vector<int> rowsToUpdate;
    std::vector<ExoSend::PeerInfo> peersToAdd;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);

        // Build list of UUIDs from DiscoveryService
        for (const auto& peer : peerList) {
            newPeerUuids.push_back(peer.uuid);
        }

        // Check each existing peer
        for (size_t i = 0; i < m_peers.size(); ++i) {
            const std::string& existingUuid = m_peers[i].uuid;

            // Find matching peer in new list
            auto it = std::find_if(peerList.begin(), peerList.end(),
                [&existingUuid](const ExoSend::PeerInfo& p) {
                    return p.uuid == existingUuid;
                });

            if (it != peerList.end()) {
                // Peer exists in both - check if data changed
                if (m_peers[i].lastSeen != it->lastSeen ||
                    m_peers[i].displayName != it->displayName ||
                    m_peers[i].ipAddress != it->ipAddress ||
                    m_peers[i].tcpPort != it->tcpPort) {
                    // Data changed - mark for update
                    rowsToUpdate.push_back(static_cast<int>(i));
                    m_peers[i] = *it;  // Update in place
                }
                // Remove from peerList so we don't add it again
                peerList.erase(it);
            }
            // If not found, peer was removed from DiscoveryService (handled by GC)
        }

        // Add remaining peers (new discoveries)
        for (auto& peer : peerList) {
            peersToAdd.push_back(std::move(peer));
        }
    }

    // Emit dataChanged for updated rows (no lock held)
    // SAFE: rowsToUpdate was collected under unique_lock (exclusive access),
    // and all modifications to m_peers are complete. No other thread can
    // modify m_peers until we release the unique_lock, so indices remain valid.
    for (int row : rowsToUpdate) {
        QModelIndex idx = createIndex(row, 0);
        emit dataChanged(idx, idx);
    }

    // Add new peers
    for (const auto& peer : peersToAdd) {
        onPeerAdded(peer);
    }

    // Remove peers that are no longer in DiscoveryService
    // (GC removes them from DiscoveryService, we need to remove from our cache)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        std::vector<int> rowsToRemove;

        for (size_t i = 0; i < m_peers.size(); ++i) {
            const std::string& uuid = m_peers[i].uuid;
            auto it = std::find(newPeerUuids.begin(), newPeerUuids.end(), uuid);
            if (it == newPeerUuids.end()) {
                // Peer not in new list - mark for removal
                rowsToRemove.push_back(static_cast<int>(i));
            }
        }

        // Remove in reverse order to maintain indices
        for (auto it = rowsToRemove.rbegin(); it != rowsToRemove.rend(); ++it) {
            int row = *it;
            std::string uuid = m_peers[row].uuid;
            lock.unlock();  // Unlock before calling onPeerRemoved which needs lock
            onPeerRemoved(uuid);
            lock.lock();
        }
    }

    // Emit peer count changed
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        emit peerCountChanged(static_cast<int>(m_peers.size()));
    }
}

// ========================================================================
// Utility Methods
// ========================================================================

QModelIndex PeerListModel::findPeerByUuid(const QString& uuid) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    int index = findPeerIndexByUuid(uuid.toStdString());
    if (index >= 0) {
        return createIndex(index, 0);
    }
    return QModelIndex();
}

ExoSend::PeerInfo PeerListModel::getPeerInfo(const QModelIndex& index) const
{
    if (!index.isValid() || index.row() >= rowCount()) {
        return ExoSend::PeerInfo();
    }

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_peers[index.row()];
}

// ========================================================================
// Private Methods
// ========================================================================

int PeerListModel::findPeerIndexByUuid(const std::string& uuid) const
{
    for (size_t i = 0; i < m_peers.size(); ++i) {
        if (m_peers[i].uuid == uuid) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

QString PeerListModel::formatPeerDisplay(const ExoSend::PeerInfo& peer) const
{
    QString name = QString::fromStdString(peer.displayName);
    QString ip = QString::fromStdString(peer.ipAddress);
    uint port = peer.tcpPort;

    return QString("%1 (%2:%3)").arg(name).arg(ip).arg(port);
}

QString PeerListModel::formatPeerTooltip(const ExoSend::PeerInfo& peer) const
{
    QString name = QString::fromStdString(peer.displayName);
    QString ip = QString::fromStdString(peer.ipAddress);
    uint port = peer.tcpPort;
    QString uuid = QString::fromStdString(peer.uuid);

    // Calculate time since last seen
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.lastSeen);
    qint64 elapsedMs = static_cast<qint64>(elapsed.count());

    QString timeAgo;

    if (elapsedMs < 60000) {
        timeAgo = QString("just now");
    } else if (elapsedMs < 3600000) {
        int mins = static_cast<int>(elapsedMs / 60000);
        timeAgo = QString("%1 minute%2 ago").arg(mins).arg(mins > 1 ? "s" : "");
    } else {
        int hours = static_cast<int>(elapsedMs / 3600000);
        timeAgo = QString("%1 hour%2 ago").arg(hours).arg(hours > 1 ? "s" : "");
    }

    return QString("Name: %1\nIP: %2\nPort: %3\nUUID: %4\nLast seen: %5")
        .arg(name)
        .arg(ip)
        .arg(port)
        .arg(uuid)
        .arg(timeAgo);
}

void PeerListModel::updatePeerStatuses(uint32_t timeoutMs)
{
    // FIX: Hold lock for entire function to prevent TOCTOU race condition
    // The lock prevents m_peers from being modified between collecting
    // indices and using them to create QModelIndex. Previously, the lock
    // was released after collecting indices, creating a race window where
    // refreshPeerList() could modify m_peers, invalidating the indices.
    std::vector<std::pair<int, ExoSend::PeerStatus>> statusChanges;

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    statusChanges.reserve(m_peers.size());

    for (size_t i = 0; i < m_peers.size(); ++i) {
        ExoSend::PeerStatus newStatus = m_peers[i].getStatus(timeoutMs);
        statusChanges.push_back({static_cast<int>(i), newStatus});
    }

    // Emit all changes in one batch (lock still held)
    // Note: Lock must be held when calling createIndex to ensure
    // row indices are still valid when QModelIndex is created.
    for (const auto& [row, status] : statusChanges) {
        QModelIndex modelIndex = createIndex(row, 0);
        emit dataChanged(modelIndex, modelIndex, {
            StatusRole,
            IsActiveRole
            // TimeRemainingRole removed
        });
    }
    // Lock released automatically when function returns
}

//=============================================================================
// Auto-Accept Support
//=============================================================================

bool PeerListModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
    if (!index.isValid() || index.row() >= rowCount()) {
        return false;
    }

    if (role == AutoAcceptRole) {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        const ExoSend::PeerInfo& peer = m_peers[index.row()];
        QString uuid = QString::fromStdString(peer.uuid);
        lock.unlock();

        bool enabled = value.toBool();
        if (m_settings) {
            m_settings->setAutoAcceptForPeer(uuid, enabled);
        }

        emit dataChanged(index, index, {AutoAcceptRole});
        return true;
    }

    return QAbstractListModel::setData(index, value, role);
}

void PeerListModel::setAutoAccept(const QString& uuid, bool enabled)
{
    if (m_settings) {
        m_settings->setAutoAcceptForPeer(uuid, enabled);

        // Find and update the peer in our list
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        for (size_t i = 0; i < m_peers.size(); ++i) {
            if (m_peers[i].uuid == uuid.toStdString()) {
                QModelIndex idx = createIndex(static_cast<int>(i), 0);
                lock.unlock();
                emit dataChanged(idx, idx, {AutoAcceptRole});
                break;
            }
        }
    }
}

bool PeerListModel::getAutoAccept(const QString& uuid) const
{
    return m_settings ? m_settings->getAutoAcceptForPeer(uuid) : false;
}
