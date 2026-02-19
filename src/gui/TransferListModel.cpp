/**
 * @file TransferListModel.cpp
 * @brief Qt list model for file transfers implementation
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/TransferListModel.h"
#include "exosend/Debug.h"
#include "exosend/ThreadSafeLog.h"
#include <QModelIndex>
#include <QPersistentModelIndex>
#include <QTimer>
#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <mutex>
#include <iostream>

// ========================================================================
// Crash logging (trace support)
// ========================================================================

namespace {
    // Thread-safe logging macro - uses ThreadSafeLog for all crash logging
    #define LogTransferModelCrash(msg) ExoSend::ThreadSafeLog::log(msg)
} // anonymous namespace

// ========================================================================
// TransferItem Methods
// ========================================================================

QString TransferItem::getStatusString() const
{
    switch (status) {
    case Idle:
        return "Idle";
    case Negotiating:
        return "Connecting...";
    case Transferring:
        return "Transferring";
    case Completed:
        return "Completed";
    case Failed:
        return "Failed";
    case Cancelled:
        return "Cancelled";
    case Busy:
        return "Remote Busy";
    default:
        return "Unknown";
    }
}

QString TransferItem::getFormattedFileSize() const
{
    const qint64 KB = 1024;
    const qint64 MB = 1024 * KB;
    const qint64 GB = 1024 * MB;

    if (fileSize < KB) {
        return QString("%1 B").arg(fileSize);
    } else if (fileSize < MB) {
        return QString("%1 KB").arg(fileSize / static_cast<double>(KB), 0, 'f', 1);
    } else if (fileSize < GB) {
        return QString("%1 MB").arg(fileSize / static_cast<double>(MB), 0, 'f', 1);
    } else {
        return QString("%1 GB").arg(fileSize / static_cast<double>(GB), 0, 'f', 2);
    }
}

QString TransferItem::getFormattedSpeed() const
{
    const qint64 KB = 1024;
    const qint64 MB = 1024 * KB;
    const qint64 GB = 1024 * MB;

    if (speed < 0.5) {
        return "0 B/s";
    } else if (speed < KB) {
        return QString("%1 B/s").arg(static_cast<int>(speed));
    } else if (speed < MB) {
        return QString("%1 KB/s").arg(speed / KB, 0, 'f', 1);
    } else if (speed < GB) {
        return QString("%1 MB/s").arg(speed / MB, 0, 'f', 1);
    } else {
        return QString("%1 GB/s").arg(speed / GB, 0, 'f', 2);
    }
}

QString TransferItem::getFormattedEta() const
{
    if (eta < 0) {
        return "Unknown";
    }

    int seconds = static_cast<int>(eta);

    if (seconds < 60) {
        return QString("0:%1").arg(seconds, 2, 10, QChar('0'));
    } else if (seconds < 3600) {
        int mins = seconds / 60;
        int secs = seconds % 60;
        return QString("%1:%2").arg(mins).arg(secs, 2, 10, QChar('0'));
    } else {
        int hours = seconds / 3600;
        int mins = (seconds % 3600) / 60;
        return QString("%1:%2:%3").arg(hours).arg(mins, 2, 10, QChar('0')).arg((seconds % 3600) % 60, 2, 10, QChar('0'));
    }
}

// ========================================================================
// TransferListModel Constructor / Destructor
// ========================================================================

TransferListModel::TransferListModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_transfers()
    , m_mutex()
{
}

// ========================================================================
// QAbstractListModel Interface
// ========================================================================

int TransferListModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return static_cast<int>(m_transfers.size());
}

QVariant TransferListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= rowCount()) {
        return QVariant();
    }

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const TransferItem* item = m_transfers[index.row()].get();

    switch (role) {
    case Qt::DisplayRole:
        return QString("%1 - %2").arg(item->filename).arg(item->getStatusString());

    case Qt::ToolTipRole:
        return QString("File: %1\nPeer: %2\nStatus: %3\nProgress: %4%\nSpeed: %5\nETA: %6")
            .arg(item->filename)
            .arg(item->peerName)
            .arg(item->getStatusString())
            .arg(item->getProgress())
            .arg(item->getFormattedSpeed())
            .arg(item->getFormattedEta());

    case SessionIdRole:
        return item->sessionId;

    case FilenameRole:
        return item->filename;

    case FileSizeRole:
        return item->fileSize;

    case BytesTransferredRole:
        return item->bytesTransferred;

    case ProgressRole:
        return item->getProgress();

    case PeerNameRole:
        return item->peerName;

    case TypeRole:
        return static_cast<int>(item->type);

    case StatusRole:
        return static_cast<int>(item->status);

    case SpeedRole:
        return item->speed;

    case EtaRole:
        return item->eta;

    case LocalPathRole:
        return item->localPath;

    case ErrorMessageRole:
        return item->errorMessage;

    default:
        return QVariant();
    }
}

QHash<int, QByteArray> TransferListModel::roleNames() const
{
    QHash<int, QByteArray> roles;
    roles[Qt::DisplayRole] = "display";
    roles[Qt::ToolTipRole] = "tooltip";
    roles[SessionIdRole] = "sessionId";
    roles[FilenameRole] = "filename";
    roles[FileSizeRole] = "fileSize";
    roles[BytesTransferredRole] = "bytesTransferred";
    roles[ProgressRole] = "progress";
    roles[PeerNameRole] = "peerName";
    roles[TypeRole] = "type";
    roles[StatusRole] = "status";
    roles[SpeedRole] = "speed";
    roles[EtaRole] = "eta";
    roles[LocalPathRole] = "localPath";
    roles[ErrorMessageRole] = "errorMessage";
    return roles;
}

// ========================================================================
// Public Slots for Transfer Events
// ========================================================================

void TransferListModel::onTransferStarted(const QString& sessionId, const QString& filename,
                                        const QString& peerName, TransferItem::Type type)
{
    LogTransferModelCrash("=== onTransferStarted START ===");
    LogTransferModelCrash("  Session ID: " + sessionId);

    int insertRow = -1;
    int active = 0;
    int completed = 0;

    auto item = std::make_unique<TransferItem>();
    item->sessionId = sessionId;
    item->filename = filename;
    item->fileSize = 0;
    item->bytesTransferred = 0;
    item->peerName = peerName;
    item->type = type;
    item->status = TransferItem::Negotiating;
    item->speed = 0.0;
    item->eta = -1;
    item->localPath.clear();
    item->errorMessage.clear();

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (findTransferIndex(sessionId) >= 0) {
            LogTransferModelCrash("  onTransferStarted: Already tracking, returning");
            return;
        }
        insertRow = static_cast<int>(m_transfers.size());
    }

    // Do not hold m_mutex while notifying Qt model observers.
    beginInsertRows(QModelIndex(), insertRow, insertRow);
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_transfers.push_back(std::move(item));
        {
            std::lock_guard<std::mutex> validLock(m_validSessionsMutex);
            m_validSessions.insert(sessionId);
        }
        getTransferCountsUnlocked(active, completed);
    }
    endInsertRows();

    emit transferCountChanged(active, completed);
    LogTransferModelCrash("=== onTransferStarted END ===");
}

void TransferListModel::onTransferProgress(const QString& sessionId, qint64 bytesTransferred,
                                          qint64 bytesTotal, double speed, qint64 eta)
{
    int index = -1;
    QModelIndex modelIndex;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->fileSize = bytesTotal;
        item->bytesTransferred = bytesTransferred;
        item->speed = speed;
        item->eta = eta;
        item->status = TransferItem::Transferring;

        // Create index while holding lock
        modelIndex = createIndex(index, 0);
    }

    // Emit notification OUTSIDE the lock
    emit dataChanged(modelIndex, modelIndex);
}

void TransferListModel::onTransferCompleted(const QString& sessionId, const QString& localPath)
{
    // Trace: Log onTransferCompleted entry
    LogTransferModelCrash("=== onTransferCompleted START ===");
    LogTransferModelCrash("  Session ID: " + sessionId);

    // Note: Check if session is still valid
    {
        std::lock_guard<std::mutex> validLock(m_validSessionsMutex);
        if (m_validSessions.count(sessionId) == 0) {
            LogTransferModelCrash("  onTransferCompleted: Session NOT in valid set, returning early");
            return;
        }
        // Mark as completed (remove from valid set)
        m_validSessions.erase(sessionId);
    }

    int index = -1;
    QString filename;
    int active = 0, completed = 0;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            LogTransferModelCrash("  onTransferCompleted: Transfer NOT found in model, returning early");
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->status = TransferItem::Completed;
        item->bytesTransferred = item->fileSize;
        item->speed = 0.0;
        item->eta = 0;
        item->localPath = localPath;
        filename = item->filename;

        // Calculate counts while holding lock
        getTransferCountsUnlocked(active, completed);
    }

    // Note: Ensure signals are emitted from the main thread using QueuedConnection
    // This prevents Qt event loop corruption when called from worker threads
    // The previous direct emit was causing race conditions and application exit

    // Create the model index for dataChanged signal
    QModelIndex modelIndex = createIndex(index, 0);

    // Emit signals via invokeMethod to ensure they run on main thread
    LogTransferModelCrash("  onTransferCompleted: About to emit dataChanged (queued)");
    QMetaObject::invokeMethod(this, [this, modelIndex]() {
        emit dataChanged(modelIndex, modelIndex);
    }, Qt::QueuedConnection);
    LogTransferModelCrash("  onTransferCompleted: dataChanged queued");

    LogTransferModelCrash("  onTransferCompleted: About to emit transferFinished (queued)");
    QMetaObject::invokeMethod(this, [this, filename]() {
        emit transferFinished(filename, true);
    }, Qt::QueuedConnection);
    LogTransferModelCrash("  onTransferCompleted: transferFinished queued");

    LogTransferModelCrash("  onTransferCompleted: About to emit transferCountChanged (queued)");
    QMetaObject::invokeMethod(this, [this, active, completed]() {
        emit transferCountChanged(active, completed);
    }, Qt::QueuedConnection);
    LogTransferModelCrash("  onTransferCompleted: transferCountChanged queued");

    // Trace: Log onTransferCompleted exit
    LogTransferModelCrash("=== onTransferCompleted END ===");
}

void TransferListModel::onTransferFailed(const QString& sessionId, const QString& error)
{
    int index = -1;
    QString filename;
    QModelIndex modelIndex;
    int active = 0, completed = 0;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->status = TransferItem::Failed;
        item->speed = 0.0;
        item->eta = -1;
        item->errorMessage = error;
        filename = item->filename;

        // Create index while holding lock
        modelIndex = createIndex(index, 0);

        // Calculate counts while holding lock
        getTransferCountsUnlocked(active, completed);
    }

    // Note: Use QueuedConnection to ensure signals run on main thread
    // This prevents Qt event loop corruption when called from worker threads
    QMetaObject::invokeMethod(this, [this, modelIndex]() {
        emit dataChanged(modelIndex, modelIndex);
    }, Qt::QueuedConnection);

    QMetaObject::invokeMethod(this, [this, filename]() {
        emit transferFinished(filename, false);
    }, Qt::QueuedConnection);

    QMetaObject::invokeMethod(this, [this, active, completed]() {
        emit transferCountChanged(active, completed);
    }, Qt::QueuedConnection);
}

void TransferListModel::onTransferCancelled(const QString& sessionId)
{
    int index = -1;
    QModelIndex modelIndex;
    int active = 0, completed = 0;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->status = TransferItem::Cancelled;
        item->speed = 0.0;
        item->eta = -1;

        // Create index while holding lock
        modelIndex = createIndex(index, 0);

        // Calculate counts while holding lock
        getTransferCountsUnlocked(active, completed);
    }

    // Emit notifications OUTSIDE the lock
    emit dataChanged(modelIndex, modelIndex);
    emit transferCountChanged(active, completed);
}

void TransferListModel::updateStatus(const QString& sessionId, TransferItem::Status status)
{
    int index = -1;
    QModelIndex modelIndex;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->status = status;

        // Create index while holding lock
        modelIndex = createIndex(index, 0);
    }

    // Emit notification OUTSIDE the lock
    emit dataChanged(modelIndex, modelIndex);
}

void TransferListModel::updateFilename(const QString& sessionId, const QString& filename)
{
    int index = -1;
    QModelIndex modelIndex;

    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        index = findTransferIndex(sessionId);

        if (index < 0) {
            return;  // Not found
        }

        TransferItem* item = m_transfers[index].get();
        item->filename = filename;

        // Create index while holding lock
        modelIndex = createIndex(index, 0);
    }

    // Emit notification OUTSIDE the lock to refresh the display
    emit dataChanged(modelIndex, modelIndex, { Qt::DisplayRole, FilenameRole });
}

// ========================================================================
// Utility Methods
// ========================================================================

QModelIndex TransferListModel::findTransfer(const QString& sessionId) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    int index = findTransferIndex(sessionId);
    if (index >= 0) {
        return createIndex(index, 0);
    }
    return QModelIndex();
}

TransferItem TransferListModel::getTransfer(const QModelIndex& index) const
{
    if (!index.isValid() || index.row() >= rowCount()) {
        return TransferItem();
    }

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return *m_transfers[index.row()];
}

void TransferListModel::clearCompleted()
{
    std::vector<int> toRemove;
    int active = 0, completed = 0;

    // Find indices to remove while holding lock
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        for (int i = static_cast<int>(m_transfers.size()) - 1; i >= 0; --i) {
            if (m_transfers[i]->status == TransferItem::Completed ||
                m_transfers[i]->status == TransferItem::Failed ||
                m_transfers[i]->status == TransferItem::Cancelled) {
                toRemove.push_back(i);
            }
        }
    }

    // Remove each item. Do not hold m_mutex while issuing Qt row notifications.
    for (int index : toRemove) {
        bool canRemove = false;
        {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            canRemove = (index < static_cast<int>(m_transfers.size()));
        }

        if (!canRemove) {
            continue;
        }

        beginRemoveRows(QModelIndex(), index, index);
        {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            m_transfers.erase(m_transfers.begin() + index);
        }
        endRemoveRows();
    }

    // Emit count changed
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        getTransferCountsUnlocked(active, completed);
    }
    emit transferCountChanged(active, completed);
}

void TransferListModel::getTransferCounts(int& activeCount, int& completedCount) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    getTransferCountsUnlocked(activeCount, completedCount);
}

void TransferListModel::getTransferCountsUnlocked(int& activeCount, int& completedCount) const
{
    activeCount = 0;
    completedCount = 0;

    for (const auto& transfer : m_transfers) {
        if (transfer->status == TransferItem::Transferring ||
            transfer->status == TransferItem::Negotiating ||
            transfer->status == TransferItem::Idle) {
            ++activeCount;
        } else if (transfer->status == TransferItem::Completed ||
                   transfer->status == TransferItem::Failed ||
                   transfer->status == TransferItem::Cancelled) {
            ++completedCount;
        }
    }
}

// ========================================================================
// Private Methods
// ========================================================================

int TransferListModel::findTransferIndex(const QString& sessionId) const
{
    for (size_t i = 0; i < m_transfers.size(); ++i) {
        if (m_transfers[i]->sessionId == sessionId) {
            return static_cast<int>(i);
        }
    }
    return -1;
}
