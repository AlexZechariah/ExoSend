/**
 * @file TransferListModel.h
 * @brief Qt list model for active and completed transfers
 *
 * This class provides a Qt model interface for displaying file transfers
 * with progress information in the GUI.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_TRANSFERLISTMODEL_H
#define EXOSEND_QTUI_TRANSFERLISTMODEL_H

#include <QAbstractListModel>
#include <QObject>
#include <QString>
#include <QVariant>
#include <QVector>
#include <QHash>
#include <QByteArray>
#include <memory>
#include <vector>
#include <shared_mutex>
#include <unordered_set>
#include <mutex>

/**
 * @struct TransferItem
 * @brief Data structure representing a single file transfer
 *
 * Contains all information needed to display and track a transfer
 * in the GUI, including progress, speed, ETA, and status.
 */
struct TransferItem {
    QString sessionId;        ///< Unique session identifier
    QString filename;         ///< Name of file being transferred
    qint64 fileSize;          ///< Total file size in bytes
    qint64 bytesTransferred;  ///< Bytes transferred so far
    QString peerName;         ///< Name of peer (sender or receiver)

    enum Type {
        Incoming,  ///< Receiving file from peer
        Outgoing   ///< Sending file to peer
    } type;

    enum Status {
        Idle,        ///< Transfer not started
        Negotiating, ///< Handshake in progress
        Transferring,///< Data transfer in progress
        Completed,   ///< Transfer finished successfully
        Failed,      ///< Transfer failed (see errorMessage)
        Cancelled,   ///< Transfer cancelled by user
        Busy         ///< Remote peer busy (can't accept)
    } status;

    double speed;   ///< Current speed in bytes/second
    qint64 eta;     ///< Estimated time remaining in seconds
    QString localPath;   ///< Local file path (for incoming)
    QString errorMessage; ///< Error message if status == Failed

    /**
     * @brief Get progress percentage (0-100)
     * @return Progress as integer percentage
     */
    int getProgress() const {
        if (fileSize <= 0) return 0;
        return static_cast<int>((bytesTransferred * 100) / fileSize);
    }

    /**
     * @brief Get status as human-readable string
     * @return Status description
     */
    QString getStatusString() const;

    /**
     * @brief Get type as human-readable string
     * @return "Incoming" or "Outgoing"
     */
    QString getTypeString() const {
        return (type == Incoming) ? "Incoming" : "Outgoing";
    }

    /**
     * @brief Format file size for display
     * @return Formatted size (e.g., "245.8 MB")
     */
    QString getFormattedFileSize() const;

    /**
     * @brief Format speed for display
     * @return Formatted speed (e.g., "15.5 MB/s")
     */
    QString getFormattedSpeed() const;

    /**
     * @brief Format ETA for display
     * @return Formatted ETA (e.g., "2:30" or "Unknown")
     */
    QString getFormattedEta() const;
};

/**
 * @class TransferListModel
 * @brief Qt model for file transfer list
 *
 * This model tracks all file transfers (active and completed)
 * and provides a Qt Model/View interface for display.
 *
 * Thread Safety:
 * - Maintains its own transfer cache for thread-safe access
 * - All public methods are thread-safe
 * - UI can safely access from main thread without blocking
 *
 * Lifecycle:
 * - Transfers are added via onTransferStarted()
 * - Progress updates via onTransferProgress()
 * - Completion via onTransferCompleted()
 * - Failure via onTransferFailed()
 * - Cancellation via onTransferCancelled()
 */
class TransferListModel : public QAbstractListModel {
    Q_OBJECT

public:
    /**
     * @brief Custom data roles for transfer data access
     */
    enum TransferRoles {
        SessionIdRole = Qt::UserRole + 1,  ///< Session ID
        FilenameRole = Qt::UserRole + 2,   ///< File name
        FileSizeRole = Qt::UserRole + 3,   ///< Total file size
        BytesTransferredRole = Qt::UserRole + 4, ///< Bytes transferred
        ProgressRole = Qt::UserRole + 5,   ///< Progress percentage (0-100)
        PeerNameRole = Qt::UserRole + 6,   ///< Peer name
        TypeRole = Qt::UserRole + 7,       ///< Transfer type (Incoming/Outgoing)
        StatusRole = Qt::UserRole + 8,     ///< Transfer status enum
        SpeedRole = Qt::UserRole + 9,      ///< Speed in bytes/sec
        EtaRole = Qt::UserRole + 10,       ///< ETA in seconds
        LocalPathRole = Qt::UserRole + 11, ///< Local file path
        ErrorMessageRole = Qt::UserRole + 12 ///< Error message if failed
    };

    /**
     * @brief Constructor
     * @param parent Parent QObject
     */
    explicit TransferListModel(QObject* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~TransferListModel() override = default;

    // ========================================================================
    // QAbstractListModel Interface
    // ========================================================================

    /**
     * @brief Get number of transfers
     * @return Number of transfers in the model
     */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    /**
     * @brief Get transfer data
     * @param index Model index
     * @param role Data role
     * @return Requested data
     */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Get role mapping
     * @return Hash of role enum to string identifiers
     */
    QHash<int, QByteArray> roleNames() const override;

    // ========================================================================
    // Public Slots for Transfer Events
    // ========================================================================

public slots:
    /**
     * @brief Called when a new transfer starts
     * @param sessionId Unique session identifier
     * @param filename File name
     * @param peerName Peer name
     * @param type Transfer type (Incoming or Outgoing)
     */
    void onTransferStarted(const QString& sessionId, const QString& filename,
                          const QString& peerName, TransferItem::Type type);

    /**
     * @brief Called when transfer makes progress
     * @param sessionId Session identifier
     * @param bytesTransferred Bytes transferred so far
     * @param bytesTotal Total file size
     * @param speed Current speed (bytes/sec)
     * @param eta Estimated time remaining (seconds)
     */
    void onTransferProgress(const QString& sessionId, qint64 bytesTransferred,
                           qint64 bytesTotal, double speed, qint64 eta);

    /**
     * @brief Called when transfer completes successfully
     * @param sessionId Session identifier
     * @param localPath Local file path (for incoming transfers)
     */
    void onTransferCompleted(const QString& sessionId, const QString& localPath);

    /**
     * @brief Called when transfer fails
     * @param sessionId Session identifier
     * @param error Error message
     */
    void onTransferFailed(const QString& sessionId, const QString& error);

    /**
     * @brief Called when transfer is cancelled
     * @param sessionId Session identifier
     */
    void onTransferCancelled(const QString& sessionId);

    /**
     * @brief Update transfer status
     * @param sessionId Session identifier
     * @param status New status
     */
    void updateStatus(const QString& sessionId, TransferItem::Status status);

    /**
     * @brief Update the filename for an existing transfer
     * @param sessionId Session ID of the transfer to update
     * @param filename New filename to set
     *
     * This is used for incoming transfers where the filename is not
     * known until after the TransferSession accept callback completes.
     */
    void updateFilename(const QString& sessionId, const QString& filename);

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * @brief Find transfer by session ID
     * @param sessionId Session ID to find
     * @return Model index, or invalid if not found
     */
    QModelIndex findTransfer(const QString& sessionId) const;

    /**
     * @brief Get transfer item at index
     * @param index Model index
     * @return Copy of TransferItem, or empty item if invalid
     */
    TransferItem getTransfer(const QModelIndex& index) const;

    /**
     * @brief Clear all completed transfers
     *
     * Removes all transfers with status Completed or Failed.
     * Active transfers are preserved.
     */
    void clearCompleted();

    /**
     * @brief Get counts of active and completed transfers
     * @param activeCount Output parameter for active count
     * @param completedCount Output parameter for completed count
     */
    void getTransferCounts(int& activeCount, int& completedCount) const;

signals:
    /**
     * @brief Emitted when transfer counts change
     * @param active Number of active transfers
     * @param completed Number of completed transfers
     */
    void transferCountChanged(int active, int completed);

    /**
     * @brief Emitted when a transfer completes
     * @param filename File name
     * @param success True if successful, false if failed
     */
    void transferFinished(const QString& filename, bool success);

private:
    /**
     * @brief Count active/completed transfers (caller must hold m_mutex)
     * @param activeCount Output parameter for active count
     * @param completedCount Output parameter for completed count
     */
    void getTransferCountsUnlocked(int& activeCount, int& completedCount) const;

    /**
     * @brief Internal helper to find transfer index by session ID
     * @param sessionId Session ID to find
     * @return Index in m_transfers, or -1 if not found
     */
    int findTransferIndex(const QString& sessionId) const;

private:
    std::vector<std::unique_ptr<TransferItem>> m_transfers;  ///< Transfer list
    mutable std::shared_mutex m_mutex;                        ///< Thread safety

    // Note: Session validity tracking to prevent access to invalid session data
    std::unordered_set<QString> m_validSessions;              ///< Track valid session IDs
    std::mutex m_validSessionsMutex;                          ///< Protects m_validSessions
};

#endif // EXOSEND_QTUI_TRANSFERLISTMODEL_H
