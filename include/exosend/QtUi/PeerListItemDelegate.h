/**
 * @file PeerListItemDelegate.h
 * @brief Custom delegate for painting peer list items with status indicators
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#ifndef EXOSEND_QTUI_PEERLISTITEMDELEGATE_H
#define EXOSEND_QTUI_PEERLISTITEMDELEGATE_H

#include <QStyledItemDelegate>
#include <QPainter>
#include <QStyleOptionViewItem>
#include <QMouseEvent>
#include "exosend/PeerInfo.h"

// Forward declarations
class QAbstractItemModel;

/**
 * @class PeerListItemDelegate
 * @brief Custom delegate for rendering peer list items with status indicators
 *
 * This delegate provides custom painting for peer list items including:
 * - Status indicator dots (green/yellow/red)
 * - Opacity changes for inactive peers
 * - Countdown timer display for peers near timeout
 *
 * Thread Safety:
 * - All painting happens on the GUI thread
 * - No internal state is maintained
 */
class PeerListItemDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    /**
     * @brief Constructor
     * @param parent Parent QObject
     */
    explicit PeerListItemDelegate(QObject* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~PeerListItemDelegate() override = default;

    /**
     * @brief Paint a peer list item
     * @param painter Painter to use
     * @param option Style options
     * @param index Model index of item to paint
     *
     * Renders the item with:
     * - Status indicator dot (colored based on peer status)
     * - Peer display name
     * - Countdown timer for inactive peers
     * - Reduced opacity for inactive peers
     */
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;

    /**
     * @brief Handle editor events for checkbox interaction
     * @param event Event that occurred
     * @param model Model containing the data
     * @param option Style options
     * @param index Model index
     * @return true if event was handled
     */
    bool editorEvent(QEvent* event, QAbstractItemModel* model,
                     const QStyleOptionViewItem& option, const QModelIndex& index) override;

private:
    /**
     * @brief Draw status indicator dot
     * @param painter Painter to use
     * @param rect Rectangle for dot position
     * @param status Peer status
     */
    void drawStatusIndicator(QPainter* painter, const QRect& rect,
                            ExoSend::PeerStatus status) const;
};

#endif // EXOSEND_QTUI_PEERLISTITEMDELEGATE_H
