/**
 * @file PeerListItemDelegate.cpp
 * @brief Custom delegate for painting peer list items with status indicators
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/QtUi/PeerListItemDelegate.h"
#include "exosend/QtUi/PeerListModel.h"
#include <QPainter>
#include <QBrush>
#include <QPen>
#include <QApplication>
#include <QDebug>
#include <QMouseEvent>

//=============================================================================
// Constructor / Destructor
//=============================================================================

PeerListItemDelegate::PeerListItemDelegate(QObject* parent)
    : QStyledItemDelegate(parent) {
}

//=============================================================================
// Painting
//=============================================================================

void PeerListItemDelegate::paint(QPainter* painter,
                                const QStyleOptionViewItem& option,
                                const QModelIndex& index) const {
    if (!index.isValid()) {
        return;
    }

    // Get peer status information
    int statusInt = index.data(PeerListModel::StatusRole).toInt();
    ExoSend::PeerStatus status = static_cast<ExoSend::PeerStatus>(statusInt);
    bool isActive = index.data(PeerListModel::IsActiveRole).toBool();
    bool autoAccept = index.data(PeerListModel::AutoAcceptRole).toBool();

    // Get display text
    QString text = index.data(Qt::DisplayRole).toString();

    // Create a copy of option for modification
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    painter->save();

    if (!isActive) {
        painter->setOpacity(0.5);
    }

    // Draw background
    if (opt.state & QStyle::State_Selected) {
        painter->fillRect(opt.rect, opt.palette.brush(QPalette::Highlight));
    }

    // Calculate positions
    // Status indicator on the left (20x20px area)
    QRect indicatorRect = opt.rect.adjusted(5, 0, 0, 0);
    indicatorRect.setWidth(20);

    // Text area (after indicator, leave space for checkbox on right)
    QRect textRect = opt.rect.adjusted(30, 0, -35, 0);

    // Checkbox area (on right side, 24x24px)
    QRect checkboxRect = opt.rect.adjusted(opt.rect.width() - 30, 0, 0, 0);
    checkboxRect.setWidth(24);
    checkboxRect.setHeight(24);
    checkboxRect.moveTop(opt.rect.top() + (opt.rect.height() - 24) / 2);

    // Draw status indicator
    drawStatusIndicator(painter, indicatorRect, status);

    // Draw checkbox
    QStyleOptionButton checkboxStyle;
    checkboxStyle.rect = checkboxRect;
    checkboxStyle.state = QStyle::State_Enabled;
    if (autoAccept) {
        checkboxStyle.state |= QStyle::State_On;
    } else {
        checkboxStyle.state |= QStyle::State_Off;
    }

    // Hover state for checkbox
    if (opt.state & QStyle::State_MouseOver) {
        checkboxStyle.state |= QStyle::State_MouseOver;
    }

    QApplication::style()->drawControl(QStyle::CE_CheckBox, &checkboxStyle, painter);

    // Set text color
    if (isActive) {
        painter->setPen(opt.palette.color(QPalette::Text));
    } else {
        painter->setPen(opt.palette.color(QPalette::Disabled, QPalette::Text));
    }

    // Draw text
    painter->drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter, text);

    painter->restore();
}

//=============================================================================
// Private Methods
//=============================================================================

void PeerListItemDelegate::drawStatusIndicator(QPainter* painter,
                                              const QRect& rect,
                                              ExoSend::PeerStatus status) const {
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing);

    // Calculate dot size and position
    int dotSize = 12;
    QRect dotRect = rect;
    dotRect.setWidth(dotSize);
    dotRect.setHeight(dotSize);
    dotRect.moveTop(rect.top() + (rect.height() - dotSize) / 2);

    // Choose color based on status (simplified binary: Green=running, Red=quit)
    QColor color;
    switch (status) {
        case ExoSend::PeerStatus::Active:
            // Green - peer is running
            color = QColor(76, 175, 80);
            break;
        case ExoSend::PeerStatus::Warning:
            // Should not happen with simplified status, treat as Active
            color = QColor(76, 175, 80);
            break;
        case ExoSend::PeerStatus::Inactive:
            // Red - peer has quit
            color = QColor(211, 47, 47);
            break;
    }

    // Draw the dot
    painter->setBrush(QBrush(color));
    painter->setPen(Qt::NoPen);
    painter->drawEllipse(dotRect);

    painter->restore();
}

//=============================================================================
// Event Handling
//=============================================================================

bool PeerListItemDelegate::editorEvent(QEvent* event, QAbstractItemModel* model,
                                       const QStyleOptionViewItem& option,
                                       const QModelIndex& index)
{
    if (!index.isValid() || event->type() != QEvent::MouseButtonRelease) {
        return QStyledItemDelegate::editorEvent(event, model, option, index);
    }

    QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);

    // Calculate checkbox area (on right side, matching paint method)
    QRect checkboxRect = option.rect.adjusted(option.rect.width() - 30, 0, 0, 0);
    checkboxRect.setWidth(24);
    checkboxRect.setHeight(24);
    checkboxRect.moveTop(option.rect.top() + (option.rect.height() - 24) / 2);

    // Check if click was on checkbox
    if (checkboxRect.contains(mouseEvent->pos())) {
        // Toggle auto-accept
        bool current = index.data(PeerListModel::AutoAcceptRole).toBool();
        model->setData(index, !current, PeerListModel::AutoAcceptRole);
        return true;
    }

    return QStyledItemDelegate::editorEvent(event, model, option, index);
}
