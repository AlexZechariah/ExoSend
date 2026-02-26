#include "exosend/QtUi/DragDropListView.h"
#include <QMimeData>
#include <QPainter>

DragDropListView::DragDropListView(QWidget* parent)
    : QListView(parent)
{
    setAcceptDrops(true);
    viewport()->setAcceptDrops(true);
}

void DragDropListView::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        m_dragActive = true;
        viewport()->update();
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void DragDropListView::dragMoveEvent(QDragMoveEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void DragDropListView::dragLeaveEvent(QDragLeaveEvent* event)
{
    m_dragActive = false;
    viewport()->update();
    QListView::dragLeaveEvent(event);
}

void DragDropListView::dropEvent(QDropEvent* event)
{
    m_dragActive = false;
    viewport()->update();
    const QMimeData* mime = event->mimeData();
    if (mime->hasUrls()) {
        event->acceptProposedAction();
        emit filesDropped(mime->urls());
    } else {
        event->ignore();
    }
}

void DragDropListView::paintEvent(QPaintEvent* event)
{
    QListView::paintEvent(event);

    QPainter painter(viewport());

    // Empty state: gray hint text when no peers are present and not dragging
    if (!m_dragActive && model() && model()->rowCount() == 0) {
        painter.save();
        painter.setPen(QColor(160, 160, 160));
        QFont f = painter.font();
        f.setPointSize(9);
        painter.setFont(f);
        painter.drawText(viewport()->rect(), Qt::AlignCenter,
                         "No peers discovered\nSearching...");
        painter.restore();
        return;
    }

    // Drag hover overlay: semi-transparent blue fill + border + prompt text
    if (m_dragActive) {
        painter.save();
        painter.fillRect(viewport()->rect(), QColor(0, 120, 215, 28));
        painter.setPen(QPen(QColor(0, 120, 215), 2));
        painter.drawRect(viewport()->rect().adjusted(1, 1, -1, -1));
        painter.setPen(QColor(0, 120, 215));
        QFont f = painter.font();
        f.setPointSize(11);
        f.setBold(true);
        painter.setFont(f);
        painter.drawText(viewport()->rect(), Qt::AlignCenter, "Drop files to send");
        painter.restore();
    }
}
