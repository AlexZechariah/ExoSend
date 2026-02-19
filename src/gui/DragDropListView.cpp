#include "exosend/QtUi/DragDropListView.h"
#include <QMimeData>

DragDropListView::DragDropListView(QWidget* parent)
    : QListView(parent)
{
    // Enable this widget to accept drop events
    setAcceptDrops(true);
    // Enable the viewport to accept drop events (QListView requirement)
    viewport()->setAcceptDrops(true);
}

void DragDropListView::dragEnterEvent(QDragEnterEvent* event)
{
    // Accept the event if it contains URLs (files)
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void DragDropListView::dragMoveEvent(QDragMoveEvent* event)
{
    // Accept the drag move to show "copy" cursor
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void DragDropListView::dropEvent(QDropEvent* event)
{
    const QMimeData* mime = event->mimeData();
    if (mime->hasUrls()) {
        // Accept the drop
        event->acceptProposedAction();
        // Emit signal with the dropped URLs
        emit filesDropped(mime->urls());
    } else {
        event->ignore();
    }
}
