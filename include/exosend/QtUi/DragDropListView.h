#ifndef EXOSEND_QTUI_DRAGDROPLISTVIEW_H
#define EXOSEND_QTUI_DRAGDROPLISTVIEW_H

#include <QListView>
#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDropEvent>

/**
 * @class DragDropListView
 * @brief QListView subclass with drag-drop support
 *
 * This class overrides QListView's drag-drop event handlers to:
 * 1. Accept file drag operations
 * 2. Provide proper cursor feedback (not "no drop")
 * 3. Signal when files are dropped
 *
 * Qt event filters CANNOT properly handle drag-drop because they
 * prevent the widget from updating its internal drag state, which
 * is required for cursor updates.
 */
class DragDropListView : public QListView
{
    Q_OBJECT

public:
    explicit DragDropListView(QWidget* parent = nullptr);

signals:
    /**
     * @brief Emitted when files are dropped on the list
     * @param urls List of dropped file URLs
     */
    void filesDropped(const QList<QUrl>& urls);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragMoveEvent(QDragMoveEvent* event) override;
    void dropEvent(QDropEvent* event) override;
};

#endif // EXOSEND_QTUI_DRAGDROPLISTVIEW_H
