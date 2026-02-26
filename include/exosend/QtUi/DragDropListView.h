#ifndef EXOSEND_QTUI_DRAGDROPLISTVIEW_H
#define EXOSEND_QTUI_DRAGDROPLISTVIEW_H

#include <QListView>
#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDragLeaveEvent>
#include <QDropEvent>
#include <QPaintEvent>

/**
 * @class DragDropListView
 * @brief QListView subclass with drag-drop support, empty-state text, and
 *        a visual drop-zone highlight when files are dragged over the widget.
 */
class DragDropListView : public QListView
{
    Q_OBJECT

public:
    explicit DragDropListView(QWidget* parent = nullptr);

signals:
    void filesDropped(const QList<QUrl>& urls);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragMoveEvent(QDragMoveEvent* event) override;
    void dragLeaveEvent(QDragLeaveEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    bool m_dragActive = false; ///< True while files are being dragged over this widget
};

#endif // EXOSEND_QTUI_DRAGDROPLISTVIEW_H
