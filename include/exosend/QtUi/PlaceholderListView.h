#ifndef EXOSEND_QTUI_PLACEHOLDERLISTVIEW_H
#define EXOSEND_QTUI_PLACEHOLDERLISTVIEW_H

#include <QListView>
#include <QPaintEvent>
#include <QPainter>

/**
 * @class PlaceholderListView
 * @brief QListView subclass that draws centered gray placeholder text when
 *        the model is empty. Used for lists that do not need drag-drop support.
 */
class PlaceholderListView : public QListView
{
    Q_OBJECT

public:
    explicit PlaceholderListView(const QString& placeholderText,
                                 QWidget* parent = nullptr);

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    QString m_placeholder;
};

#endif // EXOSEND_QTUI_PLACEHOLDERLISTVIEW_H
