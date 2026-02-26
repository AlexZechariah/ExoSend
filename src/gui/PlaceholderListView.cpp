#include "exosend/QtUi/PlaceholderListView.h"

PlaceholderListView::PlaceholderListView(const QString& placeholderText,
                                         QWidget* parent)
    : QListView(parent), m_placeholder(placeholderText)
{
}

void PlaceholderListView::paintEvent(QPaintEvent* event)
{
    QListView::paintEvent(event);

    if (model() && model()->rowCount() == 0) {
        QPainter painter(viewport());
        painter.setPen(QColor(160, 160, 160));
        QFont f = painter.font();
        f.setPointSize(9);
        painter.setFont(f);
        painter.drawText(viewport()->rect(), Qt::AlignCenter, m_placeholder);
    }
}
