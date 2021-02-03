#pragma once

#include <QtWidgets>

class ClickableTable : public QTableWidget
{
  Q_OBJECT

public:
  ClickableTable(QWidget* _parent) : QTableWidget(_parent) {}

public slots:
  void mouseReleaseEvent(QMouseEvent* event);
};