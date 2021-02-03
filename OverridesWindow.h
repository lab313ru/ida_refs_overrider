#pragma once

#include <QtWidgets>

class OverridesListWindow : public QWidget
{
  Q_OBJECT

public:
  OverridesListWindow(QWidget* _parent) : QWidget(_parent) {}

public slots:
  void switchOverride();
  void removeOverride();

public slots:
  void cellDoubleClicked(int row, int col);
};