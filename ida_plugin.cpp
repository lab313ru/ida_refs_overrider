#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <name.hpp>

#include <map>

#include "OverridesWindow.h"
#include "ClickableTable.h"

#include <QAction>

static bool plugin_inited;
static bool recursive;

static TWidget* refs_w = nullptr;
static ClickableTable* oversList = nullptr;
static QAction* toggleOverrideAction = nullptr;
static QAction* delOverrideAction = nullptr;

static netnode n;

static const char refs_override_name[] = "OverridesList:change_dest";
static const char refs_override_menu_name[] = "OverridesList:show_window";
static const char refs_override_menu_action_path[] = "View/Open subviews/Function calls";
static const char refs_override_node[] = "$ overrides_list";
static const char refs_override_widget_name[] = "Overrides list";
static const char refs_override_action_name[] = "Change Destination Address";

static const char refs_override_widget_hotkey[] = "Shift+Alt+R";
static const char refs_override_action_hotkey[] = "Shift+R";

enum RefsStorageAltType {
  RSAT_Count = 0,
  RSAT_Enabled,
  RSAT_EA,
  RSAT_OpIndex,
  RSAT_NewAddr,
  RSAT_OldAddr,
  RSAT_Last
};

enum OverridesListColumns {
  OLC_Enabled = 0,
  OLC_EA,
  OLC_OpIndex,
  OLC_NewAddr,
  OLC_DestLabel,
  OLC_OldAddr,
  OLC_OldLabel,
  OLC_Last
};

struct ListColumn_t {
  enum OverridesListColumns column;
  const char* name;
  const char* tooltip;
};

static const ListColumn_t columns[] = {
  { OLC_Enabled, "Enabled", "Is override enabled" },
  { OLC_EA, "Address", "Where to override" },
  { OLC_OpIndex, "Operand", "Override operand #" },
  { OLC_NewAddr, "New Address", "Overridden address" },
  { OLC_DestLabel, "New Address Name", "Label at the New Address" },
  { OLC_OldAddr, "Old Address", "What is overridden" },
  { OLC_OldLabel, "Old Address Name", "Label at the Old Address" },
};

struct override_t {
  bool enabled = false;
  ea_t addr = BADADDR;
  int op_idx = -1;
  ea_t new_addr = BADADDR;
  ea_t old_addr = BADADDR;
};

static std::map<std::pair<ea_t, int>, override_t> overrides;

static void add_override_item_to_list(const override_t over) {
  if (refs_w != nullptr && oversList != nullptr) {
    int index = oversList->rowCount();

    oversList->insertRow(index);

    QTableWidgetItem* item = new QTableWidgetItem(over.enabled ? "X" : "");
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_Enabled, item);

    QString addrStr = QString::number(over.addr, 16);
    item = new QTableWidgetItem(addrStr.toUpper());
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_EA, item);

    item = new QTableWidgetItem(QString::number(over.op_idx));
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_OpIndex, item);

    addrStr = QString::number(over.new_addr, 16);
    item = new QTableWidgetItem(addrStr.toUpper());
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_NewAddr, item);

    qstring name;
    get_ea_name(&name, (ea_t)over.new_addr, GN_SHORT);
    item = new QTableWidgetItem(name.c_str());
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_DestLabel, item);

    addrStr = QString::number(over.old_addr, 16);
    item = new QTableWidgetItem(addrStr.toUpper());
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_OldAddr, item);

    get_ea_name(&name, (ea_t)over.old_addr, GN_SHORT);
    item = new QTableWidgetItem(name.c_str());
    item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    oversList->setItem(index, OverridesListColumns::OLC_OldLabel, item);

    oversList->resizeColumnsToContents();
  }
}

static override_t find_override(ea_t ea, int op_idx) {
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    if (i->first.first == ea && i->first.second == op_idx && i->second.enabled) {
      return i->second;
    }
  }

  return override_t();
}

static void save_overrides() {
  n.create(refs_override_node);

  n.altset(RSAT_Count, (nodeidx_t)overrides.size());

  nodeidx_t idx = 0;
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    n.altset(idx + RSAT_Enabled, i->second.enabled);
    n.altset(idx + RSAT_EA, i->first.first);
    n.altset(idx + RSAT_OpIndex, i->first.second);
    n.altset(idx + RSAT_NewAddr, i->second.new_addr);
    n.altset(idx + RSAT_OldAddr, i->second.old_addr);
    idx += RSAT_Last - 1;
  }
}

static void load_overrides() {
  overrides.clear();

  n.create(refs_override_node);

  int refsOverridesCount = (int)n.altval(RSAT_Count);

  nodeidx_t idx = 0;
  for (auto i = 0; i < refsOverridesCount; ++i) {
    override_t over;

    over.enabled = n.altval(idx + RSAT_Enabled);
    over.addr = n.altval(idx + RSAT_EA);
    over.op_idx = n.altval(idx + RSAT_OpIndex);
    over.new_addr = n.altval(idx + RSAT_NewAddr);
    over.old_addr = n.altval(idx + RSAT_OldAddr);
    idx += RSAT_Last - 1;

    overrides[std::pair<ea_t, int>(over.addr, over.op_idx)] = over;
  }
}

static void update_overs_gui_list() {
  int row = -1, col = -1;

  if (refs_w != nullptr && oversList != nullptr) {
    row = oversList->currentRow();
    col = oversList->currentColumn();
    oversList->setRowCount(0);
  }

  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    add_override_item_to_list(i->second);
  }

  if (oversList != nullptr) {
    oversList->setCurrentCell(row, col);
  }
}

static void switch_override(ea_t ea, int op_idx) {
  for (auto i = overrides.begin(); i != overrides.end(); ++i) {
    if (i->first.first == ea && i->first.second == op_idx) {
      i->second.enabled = !i->second.enabled;
    }
  }

  save_overrides();
  load_overrides();
}

static void add_override(ea_t ea, int op_idx, ea_t new_ea, ea_t old_ea) {
  override_t over = {
    true,
    ea,
    op_idx,
    new_ea,
    old_ea
  };

  overrides[std::pair<ea_t, int>(ea, op_idx)] = over;
  add_override_item_to_list(over);

  save_overrides();
}

static void del_override(ea_t ea, int op_idx) {
  for (auto i = overrides.begin(); i != overrides.end();) {
    if (i->first.first == ea && i->first.second == op_idx) {
      i = overrides.erase(i);
    } else {
      ++i;
    }
  }

  save_overrides();
  load_overrides();
}

static void set_operand_ref(op_t& op, ea_t new_addr) {
  if (op.type == o_near || op.type == o_far) {
    op.addr = new_addr;
  }
  else {
    op.value = new_addr;
  }
}

static ea_t get_operand_ref(op_t& op) {
  if (op.type == o_near || op.type == o_far) {
    return op.addr;
  }
  
  return op.value;
}

struct refs_creation_visitor_t : public post_event_visitor_t {
  ssize_t idaapi handle_post_event(ssize_t code, int notification_code, va_list va) override {
    switch (notification_code) {
    case processor_t::ev_ana_insn: {
      insn_t* insn = va_arg(va, insn_t*);

      if (recursive) {
        return 0;
      }

      recursive = true;
      decode_insn(insn, insn->ea);
      recursive = false;

      load_overrides();

      for (auto i = 0; i < UA_MAXOP; ++i) {
        override_t over = find_override(insn->ea, i);

        if (!over.enabled) {
          continue;
        }

        set_operand_ref(insn->ops[i], over.new_addr);
      }

      return insn->size;
    } break;
    }

    return code;
  }
} ctx;

void OverridesListWindow::switchOverride() {
  int cur_row = oversList->currentRow();

  if (cur_row == -1) {
    return;
  }

  ea_t cur_ea = oversList->item(cur_row, OverridesListColumns::OLC_EA)->text().toULong(nullptr, 16);
  int cur_op_idx = oversList->item(cur_row, OverridesListColumns::OLC_OpIndex)->text().toULong(nullptr);

  switch_override(cur_ea, cur_op_idx);
}

void OverridesListWindow::removeOverride() {
  int cur_row = oversList->currentRow();

  if (cur_row == -1) {
    return;
  }

  ea_t cur_ea = oversList->item(cur_row, OverridesListColumns::OLC_EA)->text().toULong(nullptr, 16);
  int cur_op_idx = oversList->item(cur_row, OverridesListColumns::OLC_OpIndex)->text().toULong(nullptr);

  del_override(cur_ea, cur_op_idx);
}

void ClickableTable::mouseReleaseEvent(QMouseEvent* event) {
  Q_UNUSED(event);

  int row = oversList->currentRow();
  int rows_count = oversList->rowCount();

  toggleOverrideAction->setEnabled(rows_count && row != -1);
  delOverrideAction->setEnabled(rows_count && row != -1);
}

void OverridesListWindow::cellDoubleClicked(int row, int col) {
  if (row == -1) {
    return;
  }

  int op_idx = -1;
  ea_t cur_ea = BADADDR;

  switch (col) {
  case OverridesListColumns::OLC_EA:
  case OverridesListColumns::OLC_NewAddr:
  case OverridesListColumns::OLC_OldAddr: {
    cur_ea = oversList->item(row, col)->text().toULong(nullptr, 16);

    switch (col) {
    case OverridesListColumns::OLC_EA: {
      op_idx = oversList->item(row, OverridesListColumns::OLC_OpIndex)->text().toULong(nullptr, 16);
    } break;
    }
  } break;
  case OverridesListColumns::OLC_DestLabel: {
    cur_ea = oversList->item(row, OverridesListColumns::OLC_NewAddr)->text().toULong(nullptr, 16);
  } break;
  case OverridesListColumns::OLC_OldLabel: {
    cur_ea = oversList->item(row, OverridesListColumns::OLC_OldAddr)->text().toULong(nullptr, 16);
  } break;
  case OverridesListColumns::OLC_Enabled: {
    cur_ea = oversList->item(row, OverridesListColumns::OLC_EA)->text().toULong(nullptr, 16);
    op_idx = oversList->item(row, OverridesListColumns::OLC_OpIndex)->text().toULong(nullptr, 16);

    switch_override(cur_ea, op_idx);
    return;
  } break;
  default:
    return;
  }

  jumpto(cur_ea, op_idx);
}


static ssize_t idaapi hook_ui(void* user_data, int notification_code, va_list va) {
  switch (notification_code) {
  case ui_widget_visible: {
    TWidget* widget = va_arg(va, TWidget*);

    if (widget == refs_w) {
      QWidget* w = (QWidget*)widget;

      QFont font = QFont("Lucida Console", 10);

      QGridLayout* mainLayout = new QGridLayout(w);

      oversList = new ClickableTable(w);
      oversList->setEditTriggers(QAbstractItemView::NoEditTriggers);
      oversList->setFocusPolicy(Qt::NoFocus);
      oversList->setShowGrid(true);
      oversList->setColumnCount(OverridesListColumns::OLC_Last);
      oversList->setFont(font);
      oversList->setSelectionBehavior(QAbstractItemView::SelectionBehavior::SelectItems);
      oversList->setSelectionMode(QAbstractItemView::SingleSelection);
      oversList->setHorizontalHeaderLabels({
        columns[OLC_Enabled].name,
        columns[OLC_EA].name,
        columns[OLC_OpIndex].name,
        columns[OLC_NewAddr].name,
        columns[OLC_DestLabel].name,
        columns[OLC_OldAddr].name,
        columns[OLC_OldLabel].name,
        });
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_Enabled)->setToolTip(columns[OLC_Enabled].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_EA)->setToolTip(columns[OLC_EA].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_OpIndex)->setToolTip(columns[OLC_OpIndex].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_NewAddr)->setToolTip(columns[OLC_NewAddr].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_DestLabel)->setToolTip(columns[OLC_DestLabel].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_OldAddr)->setToolTip(columns[OLC_OldAddr].tooltip);
      oversList->horizontalHeaderItem(OverridesListColumns::OLC_OldLabel)->setToolTip(columns[OLC_OldLabel].tooltip);

      OverridesListWindow* overridesWnd = new OverridesListWindow(w);
      toggleOverrideAction = new QAction("Toggle override", oversList);
      toggleOverrideAction->setShortcut(QKeySequence(Qt::Key_X));
      toggleOverrideAction->setEnabled(false);

      delOverrideAction = new QAction("Delete override", oversList);
      delOverrideAction->setShortcut(QKeySequence::Delete);
      delOverrideAction->setEnabled(false);

      oversList->setContextMenuPolicy(Qt::ActionsContextMenu);

      mainLayout->addWidget(oversList);

      w->setLayout(mainLayout);

      QObject::connect(toggleOverrideAction, SIGNAL(triggered()), overridesWnd, SLOT(switchOverride()));
      oversList->addAction(toggleOverrideAction);

      QObject::connect(delOverrideAction, SIGNAL(triggered()), overridesWnd, SLOT(removeOverride()));
      oversList->addAction(delOverrideAction);

      QObject::connect(oversList, SIGNAL(cellDoubleClicked(int,int)), overridesWnd, SLOT(cellDoubleClicked(int,int)));
    }
  } break;
  case ui_widget_invisible: {
    TWidget* widget = va_arg(va, TWidget*);

    if (widget == refs_w) {
      refs_w = nullptr;
      oversList = nullptr;
      toggleOverrideAction = nullptr;
      delOverrideAction = nullptr;
    }
  } break;
  }

  return 0;
}

static struct refs_override_action_t : public action_handler_t {
  int idaapi activate(action_activation_ctx_t* ctx) override {
    ea_t ea = get_screen_ea();

    if (is_mapped(ea)) { // address belongs to disassembly
      int op_idx = get_opnum();
      op_idx = (op_idx == -1) ? 0 : op_idx;

      insn_t old_insn;
      
      decode_insn(&old_insn, ea);

      ea_t old_addr = get_operand_ref(old_insn.ops[op_idx]);
      ea_t new_addr = old_addr;

      if (ask_addr(&new_addr, "Destination address")) {
        if (is_mapped(new_addr)) {
          add_override(ea, op_idx, new_addr, old_addr);
          plan_ea(ea);
        }
      }
    }

    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_FOR_IDB;
  }

} refs_overrider;

static struct refs_override_menu_action_t : public action_handler_t {
  int idaapi activate(action_activation_ctx_t* ctx) override {
    TWidget* w = find_widget(refs_override_widget_name);
    if (w == nullptr) {
      refs_w = create_empty_widget(refs_override_widget_name);
      display_widget(refs_w, WOPN_DP_TAB | WOPN_RESTORE);
    } else {
      activate_widget(refs_w, true);
    }

    load_overrides();
    update_overs_gui_list();

    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_ALWAYS;
  }

} refs_overrider_menu;


static const action_desc_t refs_override_menu_action = ACTION_DESC_LITERAL(
  refs_override_menu_name,
  refs_override_widget_name,
  &refs_overrider_menu,
  refs_override_widget_hotkey,
  NULL, -1
);
static const action_desc_t refs_override_action = ACTION_DESC_LITERAL(
  refs_override_name,
  refs_override_action_name,
  &refs_overrider,
  refs_override_action_hotkey,
  NULL, -1
);

static plugmod_t * idaapi init(void) {
  recursive = false;

  refs_w = nullptr;
  oversList = nullptr;
  toggleOverrideAction = nullptr;
  delOverrideAction = nullptr;

  overrides.clear();

  register_action(refs_override_menu_action);
  attach_action_to_menu(refs_override_menu_action_path, refs_override_menu_name, SETMENU_APP);

  register_action(refs_override_action);

  hook_to_notification_point(HT_UI, hook_ui, NULL);
  register_post_event_visitor(HT_IDP, &ctx, NULL);

  plugin_inited = true;

  return PLUGIN_KEEP;
}

static void idaapi term(void) {
  if (plugin_inited) {
    TWidget* w = find_widget(refs_override_widget_name);

    if (w != nullptr) {
      close_widget(w, WCLS_SAVE);
    }

    refs_w = nullptr; // make lint happy

    unhook_from_notification_point(HT_UI, hook_ui);
    unregister_post_event_visitor(HT_IDP, &ctx);

    unregister_action(refs_override_name);
    unregister_action(refs_override_menu_name);

    recursive = false;
  }

  plugin_inited = false;
}

static bool idaapi run(size_t arg) {
  return false;
}


char comment[] = "Refs Overrider plugin by Vladimir Kononovich";

char help[] = "Refs Overrider by Vladimir Kononovich.\n"
"\n"
"This module allows to override refs in IDA\n";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_MOD, // plugin flags
    init, // initialize

    term, // terminate. this pointer may be NULL.

    run, // invoke plugin

    comment, // long comment about the plugin
             // it could appear in the status line
             // or as a hint

    help, // multiline help about the plugin

    "References Overrider", // the preferred short name of the plugin

    "" // the preferred hotkey to run the plugin
};