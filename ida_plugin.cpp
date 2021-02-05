#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <name.hpp>

#include <map>

static bool plugin_inited;
static bool recursive;

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
  OLC_OldAddr,
  OLC_Last
};

struct ListColumn_t {
  enum OverridesListColumns column;
  const char* name;
  const char* tooltip;
};

static const ListColumn_t list_columns[] = {
  { OLC_Enabled, "Enabled", "Is override enabled" },
  { OLC_EA, "Address", "Where to override" },
  { OLC_OpIndex, "Operand", "Override operand #" },
  { OLC_NewAddr, "New Address", "Overridden address" },
  { OLC_OldAddr, "Old Address", "What is overridden" },
};

struct override_t {
  bool enabled = false;
  ea_t addr = BADADDR;
  int op_idx = -1;
  ea_t new_addr = BADADDR;
  ea_t old_addr = BADADDR;
};

std::map<std::pair<ea_t, int>, std::pair<override_t*, int>> overrides;

static void save_overrides() {
  n.create(refs_override_node);

  n.altset(RSAT_Count, (nodeidx_t)overrides.size());

  nodeidx_t idx = 0;
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    const auto ea = i->first.first;
    const auto ea_idx = i->first.second;
    
    const auto* over = i->second.first;

    n.altset(idx + RSAT_Enabled, over->enabled);
    n.altset(idx + RSAT_EA, ea);
    n.altset(idx + RSAT_OpIndex, ea_idx);
    n.altset(idx + RSAT_NewAddr, over->new_addr);
    n.altset(idx + RSAT_OldAddr, over->old_addr);
    idx += RSAT_Last - 1;
  }
}

static void load_overrides() {
  overrides.clear();

  n.create(refs_override_node);

  int overridesCount = (int)n.altval(RSAT_Count);

  nodeidx_t idx = 0;
  for (auto i = 0; i < overridesCount; ++i) {
    override_t* over = new override_t();

    over->enabled = n.altval(idx + RSAT_Enabled);
    over->addr = n.altval(idx + RSAT_EA);
    over->op_idx = n.altval(idx + RSAT_OpIndex);
    over->new_addr = n.altval(idx + RSAT_NewAddr);
    over->old_addr = n.altval(idx + RSAT_OldAddr);
    idx += RSAT_Last - 1;

    overrides[std::pair<ea_t, int>(over->addr, over->op_idx)] = std::pair<override_t*, int>(over, overrides.size());
  }
}

static const override_t* find_override(ea_t ea, int op_idx) {
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    const auto over_ea = i->first.first;
    const auto ea_idx = i->first.second;
    const auto* over = i->second.first;

    if (over_ea == ea && ea_idx == op_idx && over->enabled) {
      return over;
    }
  }

  return new override_t();
}

static void update_overrides_list(ea_t ea=BADADDR) {
  save_overrides();

  if (ea != BADADDR) {
    plan_ea(ea);
    auto_wait();
  }

  load_overrides();
  refresh_chooser(refs_override_widget_name);
}

static size_t add_override(ea_t ea, int op_idx, ea_t new_ea, ea_t old_ea) {
  override_t* over = new override_t({ true, ea, op_idx, new_ea, old_ea });

  size_t n = overrides.size();
  overrides[std::pair<ea_t, int>(ea, op_idx)] = std::pair<override_t*, int>(over, n);

  update_overrides_list(ea);

  return n;
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

static ea_t get_insn_old_addr(ea_t ea, int op_idx) {
  insn_t old_insn;
  decode_insn(&old_insn, ea);

  return get_operand_ref(old_insn.ops[op_idx]);
}

struct overrides_list_t : public chooser_t {
protected:
  static const int list_widths[];
  static const char* const list_headers[];

private:
  void del_override(ea_t ea, int op_idx) {
    for (auto i = overrides.begin(); i != overrides.end();) {
      const auto over_ea = i->first.first;
      const auto ea_idx = i->first.second;

      if (over_ea == ea && ea_idx == op_idx) {
        i = overrides.erase(i);
        break;
      }
      else {
        ++i;
      }
    }

    update_overrides_list(ea);
  }


  void switch_override(ea_t ea, int op_idx) {
    for (auto i = overrides.begin(); i != overrides.end(); ++i) {
      const auto over_ea = i->first.first;
      const auto ea_idx = i->first.second;
      auto* over = i->second.first;

      if (over_ea == ea && ea_idx == op_idx) {
        over->enabled = !over->enabled;
        break;
      }
    }

    update_overrides_list(ea);
  }

  const override_t* get_override_by_index(size_t n) const {
    for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
      const auto over = i->second.first;
      const auto list_idx = i->second.second;

      if (list_idx == n) {
        return over;
      }
    }

    return new override_t();
  }

  void update_override_value(size_t n, bool enabled, ea_t addr, int op_idx, ea_t new_addr) {
    for (auto i = overrides.begin(); i != overrides.end(); ++i) {
      auto* over = i->second.first;
      const auto list_idx = i->second.second;

      if (list_idx == n) {
        over->enabled = enabled;
        over->addr = addr;
        over->op_idx = op_idx;
        over->new_addr = new_addr;
        break;
      }
    }

    update_overrides_list(addr);
  }

  const char* const EDIT_FORM_EDIT = "Edit Override\n"
    "\n"
    "<~E~nabled:C>>\n"
    "<#Address of instruction#    ~A~ddress:$::40::>\n"
    "<#Operand index#    ~O~perand:D::10::>\n"
    "<#New referenced address#  Ove~r~rider:$::40::>\n"
    ;

  const char* const EDIT_FORM_ADD = "Add Override\n"
    "\n"
    "<#Address of instruction#    ~A~ddress:$::40::>\n"
    "<#Operand index#    ~O~perand:D::10::>\n"
    "<#New referenced address#  Ove~r~rider:$::40::>\n"
    ;


  cbret_t ask_for_override(size_t n=-1, bool enabled=true, ea_t addr=BADADDR, int op_idx=0, ea_t new_addr=BADADDR) {
    ushort _enabled = enabled;
    ea_t _addr = addr;
    sval_t _op_idx = op_idx;
    ea_t _new_addr = new_addr;

    int res;
    
    if (n != (size_t)-1) {
      res = ask_form(EDIT_FORM_EDIT, &_enabled, &_addr, &_op_idx, &_new_addr);
    } else {
      res = ask_form(EDIT_FORM_ADD, &_addr, &_op_idx, &_new_addr);
    }

    switch (res) {
    case 1: {
      if (n != (size_t)-1) {
        update_override_value(n, _enabled, _addr, (int)_op_idx, _new_addr);
      } else {
        ea_t old_addr = get_insn_old_addr(_addr, _op_idx);
        n = add_override(_addr, _op_idx, _new_addr, old_addr);
      }

      return cbret_t(n, SELECTION_CHANGED);
    } break;
    default:
      return cbret_t();
    }
  }

public:
  overrides_list_t(const char* title) : chooser_t(CH_KEEP | CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT | CH_CAN_REFRESH | CH_RESTORE, qnumber(list_columns), list_widths, list_headers, title) {};

  cbret_t idaapi del(size_t n) newapi override {
    const auto* over = get_override_by_index(n);
    del_override(over->addr, over->op_idx);

    return cbret_t(n, SELECTION_CHANGED);
  }


  inline cbret_t idaapi enter(size_t n) newapi override {
    const auto* over = get_override_by_index(n);
    
    jumpto(over->addr, over->op_idx);
    return cbret_t(n, SELECTION_CHANGED);
  }


  void idaapi closed() override {
    save_overrides();
  }


  size_t idaapi get_count() const override {
    return overrides.size();
  }


  ea_t idaapi get_ea(size_t n) const override {
    const auto* over = get_override_by_index(n);
    return over->addr;
  }


  void idaapi get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override {
    const auto* over = get_override_by_index(n);

    qstrvec_t& cols = *cols_;

    cols[OLC_Enabled].sprnt("%s", over->enabled ? "X" : "");
    cols[OLC_EA].sprnt("0x%a", over->addr);
    cols[OLC_OpIndex].sprnt("%d", over->op_idx);

    qstring name;
    name = get_name(over->new_addr, GN_SHORT);
    cols[OLC_NewAddr].sprnt("0x%a (%s)", over->new_addr, name.c_str());

    name = get_name(over->old_addr, GN_SHORT);
    cols[OLC_OldAddr].sprnt("0x%a (%s)", over->old_addr, name.c_str());
  }


  bool idaapi init() override {
    load_overrides();
    return overrides.size() > 0;
  }


  cbret_t idaapi edit(size_t n) newapi override {
    const auto* over = get_override_by_index(n);
    return ask_for_override(n, over->enabled, over->addr, over->op_idx, over->new_addr);
  }


  cbret_t idaapi refresh(ssize_t n) newapi override {
    load_overrides();
    return cbret_t(n == -1 ? NO_SELECTION : n, ALL_CHANGED);
  }


  cbret_t idaapi ins(ssize_t n) newapi override {
    const auto* over = get_override_by_index(n);
    return ask_for_override(-1, over->enabled, over->addr, over->op_idx, over->new_addr);
  }

};

const int overrides_list_t::list_widths[] = {
  CHCOL_PLAIN | sizeof(list_columns[OLC_Enabled].name),
  CHCOL_EA | 8,
  CHCOL_DEC | sizeof(list_columns[OLC_OpIndex].name),
  CHCOL_EA | 50,
  CHCOL_EA | 50,
};

const char* const overrides_list_t::list_headers[] = {
  list_columns[OLC_Enabled].name,
  list_columns[OLC_EA].name,
  list_columns[OLC_OpIndex].name,
  list_columns[OLC_NewAddr].name,
  list_columns[OLC_OldAddr].name,
};

struct plugin_ctx_t;
struct refs_override_action_t : public action_handler_t {

  plugin_ctx_t& ctx;
  refs_override_action_t(plugin_ctx_t& ctx_) : ctx(ctx_) {};

  int idaapi activate(action_activation_ctx_t* ctx) override {
    ea_t ea = get_screen_ea();

    if (is_mapped(ea)) { // address belongs to disassembly
      int op_idx = get_opnum();
      op_idx = (op_idx == -1) ? 0 : op_idx;

      ea_t old_addr = get_insn_old_addr(ea, op_idx);
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
    return AST_ENABLE_ALWAYS;
  }

};

struct refs_override_menu_action_t : public action_handler_t {

  plugin_ctx_t& ctx;
  overrides_list_t* overrides_list;
  refs_override_menu_action_t(plugin_ctx_t& ctx_, overrides_list_t* overrides_list_) : ctx(ctx_), overrides_list(overrides_list_) {};

  int idaapi activate(action_activation_ctx_t* ctx) override {
    overrides_list->choose();

    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_ALWAYS;
  }

};

struct post_visitor_t : public post_event_visitor_t {

  plugin_ctx_t &ctx;
  post_visitor_t(plugin_ctx_t &ctx_) : ctx(ctx_) {};

  ssize_t idaapi handle_post_event(ssize_t code, int notification_code, va_list va) override;
};

ssize_t idaapi post_visitor_t::handle_post_event(ssize_t code, int notification_code, va_list va) {
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
      const auto* over = find_override(insn->ea, i);

      if (!over->enabled) {
        continue;
      }

      set_operand_ref(insn->ops[i], over->new_addr);
    }

    return insn->size;
  } break;
  }

  return code;
}

struct plugin_ctx_t : public plugmod_t {

protected:
  post_visitor_t post_visitor = post_visitor_t(*this);
  refs_override_action_t refs_overrider = refs_override_action_t(*this);
  overrides_list_t overrides_list = overrides_list_t(refs_override_widget_name);
  refs_override_menu_action_t refs_overrider_menu = refs_override_menu_action_t(*this, &overrides_list);

public:
  plugin_ctx_t() {
    recursive = false;

    overrides.clear();

    register_action(ACTION_DESC_LITERAL(
      refs_override_menu_name,
      refs_override_widget_name,
      &refs_overrider_menu,
      refs_override_widget_hotkey,
      NULL, -1
    ));
    attach_action_to_menu(refs_override_menu_action_path, refs_override_menu_name, SETMENU_APP);

    register_action(ACTION_DESC_LITERAL(
      refs_override_name,
      refs_override_action_name,
      &refs_overrider,
      refs_override_action_hotkey,
      NULL, -1
    ));

    register_post_event_visitor(HT_IDP, &post_visitor, this);

    plugin_inited = true;
  }

  virtual bool idaapi run(size_t arg) override { return false; };

  virtual ~plugin_ctx_t() {
    if (plugin_inited) {
      overrides.clear();

      detach_action_from_menu(refs_override_menu_action_path, refs_override_menu_name);
      unregister_action(refs_override_menu_name);

      unregister_action(refs_override_name);

      unregister_post_event_visitor(HT_IDP, &post_visitor);

      recursive = false;
    }

    plugin_inited = false;
  }

} plugin;

static plugmod_t * idaapi init(void) {
  return &plugin;
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
    PLUGIN_HIDE | PLUGIN_MULTI, // plugin flags
    init, // initialize

    nullptr, // terminate. this pointer may be NULL.

    nullptr, // invoke plugin

    comment, // long comment about the plugin
             // it could appear in the status line
             // or as a hint

    help, // multiline help about the plugin

    "References Overrider", // the preferred short name of the plugin

    "" // the preferred hotkey to run the plugin
};