#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <auto.hpp>
#include <name.hpp>

#include <map>

static bool plugin_inited;
static bool recursive;
static bool ida_move_del_ren;
static ea_t last_over_addr;

static const char overrides_show_wnd_name[] = "OverridesList:show_window";
static const char overrides_menu_action_path[] = "View/Open subviews/Function calls";
static const char overrides_node[] = "$ overrides_list";
static const char overrides_wnd_title[] = "Overrides List";

static const char overrides_show_wnd_hotkey[] = "Shift+Alt+R";
static const char overrides_change_dest_hotkey[] = "Shift+R";

static const char overlays_add_name[] = "OverlaysList:add_overlay";
static const char overlays_show_wnd_name[] = "OverlaysList:show_window";
static const char overlays_menu_action_path[] = "View/Open subviews/Function Calls";
static const char overlays_node[] = "$ overlays_list";
static const char overlays_wnd_title[] = "Overlays List";

static const char overlays_show_wnd_hotkey[] = "Shift+O";

enum class OverridesStorageAltType : int {
  OSAT_Count = 0,
  OSAT_Enabled,
  OSAT_EA,
  OSAT_OpIndex,
  OSAT_NewAddr,
  OSAT_OldAddr,
  OSAT_Last
};

enum class OverridesListColumns : int {
  OLC_Enabled = 0,
  OLC_EA,
  OLC_OpIndex,
  OLC_NewAddr,
  OLC_OldAddr,
  OLC_Last
};

struct OverridesListColumn_t {
  enum class OverridesListColumns column;
  const char* name;
};

static const OverridesListColumn_t overrides_list_columns[] = {
  { OverridesListColumns::OLC_Enabled, "Enabled" },
  { OverridesListColumns::OLC_EA, "Address" },
  { OverridesListColumns::OLC_OpIndex, "Operand" },
  { OverridesListColumns::OLC_NewAddr, "New Address" },
  { OverridesListColumns::OLC_OldAddr, "Old Address" },
};

struct override_t {
  bool enabled = false;
  ea_t addr = BADADDR;
  int op_idx = -1;
  ea_t new_addr = BADADDR;
  ea_t old_addr = BADADDR;
};

enum class OverlaysStorageAltType : int {
  OSAT_Count = 0,
  OSAT_OverlayAddr,
  OSAT_RealAddr,
  OSAT_Path,
  OSAT_Last
};

enum class OverlaysListColumns : int {
  OLC_Name = 0,
  OLC_OverlayAddr,
  OLC_RealAddr,
  OLC_Size,
  OLC_Path,
  OLC_Last
};

struct OverlaysListColumn_t {
  enum class OverlaysListColumns column;
  const char* name;
};

static const OverlaysListColumn_t overlays_list_columns[] = {
  { OverlaysListColumns::OLC_Name, "Name" },
  { OverlaysListColumns::OLC_OverlayAddr, "Overlay Address" },
  { OverlaysListColumns::OLC_RealAddr, "Real Address" },
  { OverlaysListColumns::OLC_Size, "Overlay Size" },
  { OverlaysListColumns::OLC_Path, "File" },
};

struct overlay_t {
  ea_t over_addr = BADADDR;
  qstring* path = nullptr;
};

static void set_operand_ref(op_t& op, ea_t new_addr) {
  if (op.type == o_void) {
    return;
  }

  if (op.type == o_near || op.type == o_far || op.type == o_mem) {
    op.addr = new_addr;
  }
  else {
    op.value = new_addr;
  }
}

static ea_t get_operand_ref(op_t& op) {
  if (op.type == o_near || op.type == o_far || op.type == o_mem) {
    return op.addr;
  }

  return op.value;
}

static ea_t get_insn_old_addr(ea_t ea, int op_idx) {
  insn_t old_insn;
  decode_insn(&old_insn, ea);

  return get_operand_ref(old_insn.ops[op_idx]);
}

struct plugin_ctx_t;
struct overrides_list_t : public chooser_t {
  plugin_ctx_t& ctx;

protected:
  static const int list_widths[];
  static const char* const list_headers[];

private:

  const char* const EDIT_FORM = "Edit Override\n"
    "\n"
    "<~E~nabled:C>>\n"
    "<#Address of instruction#    ~A~ddress:$::40::>\n"
    "<#Operand index#    ~O~perand:D::10::>\n"
    "<#New referenced address#  Ove~r~rider:$::40::>\n"
    ;

  const char* const ADD_FORM = "Add Override\n"
    "\n"
    "<#Address of instruction#    ~A~ddress:$::40::>\n"
    "<#Operand index#    ~O~perand:D::10::>\n"
    "<#New referenced address#  Ove~r~rider:$::40::>\n"
    ;


  cbret_t ask_for_override(size_t n = -1, bool enabled = true, ea_t addr = BADADDR, int op_idx = 0, ea_t new_addr = BADADDR);

public:
  overrides_list_t(const char* title, plugin_ctx_t& ctx_) : ctx(ctx_), chooser_t(CH_KEEP | CH_NOIDB | CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT | CH_CAN_REFRESH | CH_RESTORE, qnumber(overrides_list_columns), list_widths, list_headers, title) {};

  cbret_t idaapi del(size_t n) newapi override;
  inline cbret_t idaapi enter(size_t n) newapi override;
  void idaapi closed() override;
  size_t idaapi get_count() const override;
  ea_t idaapi get_ea(size_t n) const override;
  void idaapi get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override;
  bool idaapi init() override;
  cbret_t idaapi edit(size_t n) newapi override;
  cbret_t idaapi refresh(ssize_t n) newapi override;
  cbret_t idaapi ins(ssize_t n) newapi override;

};

const int overrides_list_t::list_widths[] = {
  CHCOL_PLAIN | sizeof(overrides_list_columns[(int)OverridesListColumns::OLC_Enabled].name),
  CHCOL_EA | 8,
  CHCOL_DEC | sizeof(overrides_list_columns[(int)OverridesListColumns::OLC_OpIndex].name),
  CHCOL_EA | 50,
  CHCOL_EA | 50,
};

const char* const overrides_list_t::list_headers[] = {
  overrides_list_columns[(int)OverridesListColumns::OLC_Enabled].name,
  overrides_list_columns[(int)OverridesListColumns::OLC_EA].name,
  overrides_list_columns[(int)OverridesListColumns::OLC_OpIndex].name,
  overrides_list_columns[(int)OverridesListColumns::OLC_NewAddr].name,
  overrides_list_columns[(int)OverridesListColumns::OLC_OldAddr].name,
};

struct overlays_list_t : public chooser_t {
  plugin_ctx_t& ctx;

protected:
  static const int list_widths[];
  static const char* const list_headers[];

private:

  const char* const EDIT_FORM = "Edit Overlay\n"
    "\n"
    "<~N~ame:q:64:::>\n"
    "<#Real address of the loaded data#~R~eal address:$::40::>\n"
    ;

  const char* const ADD_FORM = "Add Overlay\n"
    "\n"
    "<~N~ame:q:64:::>\n"
    "<#Address of the original memory segment#~O~verlayed address:$::40::>\n"
    "<#Real address of the loaded data#     ~R~eal address:$::40::>\n"
    ;

  cbret_t ask_for_overlay(size_t n = -1, const qstring* name = nullptr, ea_t overlayed_addr = BADADDR, ea_t real_addr = BADADDR);

public:
  overlays_list_t(const char* title, plugin_ctx_t& ctx_) : ctx(ctx_), chooser_t(CH_KEEP | CH_NOIDB | CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT | CH_CAN_REFRESH | CH_RESTORE, qnumber(overlays_list_columns), list_widths, list_headers, title) {};

  cbret_t idaapi del(size_t n) newapi override;
  inline cbret_t idaapi enter(size_t n) newapi override;
  void idaapi closed() override;
  size_t idaapi get_count() const override;
  ea_t idaapi get_ea(size_t n) const override;
  void idaapi get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override;
  bool idaapi init() override;
  cbret_t idaapi edit(size_t n) newapi override;
  cbret_t idaapi refresh(ssize_t n) newapi override;
  cbret_t idaapi ins(ssize_t n) newapi override;

  static bool check_overlay_params(const qstring* name, ea_t overlayed_addr, ea_t real_addr);
};

const int overlays_list_t::list_widths[] = {
  CHCOL_PLAIN | sizeof(overlays_list_columns[(int)OverlaysListColumns::OLC_Name].name),
  CHCOL_EA | 10,
  CHCOL_EA | 10,
  CHCOL_DEC | 10,
  CHCOL_PATH | 100,
};

const char* const overlays_list_t::list_headers[] = {
  overlays_list_columns[(int)OverlaysListColumns::OLC_Name].name,
  overlays_list_columns[(int)OverlaysListColumns::OLC_OverlayAddr].name,
  overlays_list_columns[(int)OverlaysListColumns::OLC_RealAddr].name,
  overlays_list_columns[(int)OverlaysListColumns::OLC_Size].name,
  overlays_list_columns[(int)OverlaysListColumns::OLC_Path].name,
};

struct overlays_menu_action_t : public action_handler_t {
  overlays_list_t* overlays_list;
  overlays_menu_action_t(overlays_list_t* overlays_list_) : overlays_list(overlays_list_) {};

  int idaapi activate(action_activation_ctx_t *ctx) override {
    overlays_list->choose();
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_ALWAYS;
  }
};

struct overrides_menu_action_t : public action_handler_t {

  overrides_list_t* overrides_list;
  overrides_menu_action_t(overrides_list_t* overrides_list_) : overrides_list(overrides_list_) {};

  int idaapi activate(action_activation_ctx_t* ctx) override {
    overrides_list->choose();
    return 1;
  }

  action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_ALWAYS;
  }
};

struct idb_post_event_visitor_t : public post_event_visitor_t {
  plugin_ctx_t& ctx;

public:
  idb_post_event_visitor_t(plugin_ctx_t& ctx_) : ctx(ctx_) {};

  ssize_t idaapi handle_post_event(ssize_t code, int notification_code, va_list va) override;
};

struct plugin_ctx_t : public plugmod_t, post_event_visitor_t {

  overrides_list_t overrides_list = overrides_list_t(overrides_wnd_title, *this);
  overrides_menu_action_t overrides_menu = overrides_menu_action_t(&overrides_list);

  overlays_list_t overlays_list = overlays_list_t(overlays_wnd_title, *this);
  overlays_menu_action_t overlays_menu = overlays_menu_action_t(&overlays_list);

  idb_post_event_visitor_t idb_visitor = idb_post_event_visitor_t(*this);

private:
  std::map<std::pair<ea_t, size_t>, std::pair<override_t*, size_t>> overrides; // instr addr/operand, struct/index
  std::map<ea_t, std::pair<overlay_t*, size_t>> overlays; // real addr, overlayed addr/index
  netnode n_overrides, n_overlays;

public:
  plugin_ctx_t() {
    recursive = false;
    ida_move_del_ren = false;
    last_over_addr = BADADDR;

    free_overrides();
    free_overlays();

    register_action(ACTION_DESC_LITERAL(
      overrides_show_wnd_name,
      overrides_wnd_title,
      &overrides_menu,
      overrides_show_wnd_hotkey,
      NULL, -1
    ));
    attach_action_to_menu(overrides_menu_action_path, overrides_show_wnd_name, SETMENU_APP);

    register_action(ACTION_DESC_LITERAL(
      overlays_show_wnd_name,
      overlays_wnd_title,
      &overlays_menu,
      overlays_show_wnd_hotkey,
      NULL, -1
    ));
    attach_action_to_menu(overlays_menu_action_path, overlays_show_wnd_name, SETMENU_APP);

    register_post_event_visitor(HT_IDP, this, this);
    register_post_event_visitor(HT_IDB, &idb_visitor, this);

    plugin_inited = true;
  }

  virtual bool idaapi run(size_t arg) override {
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
        } else {
          warning("Incorrect address (is not mapped)!");
        }
      }

      return true;
    }

    return false;
  };

  virtual ~plugin_ctx_t() {
    if (plugin_inited) {
      free_overrides();
      free_overlays();

      recursive = false;
      ida_move_del_ren = false;
      last_over_addr = BADADDR;
    }

    plugin_inited = false;
  }

  size_t overrides_count() {
    return overrides.size();
  }

  void free_overrides();
  void save_overrides();
  void load_overrides();
  void del_override(ea_t ea, int op_idx);
  void switch_override(ea_t ea, int op_idx);
  const override_t* get_override_by_index(size_t n) const;
  void update_override_value(size_t n, bool enabled, ea_t addr, int op_idx, ea_t new_addr);
  const override_t* find_override(ea_t ea, int op_idx);
  void update_overrides_list(ea_t ea = BADADDR);
  size_t add_override(ea_t ea, int op_idx, ea_t new_ea, ea_t old_ea);

  // overlays
  size_t overlays_count() {
    return overlays.size();
  }

  void free_overlays();
  void save_overlays();
  void load_overlays();
  void del_overlay(ea_t ea);
  const ea_t get_overlay_real_addr_by_index(size_t n) const;
  const ea_t get_overlay_over_addr_by_index(size_t n) const;
  const qstring* get_overlay_path_by_index(size_t n) const;
  const size_t get_overlay_index_by_real_addr(ea_t real_addr) const;
  void update_overlay(size_t n, qstring* name, ea_t old_real_addr, ea_t new_real_addr, bool moved);
  void update_overlays_list(ea_t start_ea = BADADDR, ea_t end_ea = BADADDR);
  size_t add_overlay(const qstring* name, ea_t overlayed_addr, ea_t real_addr);

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
};

ssize_t idaapi idb_post_event_visitor_t::handle_post_event(ssize_t code, int notification_code, va_list va) {
  switch (notification_code) {
  case idb_event::segm_deleted: {
    if (!ida_move_del_ren) {
      break;
    }

    ea_t start_ea = va_arg(va, ea_t);
    ea_t end_ea = va_arg(va, ea_t);

    ctx.del_overlay(start_ea);
  } break;
  case idb_event::segm_start_changed: {
    segment_t* s = va_arg(va, segment_t*);
    ea_t oldstart = va_arg(va, ea_t);

    size_t n = ctx.get_overlay_index_by_real_addr(oldstart);

    if (n == -1) {
      break;
    }

    qstring name;
    get_visible_segm_name(&name, s);

    ctx.update_overlay(n, &name, oldstart, s->start_ea, true);
  } break;
  case idb_event::segm_name_changed: {
    if (!ida_move_del_ren) {
      break;
    }

    refresh_chooser(overlays_wnd_title);
  } break;
  case idb_event::changing_segm_end: {
    refresh_chooser(overlays_wnd_title);
  } break;
  case idb_event::segm_moved: {
    if (!ida_move_del_ren) {
      break;
    }

    ea_t from = va_arg(va, ea_t);
    ea_t to = va_arg(va, ea_t);
    asize_t size = va_arg(va, asize_t);

    auto* segm = getseg(to);

    if (segm == nullptr) {
      break;
    }

    size_t n = ctx.get_overlay_index_by_real_addr(from);

    if (n == -1) {
      break;
    }

    qstring name;
    get_visible_segm_name(&name, segm);

    ctx.update_overlay(n, &name, from, to, true);
  } break;
  }

  return code;
}

chooser_t::cbret_t overrides_list_t::ask_for_override(size_t n, bool enabled, ea_t addr, int op_idx, ea_t new_addr) {
  ushort _enabled = enabled;
  ea_t _addr = addr;
  sval_t _op_idx = op_idx;
  ea_t _new_addr = new_addr;

  int res;

  if (n != -1) {
    res = ask_form(EDIT_FORM, &_enabled, &_addr, &_op_idx, &_new_addr);
  }
  else {
    res = ask_form(ADD_FORM, &_addr, &_op_idx, &_new_addr);
  }

  switch (res) {
  case 1: {
    if (n != -1) {
      ctx.update_override_value(n, _enabled, _addr, (int)_op_idx, _new_addr);
      return cbret_t(n, SELECTION_CHANGED);
    }
    else {
      ea_t old_addr = get_insn_old_addr(_addr, _op_idx);
      n = ctx.add_override(_addr, _op_idx, _new_addr, old_addr);
      return cbret_t(n, ALL_CHANGED);
    }
  } break;
  default:
    return cbret_t();
  }
}

chooser_t::cbret_t idaapi overrides_list_t::del(size_t n) newapi {
  const auto* over = ctx.get_override_by_index(n);
  ctx.del_override(over->addr, over->op_idx);

  return cbret_t(n, SELECTION_CHANGED);
}


inline chooser_t::cbret_t idaapi overrides_list_t::enter(size_t n) newapi {
  const auto* over = ctx.get_override_by_index(n);

  jumpto(over->addr, over->op_idx);
  return cbret_t();
}


void idaapi overrides_list_t::closed() {
  ctx.save_overrides();
}


size_t idaapi overrides_list_t::get_count() const {
  return ctx.overrides_count();
}


ea_t idaapi overrides_list_t::get_ea(size_t n) const {
  const auto* over = ctx.get_override_by_index(n);
  return over->addr;
}


void idaapi overrides_list_t::get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const {
  const auto* over = ctx.get_override_by_index(n);

  qstrvec_t& cols = *cols_;

  cols[(int)OverridesListColumns::OLC_Enabled].sprnt("%s", over->enabled ? "X" : "");
  cols[(int)OverridesListColumns::OLC_EA].sprnt("0x%a", over->addr);
  cols[(int)OverridesListColumns::OLC_OpIndex].sprnt("%d", over->op_idx);

  qstring name;
  name = get_name(over->new_addr, GN_SHORT);
  cols[(int)OverridesListColumns::OLC_NewAddr].sprnt("0x%a (%s)", over->new_addr, name.c_str());

  name = get_name(over->old_addr, GN_SHORT);
  cols[(int)OverridesListColumns::OLC_OldAddr].sprnt("0x%a (%s)", over->old_addr, name.c_str());
}


bool idaapi overrides_list_t::init() {
  ctx.load_overrides();
  return ctx.overrides_count() > 0;
}


chooser_t::cbret_t idaapi overrides_list_t::edit(size_t n) newapi {
  const auto* over = ctx.get_override_by_index(n);
  return ask_for_override(n, over->enabled, over->addr, over->op_idx, over->new_addr);
}


chooser_t::cbret_t idaapi overrides_list_t::refresh(ssize_t n) newapi {
  ctx.load_overrides();
  return cbret_t(n == -1 ? NO_SELECTION : n, n == -1 ? chooser_base_t::SELECTION_CHANGED : chooser_base_t::ALL_CHANGED);
}


chooser_t::cbret_t idaapi overrides_list_t::ins(ssize_t n) newapi {
  const auto* over = ctx.get_override_by_index(n);
  return ask_for_override();
}

chooser_t::cbret_t overlays_list_t::ask_for_overlay(size_t n /*= -1*/, const qstring* name /*= "nullptr"*/, ea_t overlayed_addr /*= BADADDR*/, ea_t real_addr /*= BADADDR*/) {
  qstring new_segm_name;
  size_t overs_count = ctx.overlays_count();
  new_segm_name.sprnt("OVER%d", overs_count + 1);

  qstring _segm_name = (name != nullptr) ? *name : new_segm_name;
  ea_t _over_addr = overlayed_addr;
  ea_t _real_addr = real_addr;
  int res;

  if (n == -1) {
    if (last_over_addr == BADADDR) {
      if (overs_count == 0) {
        const auto* segm = (overs_count == 0) ? get_segm_by_name("RAM") : nullptr;

        if (segm != nullptr) {
          _real_addr = _over_addr = segm->start_ea;
        }
      } else {
        _real_addr = _over_addr = ctx.get_overlay_over_addr_by_index(0);
      }
    } else {
      _real_addr = _over_addr = last_over_addr;
    }

#ifndef __EA64__
    _real_addr += (ea_t)((0x10000000) * (overs_count + 1));
#else
    _real_addr += (ea_t)((0x10000000 * (overs_count + 1)) << 32);
#endif // __EA64__

    res = ask_form(ADD_FORM, &_segm_name, &_over_addr, &_real_addr);

    if (!check_overlay_params(&_segm_name, _over_addr, _real_addr)) {
      return cbret_t();
    }

    last_over_addr = _over_addr;
  }
  else {
    res = ask_form(EDIT_FORM, &_segm_name, &_real_addr);
  }

  switch (res) {
  case 1: {
    if (n != -1) {
      ctx.update_overlay(n, &_segm_name, real_addr, _real_addr, false);
      return cbret_t(n, SELECTION_CHANGED);
    }
    else {
      n = ctx.add_overlay(&_segm_name, _over_addr, _real_addr);
      return cbret_t(n, ALL_CHANGED);
    }
  } break;
  default: {
    return cbret_t();
  }
  }
}

bool overlays_list_t::check_overlay_params(const qstring* name, ea_t overlayed_addr, ea_t real_addr) {
  if (name != nullptr) {
    const auto* s = get_segm_by_name(name->c_str());

    if (s != nullptr) {
      warning("Segment %s already exists!\n", name->c_str());
      return false;
    }
  }

  if (real_addr != BADADDR) {
    const auto* s = getseg(real_addr);

    if (s != nullptr) {
      warning("Segment with addr 0x%a already exists!\n", real_addr);
      return false;
    }

    if (overlayed_addr != BADADDR && overlayed_addr == real_addr) {
      warning("Overlayed and real addresses must not overlap!\n");
      return false;
    }
  }

  return true;
}

chooser_t::cbret_t idaapi overlays_list_t::del(size_t n) newapi {
  const auto real_addr = ctx.get_overlay_real_addr_by_index(n);

  const auto* segm = getseg(real_addr);

  if (segm == nullptr) {
    return cbret_t();
  }

  ida_move_del_ren = false;
  if (!del_segm(real_addr, SEGMOD_KILL)) {
    return cbret_t();
  }
  ida_move_del_ren = true;

  ctx.del_overlay(real_addr);

  return cbret_t(n, chooser_base_t::SELECTION_CHANGED);
}

chooser_t::cbret_t idaapi overlays_list_t::enter(size_t n) newapi {
  const auto real_addr = ctx.get_overlay_real_addr_by_index(n);

  jumpto(real_addr);
  return cbret_t();
}

void idaapi overlays_list_t::closed() {
  ctx.save_overlays();
}

size_t idaapi overlays_list_t::get_count() const {
  return ctx.overlays_count();
}

ea_t idaapi overlays_list_t::get_ea(size_t n) const {
  return ctx.get_overlay_real_addr_by_index(n);
}

void idaapi overlays_list_t::get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const {
  const auto real_addr = ctx.get_overlay_real_addr_by_index(n);
  const auto over_addr = ctx.get_overlay_over_addr_by_index(n);
  const auto* path = ctx.get_overlay_path_by_index(n);

  const auto* segm = getseg(real_addr);

  if (segm == nullptr) {
    return;
  }

  qstrvec_t& cols = *cols_;

  qstring sname;
  get_visible_segm_name(&sname, segm);
  cols[(int)OverlaysListColumns::OLC_Name].sprnt("%s", sname.c_str());
  cols[(int)OverlaysListColumns::OLC_OverlayAddr].sprnt("0x%a", over_addr);
  cols[(int)OverlaysListColumns::OLC_RealAddr].sprnt("0x%a", real_addr);
  cols[(int)OverlaysListColumns::OLC_Size].sprnt("%lu", segm->size());
  cols[(int)OverlaysListColumns::OLC_Path].sprnt("%s", path != nullptr ? path->c_str() : "");
}

bool idaapi overlays_list_t::init() {
  ctx.load_overlays();
  return ctx.overlays_count() > 0;
}

chooser_t::cbret_t idaapi overlays_list_t::edit(size_t n) newapi {
  const auto real_addr = ctx.get_overlay_real_addr_by_index(n);
  const auto over_addr = ctx.get_overlay_over_addr_by_index(n);

  const auto* segm = getseg(real_addr);

  if (segm == nullptr) {
    warning("Cannot edit non existing segment at 0x%a\n", real_addr);
    return cbret_t();
  }

  qstring segm_name;
  get_visible_segm_name(&segm_name, segm);

  return ask_for_overlay(n, &segm_name, over_addr, real_addr);
}

chooser_t::cbret_t idaapi overlays_list_t::refresh(ssize_t n) newapi {
  ctx.load_overlays();
  return cbret_t(n == -1 ? NO_SELECTION : n, n == -1 ? chooser_base_t::ALL_CHANGED : chooser_base_t::SELECTION_CHANGED);
}

chooser_t::cbret_t idaapi overlays_list_t::ins(ssize_t n) newapi {
  const auto real_addr = ctx.get_overlay_real_addr_by_index(n);
  const auto over_addr = ctx.get_overlay_over_addr_by_index(n);

  return ask_for_overlay();
}

void plugin_ctx_t::free_overrides() {
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    delete i->second.first;
  }

  overrides.clear();
}

void plugin_ctx_t::save_overrides() {
  n_overrides.create(overrides_node);

  n_overrides.altset((int)OverridesStorageAltType::OSAT_Count, (nodeidx_t)overrides.size());

  nodeidx_t idx = 0;
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    const auto ea = i->first.first;
    const auto ea_idx = i->first.second;

    const auto* over = i->second.first;

    n_overrides.altset(idx + (int)OverridesStorageAltType::OSAT_Enabled, over->enabled);
    n_overrides.altset(idx + (int)OverridesStorageAltType::OSAT_EA, ea);
    n_overrides.altset(idx + (int)OverridesStorageAltType::OSAT_OpIndex, ea_idx);
    n_overrides.altset(idx + (int)OverridesStorageAltType::OSAT_NewAddr, over->new_addr);
    n_overrides.altset(idx + (int)OverridesStorageAltType::OSAT_OldAddr, over->old_addr);
    idx += (int)OverridesStorageAltType::OSAT_Last - 1;
  }
}

void plugin_ctx_t::load_overrides() {
  free_overrides();

  n_overrides.create(overrides_node);

  int overridesCount = (int)n_overrides.altval((int)OverridesStorageAltType::OSAT_Count);

  nodeidx_t idx = 0;
  for (auto i = 0; i < overridesCount; ++i) {
    override_t* over = new override_t();

    over->enabled = n_overrides.altval(idx + (int)OverridesStorageAltType::OSAT_Enabled);
    over->addr = (ea_t)n_overrides.altval(idx + (int)OverridesStorageAltType::OSAT_EA);
    over->op_idx = (int)n_overrides.altval(idx + (int)OverridesStorageAltType::OSAT_OpIndex);
    over->new_addr = (ea_t)n_overrides.altval(idx + (int)OverridesStorageAltType::OSAT_NewAddr);
    over->old_addr = (ea_t)n_overrides.altval(idx + (int)OverridesStorageAltType::OSAT_OldAddr);
    idx += (int)OverridesStorageAltType::OSAT_Last - 1;

    overrides[std::pair<ea_t, size_t>(over->addr, over->op_idx)] = std::pair<override_t*, size_t>(over, overrides.size());
  }
}

void plugin_ctx_t::del_override(ea_t ea, int op_idx) {
  for (auto i = overrides.begin(); i != overrides.end();) {
    const auto over_ea = i->first.first;
    const auto ea_idx = i->first.second;

    if (over_ea == ea && ea_idx == op_idx) {
      overrides.erase(i);
      break;
    }
    else {
      ++i;
    }
  }

  update_overrides_list(ea);
}


void plugin_ctx_t::switch_override(ea_t ea, int op_idx) {
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

const override_t* plugin_ctx_t::get_override_by_index(size_t n) const {
  for (auto i = overrides.cbegin(); i != overrides.cend(); ++i) {
    const auto over = i->second.first;
    const auto list_idx = i->second.second;

    if (list_idx == n) {
      return over;
    }
  }

  return new override_t();
}

void plugin_ctx_t::update_override_value(size_t n, bool enabled, ea_t addr, int op_idx, ea_t new_addr) {
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

const override_t* plugin_ctx_t::find_override(ea_t ea, int op_idx) {
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

void plugin_ctx_t::update_overrides_list(ea_t ea) {
  save_overrides();

  if (ea != BADADDR) {
    plan_ea(ea);
    auto_wait();
  }

  load_overrides();
  refresh_chooser(overrides_wnd_title);
}

size_t plugin_ctx_t::add_override(ea_t ea, int op_idx, ea_t new_ea, ea_t old_ea) {
  override_t* over = new override_t({ true, ea, op_idx, new_ea, old_ea });

  size_t n = overrides.size();
  overrides[std::pair<ea_t, size_t>(ea, op_idx)] = std::pair<override_t*, size_t>(over, n);

  update_overrides_list(ea);

  return n;
}

void plugin_ctx_t::free_overlays() {
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    delete i->second.first->path;
    delete i->second.first;
  }

  overlays.clear();
}

void plugin_ctx_t::save_overlays() {
  n_overlays.create(overlays_node);

  n_overlays.altset((int)OverlaysStorageAltType::OSAT_Count, (nodeidx_t)overlays.size());

  nodeidx_t idx = 0;
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    const auto real_addr = i->first;
    const auto* overlay = i->second.first;

    n_overlays.altset(idx + (int)OverlaysStorageAltType::OSAT_OverlayAddr, overlay->over_addr);
    n_overlays.altset(idx + (int)OverlaysStorageAltType::OSAT_RealAddr, real_addr);
    n_overlays.supset(idx + (int)OverlaysStorageAltType::OSAT_Path, overlay->path->c_str());
    idx += (int)OverlaysStorageAltType::OSAT_Last - 1;
  }
}

void plugin_ctx_t::load_overlays() {
  free_overlays();

  n_overlays.create(overlays_node);

  int overlaysCount = (int)n_overlays.altval((int)OverlaysStorageAltType::OSAT_Count);

  nodeidx_t idx = 0;
  for (auto i = 0; i < overlaysCount; ++i) {
    ea_t overlayed_addr = (ea_t)n_overlays.altval(idx + (int)OverlaysStorageAltType::OSAT_OverlayAddr);
    ea_t real_addr = (ea_t)n_overlays.altval(idx + (int)OverlaysStorageAltType::OSAT_RealAddr);

    qstring* path = new qstring();
    n_overlays.supstr(path, idx + (int)OverlaysStorageAltType::OSAT_Path);

    overlay_t* overlay = new overlay_t({ overlayed_addr, path });

    idx += (int)OverlaysStorageAltType::OSAT_Last - 1;

    overlays[real_addr] = std::pair<overlay_t*, size_t>(overlay, overlays.size());
  }
}

void plugin_ctx_t::del_overlay(ea_t ea) {
  overlays.erase(ea);

  update_overlays_list();
}

const ea_t plugin_ctx_t::get_overlay_real_addr_by_index(size_t n) const {
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    const auto real_addr = i->first;
    const auto index = i->second.second;

    if (index == n) {
      return real_addr;
    }
  }

  return BADADDR;
}

const ea_t plugin_ctx_t::get_overlay_over_addr_by_index(size_t n) const {
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    const auto* overlay = i->second.first;
    const auto index = i->second.second;

    if (index == n) {
      return (overlay != nullptr) ? overlay->over_addr : BADADDR;
    }
  }

  return BADADDR;
}

const qstring* plugin_ctx_t::get_overlay_path_by_index(size_t n) const {
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    const auto* overlay = i->second.first;
    const auto index = i->second.second;

    if (index == n) {
      return (overlay != nullptr) ? overlay->path : nullptr;
    }
  }

  return nullptr;
}

const size_t plugin_ctx_t::get_overlay_index_by_real_addr(ea_t real_addr) const {
  for (auto i = overlays.cbegin(); i != overlays.cend(); ++i) {
    const auto i_addr = i->first;
    const auto index = i->second.second;

    if (i_addr == real_addr) {
      return index;
    }
  }

  return -1;
}

void plugin_ctx_t::update_overlay(size_t n, qstring* name, ea_t old_real_addr, ea_t new_real_addr, bool moved) {
  for (auto i = overlays.begin(); i != overlays.end(); ) {
    auto* overlay = i->second.first;
    const auto index = i->second.second;

    if (index == n) {
      auto* segm = getseg(moved ? new_real_addr : old_real_addr);

      if (segm == nullptr) {
        return;
      }

      ida_move_del_ren = false;
      int res = move_segm(segm, new_real_addr, MSF_NOFIX);
      ida_move_del_ren = true;

      switch (res) {
      case MOVE_SEGM_OK: {
        ida_move_del_ren = false;
        int res2 = set_segm_name(segm, name->c_str());
        ida_move_del_ren = true;

        switch (res2) {
        case 1: {
          overlays[new_real_addr] = std::pair<overlay_t*, size_t>(overlay, n);

          if (old_real_addr != new_real_addr) {
            overlays.erase(i);
          }
        } break;
        }

        update_overlays_list();
        return;
      } break;
      }

      qstring segm_name;
      get_visible_segm_name(&segm_name, segm);

      warning("Cannot update %s segment!\n", segm_name.c_str());
      return;
    } else {
      ++i;
    }
  }
}

void plugin_ctx_t::update_overlays_list(ea_t start_ea /*= BADADDR*/, ea_t end_ea /*= BADADDR*/) {
  save_overlays();

  if (start_ea != BADADDR && end_ea != BADADDR) {
    plan_range(start_ea, end_ea);
  }

  load_overlays();
  refresh_chooser(overlays_wnd_title);
}

size_t plugin_ctx_t::add_overlay(const qstring* name, ea_t overlayed_addr, ea_t real_addr) {
  if (!overlays_list_t::check_overlay_params(name, overlayed_addr, real_addr)) {
    return -1;
  }

  char* over_path = ask_file(false, "*.bin", "Select overlay binary...");

  if (over_path == nullptr) {
    return -1;
  }

  linput_t* li = open_linput(over_path, false);

  if (li == nullptr) {
    warning("Cannot load overlay binary!\n");
    return -1;
  }

  if (!load_binary_file(over_path, li, NEF_CODE | NEF_SEGS, 0, 0, real_addr, 0)) {
    warning("Cannot load overlay binary!\n");
    return -1;
  }

  close_linput(li);

  auto* segm = getseg(real_addr);

  if (segm == nullptr) {
    warning("Cannot find segment at 0x%a address\n", real_addr);
    return -1;
  }

  set_segm_name(segm, name->c_str());

  size_t n = overlays.size();

  qstring* path = new qstring();
  path->sprnt("%s", over_path);
  overlay_t* overlay = new overlay_t({ overlayed_addr, path });
  overlays[real_addr] = std::pair<overlay_t*, size_t>(overlay, n);

  update_overlays_list(real_addr, segm->end_ea);

  return n;
}

static plugmod_t * idaapi init(void) {
  return new plugin_ctx_t;
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
    PLUGIN_MULTI, // plugin flags
    init, // initialize

    nullptr, // terminate. this pointer may be NULL.

    nullptr, // invoke plugin

    comment, // long comment about the plugin
             // it could appear in the status line
             // or as a hint

    help, // multiline help about the plugin

    "References Overrider", // the preferred short name of the plugin

    overrides_change_dest_hotkey // the preferred hotkey to run the plugin
};