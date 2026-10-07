#include "forward.hpp"

// vmprotect inserts these tamper traps into each virtualised function, it's
// computed from a scan of the image's own bytes and conventiently never lands
// anywhere mappable. this path seems to only ever be taken if it finds a
// modified byte. symbollicaly this cannot be proven because the simplifer won't
// fold (a + b) >> 32while the low halves can carry, what we'll do is just
// substitute concrete values instead for each input and see where it lands,
// this is only ever used as a classifier for an output, the il wont change.
bool vtil::forward::never_in_image(
    const vtil::symbolic::expression::reference &targ, const Pe &pe) {
  std::uint64_t base = pe.get_image_base();

  for (std::uint64_t fill : {0ull, 1ull, ~0ull, base, base + 0x1000}) {
    // need to use as_const here in order to not rewrite the value we're trying
    // to probe.
    auto probe = std::as_const(targ)
                     .transform([fill](vtil::symbolic::expression_delegate &x) {
                       if (x->is_variable())
                         x = vtil::symbolic::expression(fill, x->size());
                     })
                     .simplify();

    if (!probe->is_constant())
      return false;

    if ((*probe->get<std::uint64_t>() >> 32) == (base >> 32))
      return false;
  }

  return true;
}

struct whyinf {
  std::string text;
  vtil::symbolic::expression::reference expr;
};

static std::unordered_map<std::uint64_t, whyinf> unk_why = {};

std::string vtil::forward::describe_var(const vtil::symbolic::variable &v) {

  static std::map<std::uint64_t, std::string> vreg_id{
      {0xc000, "cpuid.1.eax"},
      {0xc001, "cpuid.1.ebx"},
  };

  if (v.is_register()) {
    const auto &reg = v.reg();
    if (reg.is_virtual()) {
      std::uint64_t r_id = reg.local_id;

      // handle any symbolic values
      if (auto it = vreg_id.find(r_id); it != vreg_id.end())
        return it->second;
      else if (r_id >= 0x100000) {
        auto d_unk = describe_unk(r_id);
        return d_unk ? *d_unk
                     : std::format("unk#{}", r_id); // dunkmaster darius?
      }
      return reg.to_string();
    } else if (reg.is_stack_pointer())
      return "entry sp";

    return "entry " + reg.to_string();
  }

  else if (v.is_memory()) {
    const auto &mem = v.mem();

    auto base = mem.base.base.simplify();

    if (base->is_constant()) {
      auto ret = fake_env::name(*base->get<std::uint64_t>());
      if (ret)
        return *ret;
      else
        return std::format("memory [{}]", base->to_string().substr(0, 120));
    }

    auto sp0 = vtil::forward::entry_state().read_register(vtil::REG_SP);
    auto new_expr = (base - sp0).simplify();
    if (new_expr.is_constant()) {
      auto k = *new_expr.get<std::int64_t>();
      if (k == 0)
        return "return address";
      else
        return std::format("stack [entry sp + {:+#x}]", k);
    }

    return std::format("memory [{}]", base->to_string().substr(0, 120));
  }

  return "unk_var";
}

// only treat real verified exits as an exit, anything else should be marked as
// unresolved
bool vtil::forward::is_return(const vtil::symbolic::expression_reference &e) {
  // this should only fire if the return address is an unwritten memory slot
  // which reads back as a memory variable and base - sp0 is 0
  if (!e->is_variable())
    return false;

  const auto &v = e->uid.get<vtil::symbolic::variable>();
  if (!v.is_memory())
    return false;

  const auto &mem = v.mem();
  if (mem.bit_count != 64)
    return false;

  auto sp0 = vtil::forward::entry_state().read_register(vtil::REG_SP);
  auto expr = (mem.base.base - sp0).simplify();

  if (!expr.is_constant())
    return false;
  return *expr.get<std::int64_t>() == 0;
}

const std::string *vtil::forward::describe_unk(std::uint64_t id) {
  auto it = unk_why.find(id);
  return it != unk_why.end() ? &it->second.text : nullptr;
}

const vtil::symbolic::expression::reference *
vtil::forward::expr_unk(std::uint64_t id) {
  auto it = unk_why.find(id);
  return it != unk_why.end() && it->second.expr ? &it->second.expr : nullptr;
}

static bool has_unknown(const vtil::symbolic::expression::reference &e) {
  bool found = false;
  e->enumerate([&found](const vtil::symbolic::expression &x) {
    if (!x.is_variable())
      return;
    auto &v = x.uid.get<vtil::symbolic::variable>();
    if (!(v.is_register() && v.reg().is_stack_pointer()))
      found = true;
  });
  return found;
}

static vtil::symbolic::expression::reference
fresh_unk(bitcnt_t bits, std::string why,
          vtil::symbolic::expression::reference e = {}) {
  static std::uint32_t next = 0;
  auto id = 0x100000ull + next++;

  whyinf inf;
  inf.text = std::move(why);
  inf.expr = e;

  unk_why[id] = std::move(inf);

  return vtil::symbolic::variable{
      vtil::register_desc{vtil::register_virtual, id, bits}}
      .to_expression();
}

vtil::symbolic::expression::reference vtil::forward::forward_vm::read_memory(
    const vtil::symbolic::expression::reference &ptr, std::size_t bytes) const {
  std::uint64_t res = 0;
  std::uint64_t base = 0;

  if (bytes >= 1 && bytes <= 8 && is_return(ptr)) {
    std::uint64_t v = 0;
    for (std::int32_t idx = 0; idx < bytes; ++idx)
      v = (v << 8) | 0x90;

    spdlog::info(
        "[env] read through return address ({} bits) -> assuming no breakpoint",
        bytes * 8);

    return vtil::symbolic::expression(v, static_cast<bitcnt_t>(bytes * 8));
  }

  if (pe && ptr->is_constant()) {
    // make sure we handle our fake peb/teb field reads too. it's different live
    // vs on disk.
    // the os version fields are the function's real inputs, not protection
    // internals - leave them as unknown initial memory instead of faking them.
    if (auto a = *ptr->get<std::uint64_t>();
        a >= fake_env::PEB + 0x118 && a < fake_env::PEB + 0x128)
      return vtil::symbolic_vm::read_memory(ptr, bytes);
    if (auto v = fake_env::read(*ptr->get<std::uint64_t>(),
                                static_cast<unsigned>(bytes * 8)))
      return vtil::symbolic::expression{*v, static_cast<bitcnt_t>(bytes * 8)};
    if (auto addr = *ptr->get<std::uint64_t>(); fake_env::contains(addr)) {
      spdlog::info("[env] {:#x} ({} bits) not modelled, left unknown", addr,
                   bytes * 8);
      return vtil::symbolic_vm::read_memory(addr, bytes);
    }

    res = *ptr->get<std::uint64_t>();
    base = pe->get_image_base();
    if (res >= base && res - base < UINT32_MAX) {
      auto rb =
          pe->get_rva_bytes(res - base, static_cast<std::uint32_t>(bytes));
      std::uint64_t output = 0;
      if (rb.has_value()) {
        std::memcpy(&output, rb->data(), std::min<std::size_t>(rb->size(), 8));
        return vtil::symbolic::expression{output,
                                          static_cast<bitcnt_t>(bytes * 8)};
      }
    }
  }

  return vtil::symbolic_vm::read_memory(ptr, bytes);
}

void vtil::forward::forward_vm::write_register(
    const vtil::register_desc &reg,
    vtil::symbolic::expression::reference value) {
  if (value->depth > max_depth && has_unknown(value))
    value = fresh_unk(reg.bit_count,
                      std::format("widened {} = {}", reg.to_string(),
                                  value->to_string().substr(0, 120)),
                      value);
  vtil::symbolic_vm::write_register(reg, std::move(value));
}

bool vtil::forward::forward_vm::write_memory(
    const vtil::symbolic::expression::reference &ptr,
    vtil::deferred_value<vtil::symbolic::expression::reference> value,
    bitcnt_t size) {
  auto v = value.get();
  if (v->depth > max_depth && has_unknown(v))
    v = fresh_unk(size,
                  std::format("widened {} = {}", ptr.to_string(),
                              v->to_string().substr(0, 120)),
                  v);

  return vtil::symbolic_vm::write_memory(ptr, v, size);
}

const vtil::symbolic_vm *
vtil::forward::states::get(const vtil::basic_block *block) const {

  auto it = at_end.find(block);
  return it != at_end.end() ? &it->second : nullptr;
}

void vtil::forward::states::invalidate(const vtil::basic_block *block) {
  if (!at_end.erase(block))
    return;

  dirty.insert(block);

  for (auto *b : block->next)
    invalidate(b);
}

vtil::symbolic_vm vtil::forward::entry_state() {
  vtil::symbolic_vm vm;
  vm.write_register(vtil::REG_FLAGS,
                    vm.read_register(vtil::REG_FLAGS) & ~0x100ull);

  return vm;
}

static std::vector<vtil::register_desc> merge_regs() {
  std::vector<vtil::register_desc> regs = {vtil::REG_SP, vtil::REG_FLAGS};
  for (auto reg : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RCX,
                   ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
                   ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9,
                   ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
                   ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15})
    regs.push_back(vtil::zydis_to_vtil_reg(reg).reg());

  return regs;
}

static std::optional<vtil::symbolic_vm>
pred_state(vtil::basic_block *pred, const vtil::forward::states &fs) {
  auto *s = fs.get(pred);
  if (!s)
    return std::nullopt;

  vtil::symbolic_vm vm = *s;
  vm.write_register(vtil::REG_SP,
                    vm.read_register(vtil::REG_SP) + pred->sp_offset);

  return vm;
}

static vtil::symbolic::expression::reference
stable_unk(vtil::forward::states &fs, std::string key, bitcnt_t bits) {
  if (auto it = fs.join_unk.find(key); it != fs.join_unk.end())
    return it->second;

  auto v = fresh_unk(bits, key);
  fs.join_unk.emplace(key, v);
  return v;
}

static vtil::symbolic_vm
merge_states(const std::vector<vtil::symbolic_vm> &inputs,
             const vtil::basic_block *block, vtil::forward::states &fs,
             std::string &sig) {
  vtil::symbolic_vm out;
  sig.clear();
  // in here we're going to make sure that every reg or memory interaction
  // across each state that is the same gets saved into our exit state, anything
  // that is different is made an unknown. we use a new type of unknown being
  // the stable unknown which is built up off of the fresh unknown but we
  // monitor it and track it, by doing this - each block gets the same unknown
  // for the same slot. we build a fingerprint at the end to see if anything
  // actually changed, run will eventually check this and compare it with the
  // last one and seeing it it needs to recompute the join

  for (const auto &reg : merge_regs()) {
    auto v0 = inputs[0].read_register(reg).simplify();
    bool same = true;
    for (std::int32_t idx = 1; idx < inputs.size() && same; ++idx)
      same = inputs[idx].read_register(reg).simplify().is_identical(*v0);

    if (!same)
      v0 = stable_unk(
          fs, std::format("{:x}:r:{}", block->entry_vip, reg.to_string()),
          reg.bit_count);

    out.write_register(reg, *v0);
    sig += reg.to_string() + "=" + v0.to_string() + ";";
  }

  std::vector<std::pair<vtil::symbolic::pointer, bitcnt_t>> locs = {};
  std::unordered_set<std::string> seen = {};
  for (const auto &state : inputs) {
    for (const auto &[ptr, val] : state.memory_state) {
      auto str = ptr.to_string() + ":" + std::to_string(val->size());
      if (seen.insert(str).second)
        locs.emplace_back(ptr, val.size());
    }
  }

  for (const auto &[ptr, size] : locs) {
    auto v0 = inputs[0].memory_state.read(ptr, size);
    bool same = static_cast<bool>(v0);
    if (same)
      v0 = v0.simplify();

    for (std::int32_t idx = 1; idx < inputs.size() && same; ++idx) {
      auto vi = inputs[idx].memory_state.read(ptr, size);
      same = vi && vi.simplify()->is_identical(*v0);
    }

    if (!same)
      v0 = stable_unk(
          fs,
          std::format("{:x}:m:{}:{}", block->entry_vip, ptr.to_string(), size),
          size);

    out.memory_state.write(ptr, v0, size);
    sig += ptr.to_string() + "=" + v0->to_string() + ";";
  }

  return out;
}

static std::optional<vtil::symbolic_vm>
join_start(const vtil::basic_block *block, vtil::forward::states &fs,
           std::string &sig) {
  std::vector<vtil::symbolic_vm> inputs;
  for (auto *pred : block->prev)
    if (auto s = pred_state(pred, fs))
      inputs.push_back(std::move(*s));

  if (inputs.empty())
    return std::nullopt;

  return merge_states(inputs, block, fs, sig);
}

std::size_t vtil::forward::run(const std::vector<vtil::basic_block *> &blocks,
                               states &fs, const Pe &pe) {
  std::size_t result = 0;
  for (const auto &block : blocks) {
    vtil::symbolic_vm vm;
    // all entry blocks start from a clean vm state
    if (fs.entries.count(block))
      vm = entry_state();
    // if we've not seen this block but we've seen its predecesser and we've
    // stored that state then we'll adopt that state for this block too.
    else if (const auto &prev = block->prev;
             prev.size() == 1 && fs.get(prev[0])) {
      vm = *fs.get(prev[0]);
      // apply stack shift since this block starts at 0
      vm.write_register(vtil::REG_SP, vm.read_register(vtil::REG_SP) +
                                          block->prev[0]->sp_offset);
    }
    // here is where the magic happens, we now are going to merge multiple
    // branches
    else if (block->prev.size() >= 2) {
      std::string sig;
      auto merged = join_start(block, fs, sig);
      if (!merged)
        continue;

      // replace our state with the merged state which accounted for each
      // predecesser
      vm = std::move(*merged);
      fs.join_sig[block] = sig;
    } else
      continue;

    // erase any temporaries as they are block local, we shouldn't carry them
    // over to each new state especially copied states.
    std::erase_if(vm.register_state.value_map, [](const auto &kv) {
      return kv.first.flags & vtil::register_local;
    });

    forward_vm fvm;
    static_cast<vtil::symbolic_vm &>(fvm) = std::move(vm);
    fvm.pe = &pe;

    for (auto it = block->begin(); !it.is_end(); ++it) {
      // previously we used to have separate passes to fold image loads into
      // moving their constant value directly in for our tracer but now that we
      // have this vm state, we will walk each instruction and fold them
      // directly here.
      auto why = fvm.execute(*it);
      if (why != vtil::vm_exit_reason::none) {
        if (!it->base->is_branching()) {
          std::string k_why =
              std::format("{:x} : {}", block->entry_vip, it->to_string());
          vtil::symbolic::expression::reference k_expr = {};
          if (it->base == &vtil::ins::ldd) {
            auto [mb, mo] = it->memory_location();
            k_expr = (fvm.read_register(mb) + mo).simplify();
            k_why +=
                std::format(", ptr = {}", k_expr.to_string().substr(0, 120));
          }

          for (auto [op, type] : it->enum_operands()) {
            if (type >= vtil::operand_type::write && op.is_register() &&
                !op.reg().is_stack_pointer())
              fvm.write_register(op.reg(),
                                 fresh_unk(op.bit_count(), k_why, k_expr));
          }
        }
        continue;
      }

      if (it->base == &vtil::ins::ldd) {
        auto dst = it->operands[0];
        auto v = fvm.read_register(dst.reg()).simplify();
        if (v->is_constant()) {
          (+it)->base = &vtil::ins::mov;
          (+it)->operands = {
              dst, vtil::operand{*v->get<std::uint64_t>(), dst.bit_count()}};
          ++result;
        }
      }
    }
    /*
    for (vtil::il_const_iterator it = block->begin();;) {
      auto [at, why] = fvm.run(it);
      if (at.is_end())
        break;

      if (!at->base->is_branching()) {
        for (auto [op, type] : at->enum_operands())
          if (type >= vtil::operand_type::write && op.is_register() &&
              !op.reg().is_stack_pointer())
            fvm.write_register(op.reg(), fresh_unk(op.bit_count()));
      }
      it = std::next(at);
    }*/

    fs.at_end[block] = std::move(static_cast<vtil::symbolic_vm &>(fvm));

    // check to see what blocks merged and where it jumps to
    for (const auto &b : block->next) {
      // look specifically for joins, they'll have 2 or more predecssors not 1
      // or that's a fallthrough.
      if (b->prev.size() < 2 || !fs.get(b))
        continue;

      std::string sig;
      if (join_start(b, fs, sig) && sig != fs.join_sig[b])
        fs.invalidate(b);
    }
  }
  return result;
}
