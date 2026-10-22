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

// instead of creating deep expressions of everything, we'll just have a basic
// check to see how deep the expression is.
static bool too_big(const vtil::symbolic::expression::reference &e) {
  if (e->depth > vtil::forward::forward_vm::max_depth)
    return true;

  std::int32_t cnt = 0;

  e->enumerate([&cnt](const vtil::symbolic::expression &x) { ++cnt; });

  return cnt > 64;
}
// vtil has an issue where it dereferences null on register_desc::to_string()
// for registers that vtil doesn't have a name for, x87 registers in junk
// decoded as code caused this to arise so we'll just avoid using to_string()
// and use this format.
static std::string reg_key(const vtil::register_desc &reg) {
  return std::format("{:x}.{:x}.{}.{}", static_cast<std::uint64_t>(reg.flags),
                     reg.combined_id, reg.bit_offset, reg.bit_count);
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
fresh_unk_lazy(bitcnt_t bits, const std::function<whyinf()> &describe,
               std::string site) {
  static std::uint32_t next = 0;
  static std::unordered_map<std::string, std::uint64_t> id_map;
  // the difference here vs before is that we're going to make it so that
  // unknowns that should be the same are re-used instead of creating a
  // fresh_unk each time. this can be seen by re-running the same block.
  if (!site.empty()) {
    std::string key = std::format("{}:{}", site, bits);
    if (auto it = id_map.find(key); it != id_map.end()) {
      return vtil::symbolic::variable{
          vtil::register_desc{vtil::register_virtual, it->second, bits}}
          .to_expression();
    }
    id_map.emplace(std::move(key), 0x100000ull + next);
  }

  auto id = 0x100000ull + next++;

  unk_why[id] = describe();

  return vtil::symbolic::variable{
      vtil::register_desc{vtil::register_virtual, id, bits}}
      .to_expression();
}
static vtil::symbolic::expression::reference
fresh_unk(bitcnt_t bits, std::string why,
          vtil::symbolic::expression::reference e = {},
          const std::string &site = {}) {
  return fresh_unk_lazy(bits, [&] { return whyinf{std::move(why), e}; }, site);
}
/*
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
*/
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

    // we should treat anything read from a writable section as symbolic because
    // it could be written to and different from the version it is on disk,
    // anything that isn't in a writable section we should just do as we
    // normally do and that is read from disk. rip itself is lifted as an rva,
    // so anything built from it is also an rva
    std::uint64_t rva = res >= base ? res - base : res;
    if (rva < pe->get_size()) {
      for (const auto &sec : pe->get_sections()) {
        const auto *h = sec.header;
        if ((h->Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (rva >= h->VirtualAddress &&
             rva < h->VirtualAddress + h->Misc.VirtualSize))
          return vtil::symbolic_vm::read_memory(ptr, bytes);
      }

      auto rb = pe->get_rva_bytes(static_cast<std::uint32_t>(rva),
                                  static_cast<std::uint32_t>(bytes));
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
  if (too_big(value) && has_unknown(value))
    value = fresh_unk_lazy(
        reg.bit_count,
        [reg, value] {
          return whyinf{std::format("widened {} = {}", reg.to_string(),
                                    value->to_string().substr(0, 120)),
                        value};
        },
        site.empty() ? site : site + ":wr:" + reg_key(reg));
  vtil::symbolic_vm::write_register(reg, std::move(value));
}

bool vtil::forward::forward_vm::write_memory(
    const vtil::symbolic::expression::reference &ptr,
    vtil::deferred_value<vtil::symbolic::expression::reference> value,
    bitcnt_t size) {
  auto v = value.get();
  if (too_big(v) && has_unknown(v))
    v = fresh_unk_lazy(
        size,
        [ptr, v] {
          return whyinf{std::format("widened {} = {}", ptr.to_string(),
                                    v->to_string().substr(0, 120)),
                        v};
        },
        site.empty() ? site : site + ":wm");

  return vtil::symbolic_vm::write_memory(ptr, v, size);
}

const vtil::symbolic_vm *
vtil::forward::states::get(const vtil::basic_block *block) const {

  auto it = at_end.find(block);
  return it != at_end.end() ? &it->second : nullptr;
}

void vtil::forward::states::invalidate(const vtil::basic_block *block) {
  dirty.insert(block);
}

void vtil::forward::states::forget(const vtil::basic_block *block) {
  at_end.erase(block);
  dirty.erase(block);
  entries.erase(block);
  join_sig.erase(block);
  fork_cond.erase(block);
  resolved.erase(block);
  changed.erase(block);
  end_hash.erase(block);
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

// split up run to now be able handle loops properly, we shouldn't fold loads
// too early because in a loop we don't know when that load could suddenly stop
// being constant. the big mistake currently with how we handle it is that in a
// loop, on the first iteration the state is already built and everything
// ongoing is then built off of that.
static std::optional<vtil::symbolic_vm>
start_state(const vtil::basic_block *block, vtil::forward::states &fs,
            std::string &sig) {
  sig.clear();

  if (fs.entries.count(block))
    return vtil::forward::entry_state();

  const auto &pred = block->prev;
  // if we've not seen this block but we've seen its predecesser and we've
  // stored that state then we'll adopt that state for this block too.

  if (pred.size() == 1)
    return pred_state(pred[0], fs);
  // we now are going to merge multiple branches
  else if (pred.size() >= 2)
    return join_start(block, fs, sig);

  return std::nullopt;
}

static vtil::symbolic_vm exec_block(vtil::basic_block *block,
                                    vtil::symbolic_vm vm, const Pe &pe,
                                    std::size_t *folded,
                                    const vtil::instruction *stop = nullptr) {
  // erase any temporaries as they are block local, we shouldn't carry them
  // over to each new state especially copied states.
  std::erase_if(vm.register_state.value_map, [](const auto &kv) {
    return kv.first.flags & vtil::register_local;
  });

  vtil::forward::forward_vm fvm;
  static_cast<vtil::symbolic_vm &>(fvm) = std::move(vm);
  fvm.pe = &pe;

  std::size_t idx = 0;
  for (auto it = block->begin(); !it.is_end(); ++it, ++idx) {
    if (stop && &*it == stop)
      break;

    fvm.site = std::format("{:x}:{}", block->entry_vip, idx);
    auto why = fvm.execute(*it);
    if (why != vtil::vm_exit_reason::none) {
      // vmprotect can call native functions to which it will leave the vm to
      // call, under ms x64 calling convention, the callee can clobber every
      // volatile register and hand its result back in rax, under this knowledge
      // we should see that none of the registers may survive the call. what we
      // do to fix this is just turn those registers into fresh unknowns.
      if (it->base == &vtil::ins::vxcall) {
        for (auto reg :
             {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
              ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10,
              ZYDIS_REGISTER_R11}) {
          auto r = vtil::zydis_to_vtil_reg(reg).reg();
          fvm.write_register(r,
                             fresh_unk_lazy(
                                 r.bit_count,
                                 [block, it] {
                                   return whyinf{std::format("{:x} : after {}",
                                                             block->entry_vip,
                                                             it.to_string()),
                                                 {}};
                                 },
                                 fvm.site + ":" + reg_key(r)));
        }
        fvm.write_register(vtil::REG_FLAGS,
                           fresh_unk_lazy(
                               vtil::REG_FLAGS.bit_count,
                               [block, it] {
                                 return whyinf{std::format("{:x} : after {}",
                                                           block->entry_vip,
                                                           it.to_string()),
                                               {}};
                               },
                               fvm.site + ":flags"));
        continue;
      }

      if (!it->base->is_branching()) {

        for (auto [op, type] : it->enum_operands()) {
          if (type >= vtil::operand_type::write && op.is_register() &&
              !op.reg().is_stack_pointer())
            fvm.write_register(
                op.reg(),
                fresh_unk_lazy(
                    op.bit_count(),
                    [&] {
                      std::string k_why = std::format(
                          "{:x} : {}", block->entry_vip, it->to_string());
                      vtil::symbolic::expression::reference k_expr = {};

                      if (it->base == &vtil::ins::ldd) {
                        auto [mb, mo] = it->memory_location();
                        k_expr = (fvm.read_register(mb) + mo).simplify();
                        k_why += std::format(", ptr = {}",
                                             k_expr.to_string().substr(0, 120));
                      }
                      return whyinf{std::move(k_why), std::move(k_expr)};
                    },
                    fvm.site + ":" + reg_key(op.reg())));
        }
      }
      continue;
    }

    // previously we used to fold everytime an instruction was executed but now
    // we've opted to only fold when explicity asked to, this doubles on the
    // idea that before in a loop we cannot prove that a value that is constant
    // on one iteration can be constant the next iteration.
    if (folded && it->base == &vtil::ins::ldd) {
      auto dst = it->operands[0];
      auto v = fvm.read_register(dst.reg()).simplify();
      if (v->is_constant()) {
        (+it)->base = &vtil::ins::mov;
        (+it)->operands = {
            dst, vtil::operand{*v->get<std::uint64_t>(), dst.bit_count()}};
        ++*folded;
      }
    }
  }
  return std::move(static_cast<vtil::symbolic_vm &>(fvm));
}

static std::uint64_t state_hash(const vtil::symbolic_vm &vm) {
  auto mix = [](std::uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return x;
  };
  std::uint64_t h = 0;
  const auto &rs = vm.register_state.value_map;
  for (const auto &[k, seg] : rs) {
    if (k.flags & vtil::register_local)
      continue;
    std::uint64_t e = mix(rs.hash_function()(k)) ^ seg.bitmap;
    for (std::size_t i = 0; i < 64; ++i)
      if (seg.linear_store[i])
        e = mix(e + i * 0x9e3779b97f4a7c15ull +
                seg.linear_store[i]->hash().as64());
    h += mix(e);
  }
  for (const auto &[ptr, val] : vm.memory_state)
    h += mix(std::hash<std::string>{}(ptr.to_string()) * 31 +
             (val ? val->hash().as64() : 0));
  return h;
}

std::size_t vtil::forward::run(const std::vector<vtil::basic_block *> &blocks,
                               states &fs, const Pe &pe) {

  constexpr std::size_t max_laps = 64;
  std::size_t result = 0;

  std::deque<vtil::basic_block *> work{blocks.begin(), blocks.end()};

  // the main issue we had in the old version of our run was that it could never
  // really settle on loops,  it kept the same initial state and kept it going
  // which means something like a counter never really changed, nothing was
  // recomputed outside of the blocks that were handed to it. this means that
  // ordinary blocks would keep stale states and nothing would travel downstream
  // to the other blocks. what we solve here is that when a change is made,
  // anything linked should be recomputed so that each affected block no longer
  // has a stale state.

  std::unordered_set<vtil::basic_block *> queued{blocks.begin(), blocks.end()};
  std::unordered_set<vtil::basic_block *> forced{blocks.begin(), blocks.end()};
  std::unordered_map<vtil::basic_block *, std::size_t> lap_map;

  while (!work.empty()) {
    auto *block = work.front();
    work.pop_front();
    queued.erase(block);

    std::string sig;
    auto start = start_state(block, fs, sig);

    // no start state, will be re-queued once a predecessor is being worked
    if (!start)
      continue;

    bool force = forced.erase(block) != 0;
    bool join = block->prev.size() >= 2 && !fs.entries.count(block);

    if (!force && join && fs.get(block)) {
      auto it = fs.join_sig.find(block);
      if (it != fs.join_sig.end() && it->second == sig)
        continue;
    }

    if (++lap_map[block] > max_laps) {
      spdlog::warn("[forward] max laps reached for block {:x}, skipping",
                   block->entry_vip);
      continue;
    }

    if (join)
      fs.join_sig[block] = sig;

    // don't fold to begin with
    auto out = exec_block(block, std::move(*start), pe, nullptr);
    auto hash = state_hash(out);

    fs.at_end[block] = std::move(out);
    fs.changed.insert(block);
    ++result;

    auto [b_it, inserted] = fs.end_hash.try_emplace(block, hash);
    if (!inserted &&
        b_it->second ==
            hash) // hash already the same, nothing changed just continue
      continue;
    // not the same, store and queue successors as this could be a fresh path
    b_it->second = hash;

    for (auto *b : block->next)
      if (queued.insert(b).second)
        work.push_back(b);
  }

  return result;
}

vtil::symbolic::expression::reference vtil::forward::value_before(
    vtil::basic_block *block, vtil::il_const_iterator it,
    const vtil::register_desc &reg, states &fs, const Pe &pe) {

  std::string sig;
  auto start = start_state(block, fs, sig);

  if (!start)
    return {};

  // stop right before where we want to get the value of
  auto out = exec_block(block, std::move(*start), pe, nullptr, &*it);

  // check if it's a stack pointer adn if it is we'll return the stack address
  auto val = out.read_register(reg);
  if (reg.is_stack_pointer())
    return (val + it->sp_offset).simplify();

  return val.simplify();
}

std::size_t vtil::forward::fold_loads(vtil::routine *rtn, states &fs,
                                      const Pe &pe) {
  std::size_t result = 0;

  for (auto &[vip, block] : rtn->explored_blocks) {
    if (!fs.get(block.get()))
      continue;

    std::string sig;
    if (auto start = start_state(block.get(), fs, sig))
      exec_block(block.get(), std::move(*start), pe, &result);
  }

  spdlog::info("[forward] folded {} constant loads", result);

  return result;
}
