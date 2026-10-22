#include "cfg.hpp"

#include "../vtil/jcc/jcc.hpp"
#include "../vtil/regs/regs.hpp"

// a new change we'll make is that we're going to filter out opaques directly in
// our cfg walk, vmprotect will pad code with opaques where the jccs condition
// is fixed by constants that are set a few instructions or few blocks earlier,
// what we'll do is we'll create a symbolic state that is passed alogn every
// edge which will keep values only if it's constant or a stack address that can
// be passed through our cfg walk, this will help us know if we're walking
// opaque predicates or not instead of lifting and deciding then.
namespace {
std::uint64_t walk_unk_id = 0x200000;
// we'll create fresh unknowns for anything that doesn't
// fit the criteria of what we're targeting. in our case it's anything that
// isn't a constant or stack address.
vtil::symbolic::expression::reference fresh_unk(bitcnt_t bits) {
  return vtil::symbolic::variable{
      vtil::register_desc{vtil::register_virtual, walk_unk_id++, bits}}
      .to_expression();
}

struct walk_vm : vtil::symbolic_vm {
  // can just think of this function as a filter, either return the raw value or
  // create a fresh unk for our vm.
  static vtil::symbolic::expression::reference
  narrow(vtil::symbolic::expression::reference v, bitcnt_t bits) {
    static const auto sp0 =
        vtil::symbolic::variable{vtil::REG_SP}.to_expression();
    if (v && (v->is_constant() ||
              (v.size() == 64 && (v - sp0).simplify().is_constant())))
      return v;

    return fresh_unk(bits);
  }

  void write_register(const vtil::register_desc &desc,
                      vtil::symbolic::expression::reference v) override {
    // narrow anything that isn't a stack pointer because the sp is what we're
    // always going to use as our point of reference for every other
    // calculation.
    if (!desc.is_stack_pointer())
      v = narrow(std::move(v), desc.bit_count);
    vtil::symbolic_vm::write_register(desc, v);
  }

  bool
  write_memory(const vtil::symbolic::expression::reference &ptr,
               vtil::deferred_value<vtil::symbolic::expression::reference> v,
               bitcnt_t size) override {
    return vtil::symbolic_vm::write_memory(ptr, narrow(v.get(), size), size);
  }
};

std::shared_ptr<vtil::symbolic_vm> seed_walk(const vtil::symbolic_vm &s) {
  walk_vm vm;
  for (auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RCX,
                 ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
                 ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9,
                 ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
                 ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15}) {
    auto reg = vtil::zydis_to_vtil_reg(r).reg();
    vm.write_register(reg, s.read_register(reg).simplify());
  }
  vm.write_register(vtil::REG_SP, s.read_register(vtil::REG_SP).simplify());
  return std::make_shared<vtil::symbolic_vm>(vm);
}

std::shared_ptr<vtil::symbolic_vm>
run_block(const basic_block &block, const std::shared_ptr<vtil::symbolic_vm> &s,
          bool include_last, std::optional<bool> *taken) {
  // create a scratch block to pull the instructions into, we only create it
  // once otherwise it trips up vtil's assertion for explored blocks being
  // deleted
  static vtil::basic_block *scratch = vtil::basic_block::begin(0x1000);
  scratch->clear();

  const std::int32_t end = block.instrs.size() - (include_last ? 0 : 1);
  for (std::int32_t idx = 0; idx < end; ++idx) {
    const auto &id = block.instrs[idx];
    vtil::lift_instr(scratch, id.rva, id.instr, id.operands.data(),
                     id.bytes.data());
  }

  vtil::operand cond;
  if (taken)
    cond = vtil::jcc_condition(scratch, block.instrs.back().instr.mnemonic);

  walk_vm vm;
  if (s)
    static_cast<vtil::symbolic_vm &>(vm) = *s;

  for (auto it = scratch->begin(); it != scratch->end(); ++it) {
    if (vm.execute(*it) == vtil::vm_exit_reason::none)
      continue;

    if (it->base == &vtil::ins::str)
      vm.memory_state.reset();

    for (const auto &[op, type] : it->enum_operands()) {
      if (type >= vtil::operand_type::write && op.is_register())
        vm.write_register(op.reg(), fresh_unk(op.bit_count()));
    }
  }

  if (taken)
    if (auto val = vm.read_register(cond.reg()).simplify(); val->is_constant())
      *taken = (*val->get<std::uint64_t>() & 1) != 0;

  // remove any temporaries from thsi block that we've created before handing
  // them to successors.
  auto out = std::make_shared<vtil::symbolic_vm>(vm);
  std::erase_if(out->register_state.value_map, [](const auto &kv) {
    return kv.first.flags & vtil::register_local;
  });

  return out;
}

} // namespace

cfg_fn::cfg_fn(pdb::pdb_fn fn_info, const Pe &pe, ZydisDecoder decoder)
    : fn_info(fn_info), pe(pe), decoder(decoder) {};

const pdb::pdb_fn &cfg_fn::get_fn_info() const { return fn_info; }

const std::unordered_map<std::uint32_t, basic_block> &
cfg_fn::get_blocks() const {
  return blocks;
}
std::expected<std::monostate, std::string>
cfg_fn::build_blocks(std::shared_ptr<const vtil::symbolic_vm> seeded) {
  auto in_fn = [&](std::uint64_t t) {
    return t >= fn_info.fn_rva && t < fn_info.fn_rva + fn_info.fn_size;
  };

  std::deque<std::pair<std::uint32_t, std::shared_ptr<vtil::symbolic_vm>>> work{
      {fn_info.fn_rva,
       seeded ? seed_walk(*seeded) : std::shared_ptr<vtil::symbolic_vm>{}}};

  std::size_t pruned = 0;

  while (!work.empty()) {
    auto [leader, entry] = std::move(work.front());

    work.pop_front();
    if (blocks.contains(leader))
      continue;
    if (split_at(leader))
      continue;

    basic_block b{.block_rva = leader, .term = block_terminator::unk};
    std::vector<std::pair<std::uint32_t, std::shared_ptr<vtil::symbolic_vm>>>
        next_states = {};

    std::uint32_t cur = leader;
    spdlog::info("[walk] start 0x{:x} is_exec={}", cur, is_exec(cur));

    while (is_exec(cur)) {
      auto bytes = pe.get_rva_bytes(cur, ZYDIS_MAX_INSTRUCTION_LENGTH);
      for (std::uint32_t n = ZYDIS_MAX_INSTRUCTION_LENGTH - 1; !bytes && n > 0;
           --n)
        bytes = pe.get_rva_bytes(cur, n);
      if (!bytes) {
        spdlog::warn("[walk] 0x{:x}: get_rva_bytes failed", cur);
        break;
      }
      ZydisDecodedInstruction instr;
      std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops;
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
              &decoder, bytes->data(), bytes->size(), &instr, ops.data()))) {
        spdlog::warn("[walk] 0x{:x}: decode failed ({} bytes: {:02x} {:02x} "
                     "{:02x} {:02x})",
                     cur, bytes->size(), (*bytes)[0], (*bytes)[1], (*bytes)[2],
                     (*bytes)[3]);
        break;
      }
      instr_data id{.rva = cur, .instr = instr, .operands = ops};
      std::memcpy(id.bytes.data(), bytes->data(), instr.length);
      b.instrs.push_back(id);

      std::uint32_t next = cur + instr.length;

      switch (instr.meta.category) {
      case ZYDIS_CATEGORY_UNCOND_BR:
        if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
          std::uint64_t t = 0;
          ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);
          b.term =
              in_fn(t) ? block_terminator::jmp : block_terminator::tail_call;
          if (is_exec(t)) {
            b.successors.push_back(
                static_cast<std::uint32_t>(t)); // follow it either way
            next_states.emplace_back(static_cast<std::uint32_t>(t),
                                     run_block(b, entry, false, nullptr));
          }
        } else {
          b.term = block_terminator::indirect_jmp;
        }
        goto done;

      case ZYDIS_CATEGORY_COND_BR: {
        std::uint64_t t = 0;
        ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);

        std::optional<bool> taken;
        auto out = run_block(b, entry, false, &taken);

        if (taken) {
          // we've encountered an opaque, find which arm runs and rewrite this
          // jcc to a jmp
          b.term = block_terminator::jmp;
          ++pruned;
          auto dst = *taken ? t : next;

          if (is_exec(dst)) {
            b.successors.push_back(static_cast<std::uint32_t>(dst));

            next_states.emplace_back(static_cast<std::uint32_t>(dst), out);
          }
          goto done;
        }

        b.term = block_terminator::jcc;
        if (is_exec(t)) {
          b.successors.push_back(static_cast<std::uint32_t>(t));
          next_states.emplace_back(static_cast<std::uint32_t>(t), out);
        }
        if (is_exec(next)) {
          b.successors.push_back(next);
          next_states.emplace_back(static_cast<std::uint32_t>(next), out);
        }
        goto done;
      }

      case ZYDIS_CATEGORY_CALL:
        if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
          std::uint64_t t = 0;
          ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);
          if (is_exec(t)) {
            b.term = block_terminator::call;
            b.successors.push_back(static_cast<std::uint32_t>(t));
            next_states.emplace_back(static_cast<std::uint32_t>(t),
                                     run_block(b, entry, true, nullptr));
            goto done;
          }
        }
        break;

      case ZYDIS_CATEGORY_RET:
        b.term = block_terminator::ret;
        goto done;

      default:
        break;
      }

      if (blocks.contains(next)) {
        b.term = block_terminator::fall_through;
        b.successors.push_back(next);
        goto done;
      }
      cur = next;
    }
  done:
    if (b.instrs.empty())
      continue;
    for (auto &ns : next_states)
      work.push_back(std::move(ns));
    blocks[leader] = std::move(b);
  }

  if (pruned)
    spdlog::info("[walk] {:#x}: pruned {} opaques", fn_info.fn_rva, pruned);
  return std::monostate{};
}
bool cfg_fn::split_at(std::uint32_t rva) {
  for (auto &[brva, b] : blocks) {
    for (std::size_t i = 1; i < b.instrs.size(); ++i) {
      if (b.instrs[i].rva != rva)
        continue;
      basic_block tail{.block_rva = rva,
                       .instrs = {b.instrs.begin() + i, b.instrs.end()},
                       .successors = std::move(b.successors),
                       .term = b.term};
      b.instrs.resize(i);
      b.successors = {rva};
      b.term = block_terminator::fall_through;
      blocks[rva] = std::move(tail);
      return true;
    }
  }
  return false;
}
bool cfg_fn::is_exec(std::uint64_t rva) const {
  for (const auto &sec : pe.get_sections()) {
    const auto *h = sec.header;
    if (!(h->Characteristics & IMAGE_SCN_MEM_EXECUTE))
      continue;
    if (rva >= h->VirtualAddress &&
        rva < h->VirtualAddress + h->Misc.VirtualSize)
      return true;
  }
  return false;
}

void cfg_fn::set_terminator(std::uint32_t rva, block_terminator term,
                            std::vector<std::uint32_t> successors) {
  auto it = blocks.find(rva);
  if (it == blocks.end())
    return;
  it->second.term = term;
  it->second.successors = std::move(successors);
}

std::expected<std::monostate, std::string>
cfg_fn::add_root(const pdb::pdb_fn &new_fn,
                 std::shared_ptr<const vtil::symbolic_vm> seeded) {
  if (blocks.count(new_fn.fn_rva))
    return std::monostate{};

  auto saved = fn_info;
  fn_info = new_fn;
  auto r = build_blocks(std::move(seeded));
  fn_info = saved;
  return r;
}

bool cfg_fn::is_lifted(vtil::vip_t vip) const { return lifted.count(vip) != 0; }
void cfg_fn::mark_lifted(vtil::vip_t vip) { lifted.insert(vip); }
