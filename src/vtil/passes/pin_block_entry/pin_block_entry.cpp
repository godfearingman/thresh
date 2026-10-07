#include "pin_block_entry.hpp"

// this part is going to attempt to store any stack values whether they're
// constants or stack addresses - as long as they're known by the end of the
// predecessor block, handler blocks may reference values stored on the stack
// and our current pinning functions don't account for that, that's what we'll
// do here now.
struct slot {
  std::uint64_t value;
  bitcnt_t bits;
  bool sp_relative;
};

static std::map<std::int64_t, slot> known_slots(vtil::basic_block *pred,
                                                pe_aware_tracer &tr) {
  std::map<std::int64_t, slot> slots = {};
  auto sp0 = tr.trace(vtil::symbolic::variable{pred->begin(), vtil::REG_SP})
                 .simplify();

  auto kill = [&slots](std::int64_t lo, std::int64_t hi) {
    // make sure no stack stores overlap, otherwise erase old value and
    // overwrite wih new value.
    for (auto e = slots.begin(); e != slots.end();) {
      auto elo = e->first;
      auto ehi = e->first + e->second.bits / 8;
      if (elo < hi && lo < ehi)
        e = slots.erase(e);
      else
        ++e;
    }
  };

  for (auto it = pred->begin(); it != pred->end(); ++it) {
    if (it->base != &vtil::ins::str)
      continue;

    const auto &base = it->operands[0];
    const auto &imm = it->operands[1];
    const auto &val = it->operands[2];
    auto ptr =
        tr.trace(vtil::symbolic::variable{it, base.reg()}) + imm.imm().i64;
    auto rel = (ptr - sp0).simplify();

    if (!rel.is_constant()) {
      slots.clear();
      continue;
    }

    std::int64_t lo = *rel.get<std::int64_t>();
    bitcnt_t bits = val.bit_count();
    kill(lo, lo + bits / 8);

    slot entry{0, 0, false};

    if (!val.is_immediate()) {
      auto expr = tr.trace(vtil::symbolic::variable{it, val.reg()}).simplify();
      if (expr->is_constant())
        entry = {*expr->get<std::uint64_t>(), bits, false};
      else if (bits == 64) {
        // this is potentially going to be an address so let's store this as a
        // sp relative slot
        auto d = (expr - sp0).simplify();
        if (d.is_constant())
          entry = {*d.get<std::uint64_t>(), bits, true};
      }
    } else
      entry = {val.imm().u64, bits, false};

    if (entry.bits != 0)
      slots[lo] = entry;
  }

  // from here we're going to need to rebase the sp before returning since
  // everything is just relative to the sp at the start of the block
  auto last = std::prev(pred->end());
  auto delta = ((tr.trace(vtil::symbolic::variable{last, vtil::REG_SP}) +
                 last->sp_offset) -
                sp0)
                   .simplify();
  if (!delta.is_constant())
    return {};

  std::map<std::int64_t, slot> rebased;
  for (auto &[off, sl] : slots) {
    auto s = sl;
    // sp relative values need to get their value shifted by the delta as well
    // so that it remains relative to sp calculations
    if (s.sp_relative)
      s.value -= *delta.get<std::int64_t>();
    rebased[off - *delta.get<std::int64_t>()] = s;
  }
  return rebased;
}

// previously, we pinned needed vm values at the start of every handler. this is
// fine for the beginning but handlers split up into multiple blocks handled by
// its internal jmps, those pinned values don't really help anymore because the
// symbolic engine can't prove that something like str[r8-8] doesnt hit the slot
// it's following if r8 is unknown. what we'll need to do is start pinning gpr's
// within every block lifted. this will help the sym eng know how to handle
// values it previously couldn't resolve. solution? pin every gpr - rsp whose
// value is traceable to a constant or $sp + d to every block with a single
// predecessor.
std::size_t
vtil::passes::pin_block_entry(const std::vector<vtil::basic_block *> &blocks,
                              pe_aware_tracer &tr) {
  std::size_t result = 0;

  static std::vector<ZydisRegister> regs = {
      ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RCX,
      ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
      ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,
      ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
      ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15};

  for (const auto &block : blocks) {
    // make sure it has one pred
    if (block->prev.size() != 1 || block->prev[0]->empty())
      continue;

    // trace point should start at the final instruction which is going to be
    // the jmp and trace the sp (factoring in sp offset)
    auto it = std::prev(block->prev[0]->end());
    auto sp =
        (tr.trace(vtil::symbolic::variable{it, vtil::REG_SP}) + it->sp_offset)
            .simplify();

    std::vector<vtil::instruction> pins;
    for (const auto &reg : regs) {
      auto v_reg = vtil::zydis_to_vtil_reg(reg);
      auto var = vtil::symbolic::variable{it, v_reg.reg()};
      auto expr = tr.trace(var).simplify();

      if (!expr->is_constant()) {
        auto off = (expr - sp).simplify();
        if (off.is_constant()) {
          auto raw_off = off.get<std::int64_t>();
          pins.emplace_back(
              vtil::instruction{&vtil::ins::mov, {v_reg, vtil::REG_SP}});
          pins.emplace_back(vtil::instruction{
              &vtil::ins::add, {v_reg, vtil::operand{*raw_off, 64}}});
          continue;
        }

        expr = bounded_tracer{tr.pe, 128}.rtrace(var).simplify();
        if (!expr->is_constant())
          continue;
      }

      auto val = expr->get<std::uint64_t>();
      pins.emplace_back(
          vtil::instruction{&vtil::ins::mov, {v_reg, vtil::operand{*val, 64}}});
    }

    // tie in stack slots pinning.
    for (auto &[off, sl] : known_slots(block->prev[0], tr)) {
      if (!sl.sp_relative) {
        pins.push_back(
            vtil::instruction{&vtil::ins::str,
                              {vtil::REG_SP, vtil::make_imm<std::int64_t>(off),
                               vtil::operand{sl.value, sl.bits}}});
        continue;
      }
      auto t = block->tmp(64);
      pins.push_back(vtil::instruction{&vtil::ins::mov, {t, vtil::REG_SP}});
      pins.push_back(vtil::instruction{
          &vtil::ins::add,
          {t,
           vtil::make_imm<std::int64_t>(static_cast<std::int64_t>(sl.value))}});
      pins.push_back(vtil::instruction(
          &vtil::ins::str,
          {vtil::REG_SP, vtil::make_imm<std::int64_t>(off), t}));
    }

    if (pins.empty())
      continue;

    // write each instruction to the block now and clean it up in the tracer.
    for (auto pin = pins.rbegin(); pin != pins.rend(); ++pin)
      block->insert(block->begin(), std::move(*pin));

    tr.flush(block);
    ++result;
  }

  return result;
}
