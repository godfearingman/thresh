#include "reg_dce.hpp"

namespace {
// return a mask of the register which shows what segment of the register it's
// using, helps us know what part of a register is dead or live.
std::uint64_t mask_of(vtil::register_desc reg) {
  return (reg.bit_count == 64 ? ~0ull : (1ull << reg.bit_count) - 1)
         << reg.bit_offset;
}

struct live_set {
  // we store the weakened version of ther register so that we can keep any
  // entry of any register to 1. this includes any bit count reference to that
  // register, this way we can see which part of the register is dead.
  std::unordered_map<vtil::register_desc::weak_id, std::uint64_t> reg_map = {};

  // sometimes we just need to quickly assume every other register is live, like
  // when we encounter a call or an exit.
  bool rest = false;

  std::uint64_t get(vtil::register_desc::weak_id id) const {
    auto it = reg_map.find(id);
    if (it != reg_map.end())
      return it->second;

    // if we didn't find the entry we should return 0 but if the rest flag is on
    // which is toggled by everything() then we should just fill it all with 1's
    // indicating the entire register is live.
    return rest ? ~0ull : 0;
  }

  void add(const vtil::register_desc &reg) {
    vtil::register_desc::weak_id id = reg.weaken();

    auto it = reg_map.find(id);
    // if we don't have a slot for this reg and we want to store every part of a
    // reg we'll just store it fully as live, else we'll just store what was
    // referenced.
    if (it == reg_map.end())
      reg_map[id] = rest ? ~0ull : mask_of(reg);
    else
      it->second |= mask_of(reg);
  }

  void remove(const vtil::register_desc &reg) {
    vtil::register_desc::weak_id id = reg.weaken();

    auto it = reg_map.find(id);
    if (it != reg_map.end())
      reg_map[id] &= ~mask_of(reg); // remove only what was referenced
    else if (rest)                  // keep everything but what was referenced
      reg_map[id] = ~mask_of(reg);
  }

  void all() {
    reg_map.clear();
    rest = true;
  }

  live_set without_local() const {
    live_set out;
    out.rest = rest;

    for (const auto [reg, bits] : reg_map)
      if (!(reg.flags & vtil::register_local))
        out.reg_map[reg] = bits;

    return out;
  }

  live_set merge(const live_set &o) const {
    live_set out;
    out.rest = rest | o.rest;

    for (const auto &[reg, bits] : reg_map) {
      std::uint64_t val = bits | o.get(reg);
      // no point in adding a value if it's nothing or if rest covers it, we're
      // only adding values that show a change
      if (val != (out.rest ? ~0ull : 0))
        out.reg_map[reg] = val;
    }

    for (const auto &[reg, bits] : o.reg_map) {
      std::uint64_t val = bits | get(reg);
      if (val != (out.rest ? ~0ull : 0))
        out.reg_map[reg] = val;
    }

    return out;
  }

  bool operator==(const live_set &o) const {
    if (reg_map.size() != o.reg_map.size())
      return false;
    else if (rest != o.rest)
      return false;

    for (const auto &[reg, bits] : reg_map) {
      auto it = o.reg_map.find(reg);
      if (it == o.reg_map.end())
        return false;

      if (bits != it->second)
        return false;
    }
    return true;
  }
};

bool removeable(const vtil::instruction &instr) {
  // list of what not to optimise away in our dce; anything that branches,
  // writes memory, is volatile, has at least one register operand, does not
  // touch sp
  auto *desc = instr.base;
  if (desc->is_branching() || instr.is_volatile() || desc->memory_write)
    return false;

  std::size_t reg_count = 0;
  for (std::size_t idx = 0; idx < desc->operand_count(); ++idx) {
    const vtil::operand_type &t = desc->operand_types[idx];
    const vtil::operand &op = instr.operands[idx];

    if (t == vtil::operand_type::read)
      continue;

    if (t >= vtil::operand_type::write) {
      const auto &reg = op.reg();
      if (reg.is_volatile() || reg.is_stack_pointer())
        return false;

      ++reg_count;
    }
  }

  if (!reg_count)
    return false;

  return true;
}

// now that we have our helper function that will reject any non removeable
// instruction, we need another function which tells us what to do when we
// encounter one of these.
bool step(const vtil::instruction &instr, live_set &t) {
  auto *base = instr.base;

  // if it's volatile or the instruction is any of these, capture all registers
  if (base == &vtil::ins::vexit || base == &vtil::ins::vxcall ||
      instr.is_volatile()) {
    t.all();
    return true;
  }

  if (!removeable(instr)) {
    for (const auto &[op, _] : instr.enum_operands()) {
      if (!op.is_register())
        continue;
      t.add(op.reg());
    }
    return true;
  } else {
    for (const auto &[op, type] : instr.enum_operands()) {

      // first check if it's a register that's written to
      if (type >= vtil::operand_type::write) {

        // can't write to anything but a register so we don't need to do any
        // checks here.
        auto reg = op.reg();
        auto id = reg.weaken();
        const std::uint64_t bits = t.get(id);
        const std::uint64_t mask = mask_of(reg);

        // already dead so just return false so that it can be removed
        if (!(bits & mask))
          return false;
        else {
          // at this point we need to check if it's a plain write or a
          // readwrite, this is because if it were a write then it should be
          // treated as dead on next encounter, if it's a readwrite then it's
          // essentially being immediately read after writing which would be the
          // case if it were split up. tldr; treat readwrite's as still live
          type == vtil::operand_type::readwrite ? t.add(reg) : t.remove(reg);
          continue;
        }
      } else {
        // unlike with write where it can only write to registers, with read we
        // can read either imm's or memory as well as registers. we need to
        // specifically catch any reads but only target operands who are
        // registers because the way the IL is stored doesn't build it from or
        // operations but rather as strict enum values. cases like mov's source
        // accepts stricyl read/read_any. this just means we'll need to do a
        // check to see if we're actually dealing with a register or not.

        if (!op.is_register())
          continue;

        auto reg = op.reg();
        auto id = reg.weaken();
        const std::uint64_t bits = t.get(id);
        const std::uint64_t mask = mask_of(reg);

        t.add(reg);
        continue;
      }
    }
  }

  return true;
}

// merge each set from each successor into its predecessor, something like
// set(A) = merge(set(B), set(C)) where B & C are A's successors, since our pass
// will work backwards, A needs to inherit each successors set and so on and so
// forth.
live_set
live_out(vtil::basic_block *block,
         const std::unordered_map<vtil::basic_block *, live_set> &seen) {
  live_set out;

  // if there is no successor we can clearly tell that this is going to be a
  // vexit or something we couldn't lift so we'll treat it as that it requires
  // all.
  const auto &succs = block->next;

  if (!succs.size()) {
    out.all();
    return out;
  }

  // if we haven't encountered its successors yet there's no state to give back
  // or merge so we just return nothing, else store its end set
  for (auto *succ : succs) {
    auto it = seen.find(succ);
    if (it == seen.end())
      return out;

    out = out.merge(it->second.without_local());
  }

  return out;
}

} // namespace

namespace vtil::passes {
std::size_t reg_dce(vtil::routine *rtn) {
  std::size_t result = 0;
  std::unordered_map<vtil::basic_block *, live_set> seen = {};
  std::deque<vtil::basic_block *> work = {};
  std::unordered_set<vtil::basic_block *> waiting = {};

  // insert all blocks in no particular order, the first pass will include sets
  // into every block and most will be guessed but re-filled later.
  for (const auto &[_, block] : rtn->explored_blocks) {
    work.push_back(block.get());
    waiting.insert(block.get());
  }

  while (!work.empty()) {
    auto *block = work.back();
    work.pop_back();
    waiting.erase(block);

    auto out = live_out(block, seen);
    // out is currently the end of the block, we need to walk up through the
    // block to the top and then store the set once it's filled with everything
    // we need or don't
    if (!block->empty()) {
      auto [rbegin, rend] = reverse_iterators(*block);
      for (auto it = rbegin; it != rend; ++it)
        step(*it, out);
    }

    for (auto *pred : block->prev) {
      auto it = seen.find(block);
      // so we don't have trouble on loops, store the predecessor only if the
      // set has changed or if it's on its first visit and it's not queue'd
      // already.
      if ((it == seen.end() || !(it->second == out)) &&
          waiting.insert(pred).second)
        work.push_back(pred);
    }

    seen[block] = std::move(out);
  }

  // we should now have collected each completed set for each block, merged when
  // needed, now we need to work backwards through each blocks instructions and
  // see if anything was removed or not
  for (auto &[block, _] : seen) {
    if (block->empty())
      continue;

    std::vector<vtil::il_iterator> dead_it = {};
    auto out = live_out(block, seen);

    auto [rbegin, rend] = reverse_iterators(*block);
    for (auto it = rbegin; it != rend; ++it) {
      bool remove = step(*it, out);
      if (remove) // instruction is not dead, keep it
        continue;

      dead_it.push_back(it.revert());
      ++result;
    }

    for (auto &it : dead_it)
      block->erase(it);
  }

  if (result)
    spdlog::info("[passes] removed {} dead code targeting registers", result);

  return result;
}
} // namespace vtil::passes
