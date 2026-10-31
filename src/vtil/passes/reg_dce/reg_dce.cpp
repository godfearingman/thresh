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

} // namespace
