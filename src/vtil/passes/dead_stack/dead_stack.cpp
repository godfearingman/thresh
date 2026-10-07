#include "dead_stack.hpp"

namespace {
enum class ptr_kind { stack, non_stack, unresolved };
ptr_kind classify_ptr(vtil::il_const_iterator it, pe_aware_tracer &tr,
                      std::int64_t base,
                      const vtil::symbolic::expression::reference &sp0,
                      std::int64_t &slot) {
  auto [mb, mo] = it->memory_location();

  if (mb.is_stack_pointer())
    slot = base + mo;
  else {

    bool has_sp = false;
    auto expr = tr.rtrace_p(vtil::symbolic::variable{it, mb}).simplify();

    expr->enumerate([&has_sp](const vtil::symbolic::expression &x) {
      if (!x.is_variable())
        return;
      const auto &v = x.uid.get<vtil::symbolic::variable>();

      if (v.is_register() && v.reg().is_stack_pointer())
        has_sp = true;
    });

    auto new_expr = (expr - sp0).simplify();
    if (new_expr.is_constant())
      slot = *new_expr.get<std::int64_t>() + mo;
    else if (expr->is_constant())
      return ptr_kind::non_stack;
    else if (!has_sp)
      return ptr_kind::non_stack;
    else
      return ptr_kind::unresolved;
  }

  return ptr_kind::stack;
}
} // namespace

std::size_t vtil::passes::dead_stack_removal(vtil::routine *rtn,
                                             pe_aware_tracer &tr) {
  // most of post optimised ir is dominated by stack stores that are never read
  // from anywhere, they cannot be affected by DCE pass because aux::is_used
  // says they should survive because later on something might read from the
  // same memory as it. the problem here is, this is decided purply by flags so
  // any pointer that is not derived from $sp has flags == 0 and because of
  // that, it gets treated as possibly touching the entire frame. what we'll do
  // here to resolve this is - compute the exact set of stack bytes that is
  // actually used within the routine and then drop anything else.

  std::size_t result = 0;

  std::unordered_map<const vtil::basic_block *, std::int64_t> entry_rel;
  // entry relative sp slot is 0
  entry_rel[rtn->entry_point] = 0;

  std::vector<vtil::basic_block *> work{rtn->entry_point};
  auto sp0 = vtil::symbolic::variable{rtn->entry_point->begin(), vtil::REG_SP}
                 .to_expression();

  while (!work.empty()) {

    auto *b = work.back();
    work.pop_back();

    std::int64_t base = entry_rel.at(b);
    std::int64_t v = base + b->sp_offset;

    for (const auto &s : b->next) {
      auto [pos, inserted] = entry_rel.emplace(s, v);
      if (inserted)
        work.push_back(s);
      else if (pos->second != v) {
        spdlog::warn("[passes] sp slot for block {:x} doesn't match",
                     b->entry_vip);
        return 0;
      }
    }
  }

  std::set<std::int64_t> read_bytes;
  for (const auto &[vip, block] : rtn->explored_blocks) {
    auto pos = entry_rel.find(block.get());
    if (pos == entry_rel.end()) {
      spdlog::warn("[passes] failed to find block {:x} in map",
                   block->entry_vip);
      return 0;
    }

    std::int64_t base = pos->second;
    for (auto it = block->begin(); it != block->end(); ++it) {
      if (it->sp_index || it->sp_reset) {
        spdlog::warn(
            "[passes] block {:x} has a sp index {} or sp reset set to {}",
            block->entry_vip, it->sp_index, it->sp_reset ? 1 : 0);
        return 0;
      }

      if (!it->base->reads_memory())
        continue;

      std::int64_t slot = 0;
      switch (classify_ptr(it, tr, base, sp0, slot)) {
      case ptr_kind::stack:
        spdlog::info("[passes] read slot {:+#x} ({} bits) in block {:x}", slot,
                     static_cast<std::int32_t>(it->access_size()),
                     block->entry_vip);
        break;
      case ptr_kind::non_stack:
        spdlog::warn("[passes] non stack instr {}", it->to_string());
        continue;
      case ptr_kind::unresolved:
        spdlog::warn("[passes] failed to resolve instr {}", it->to_string());
        return 0;
      }

      for (std::int64_t idx = 0; idx < it->access_size() / 8; ++idx)
        read_bytes.insert(slot + idx);
    }
  }

  for (const auto &[vip, block] : rtn->explored_blocks) {
    auto pos = entry_rel.find(block.get());
    if (pos == entry_rel.end()) {
      spdlog::warn("[passes] failed to find block {:x} in map",
                   block->entry_vip);
      return 0;
    }

    std::int64_t base = pos->second;
    for (auto it = block->begin(); it != block->end(); ++it) {

      if (!it->base->writes_memory())
        continue;

      std::int64_t slot = 0;
      if (classify_ptr(it, tr, base, sp0, slot) != ptr_kind::stack)
        continue;

      bool dead = true;
      for (std::int64_t idx = 0; idx < it->access_size() / 8 && dead; ++idx)
        if (read_bytes.count(slot + idx))
          dead = false;

      if (!dead)
        continue;
      (+it)->base = &vtil::ins::nop;
      (+it)->operands = {};
      ++result;
    }
  }

  spdlog::info("[passes] nopped {} dead stack stores", result);

  for (std::int32_t round = 0; round < 3; ++round) {
    vtil::optimizer::dead_code_elimination_pass{}(rtn);
    vtil::optimizer::mov_propagation_pass{}(rtn);
    vtil::optimizer::dead_code_elimination_pass{}(rtn);
  }

  return result;
}
