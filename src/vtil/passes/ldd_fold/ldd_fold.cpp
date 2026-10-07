#include "ldd_fold.hpp"

// trace register values within a block local to try and see if they're
// originaly stack values. cheaper tracing.
static bool reads_stack(pe_aware_tracer &tr, vtil::il_iterator it) {
  if (it->operands[1].reg().is_stack_pointer())
    return true;
  bool found = false;
  tr.trace(vtil::symbolic::variable{it, it->operands[1].reg()})
      ->enumerate([&found](const vtil::symbolic::expression &e) {
        if (e.is_variable()) {
          const auto &v = e.uid.get<vtil::symbolic::variable>();
          if (v.is_register() && v.reg().is_stack_pointer())
            found = true;
        }
      });
  return found;
}

std::size_t
vtil::passes::fold_ldd(const std::vector<vtil::basic_block *> &blocks,
                       pe_aware_tracer &tr) {
  std::size_t resolved = 0;

  for (const auto &block : blocks) {

    for (auto it = block->begin(); it != block->end(); ++it) {
      if (it->base != &vtil::ins::ldd)
        continue;

      bounded_tracer bt{tr.pe, 128};

      auto dst = it->operands[0];
      auto var = vtil::symbolic::variable{std::next(it), dst.reg()};
      auto expr =
          reads_stack(tr, it) ? bt.rtrace(var).simplify() : bt.trace(var);
      if (!expr->is_constant())
        continue;

      (+it)->base = &vtil::ins::mov;
      (+it)->operands = {
          dst, vtil::operand{*expr->get<std::uint64_t>(), dst.bit_count()}};

      tr.flush(block);
      ++resolved;
    }
  }

  return resolved;
}
