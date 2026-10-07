#include "fold_tamper_fork.hpp"

namespace {
// a trap arm is a single leaf block that exits through a computed target that
// never exists as mappable memory within the image, in spirits of a
// devirtualiser we should identify it and then remove it from existing as it
// shouldn't appear in native code when recompiling.
bool is_trap_arm(vtil::basic_block *arm, pe_aware_tracer &tr, const Pe &pe) {
  // if there is a successor or if thsi block is empty or if there is more than
  // one predecessor then it cannot be the block we're looking for.
  if (!arm->next.empty() || arm->empty() || arm->prev.size() != 1)
    return false;

  // we replace computed jmps with vexit so vtil can treat it as a finished
  // block.
  const auto &exit = arm->back();
  if (exit.base != &vtil::ins::vexit)
    return false;

  // constant targets are a real exit
  const auto &op = exit.operands[0];
  if (!op.is_register())
    return false;

  auto targ =
      tr.trace(vtil::symbolic::variable{std::prev(arm->end()), op.reg()})
          .simplify();
  // check if it's a return, if it is then this is not a trap block
  if (vtil::forward::is_return(targ))
    return false;

  return vtil::forward::never_in_image(targ, pe);
}

void unlink(vtil::basic_block *a, vtil::basic_block *b) {
  std::erase(a->next, b);
  std::erase(b->prev, a);
}
} // namespace

std::size_t vtil::passes::fold_tamper_forks(vtil::routine *rtn,
                                            pe_aware_tracer &tr, const Pe &pe) {
  std::size_t result = 0;
  std::vector<vtil::basic_block *> candidates = {};

  for (const auto &[_, block] : rtn->explored_blocks)
    if (!block->empty() && block->back().base == &vtil::ins::js &&
        block->next.size() == 2)
      candidates.push_back(block.get());

  for (auto *cand : candidates) {
    bool trap[2] = {is_trap_arm(cand->next[0], tr, pe),
                    is_trap_arm(cand->next[1], tr, pe)};

    if (trap[0] == trap[1]) {
      if (trap[0])
        spdlog::warn("[passes] both arms of {:x} are trap, not folding either "
                     "and continuing.",
                     cand->entry_vip);
      continue;
    }

    vtil::basic_block *dead = cand->next[trap[0] ? 0 : 1];
    vtil::basic_block *live = cand->next[trap[0] ? 1 : 0];

    spdlog::info("[passes] folding dead branch {:x} ({} instrs), keeping {:x} "
                 "({} instrs)",
                 dead->entry_vip, dead->size(), live->entry_vip, live->size());

    tr.flush(cand);
    tr.flush(dead);
    tr.flush(live);

    cand->pop_back();
    cand->jmp(live->entry_vip);

    unlink(cand, dead);
    unlink(cand, live);

    cand->next.push_back(live);
    live->prev.push_back(cand);

    rtn->delete_block(dead);
    ++result;
  }

  if (result)
    spdlog::info("[passes] folded {} tamper forks", result);

  return result;
}
