#include "fold_redundant_fork.hpp"

namespace {
bool is_bare_jmp(vtil::basic_block *arm) {
  return arm->size() == 1 && arm->prev.size() == 1 && arm->next.size() == 1 &&
         arm->back().base == &vtil::ins::jmp;
}
// should probably make this shared at this point, holy shit.
void unlink(vtil::basic_block *a, vtil::basic_block *b) {
  std::erase(a->next, b);
  std::erase(b->prev, a);
}
} // namespace

std::size_t vtil::passes::fold_redundant_forks(vtil::routine *rtn,
                                               pe_aware_tracer &tr) {
  std::size_t result = 0;
  std::vector<vtil::basic_block *> candidates = {};

  for (const auto &[_, block] : rtn->explored_blocks)
    if (!block->empty() && block->back().base == &vtil::ins::js &&
        block->next.size() == 2)
      candidates.push_back(block.get());

  for (auto *cand : candidates) {
    auto *a = cand->next[0];
    auto *b = cand->next[1];

    if (a == b || !is_bare_jmp(a) || !is_bare_jmp(b) ||
        a->next[0] != b->next[0])
      continue;

    auto *join = a->next[0];
    spdlog::info(
        "[passes] folding redundant fork {:x} -> {:x}, dropping {:x} and {:x}",
        cand->entry_vip, join->entry_vip, a->entry_vip, b->entry_vip);

    tr.flush(cand);
    tr.flush(a);
    tr.flush(b);
    tr.flush(join);

    cand->pop_back();
    cand->jmp(join->entry_vip);

    unlink(cand, a);
    unlink(cand, b);
    unlink(a, join);
    unlink(b, join);

    cand->next.push_back(join);
    join->prev.push_back(cand);

    rtn->delete_block(a);
    rtn->delete_block(b);
    ++result;
  }

  if (result) {
    spdlog::info("[passes] folded {} redundant forks", result);
    // the condition the js used is now unreferenced, so let dce take it and
    // whatever only fed it.
    for (std::int32_t round = 0; round < 3; ++round) {
      vtil::optimizer::dead_code_elimination_pass{}(rtn);
      vtil::optimizer::mov_propagation_pass{}(rtn);
      vtil::optimizer::dead_code_elimination_pass{}(rtn);
    }
  }

  return result;
}
