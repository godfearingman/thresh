#include "collapse_stack_check.hpp"

static std::vector<vtil::basic_block *> get_canditates(vtil::routine *rtn) {
  std::vector<vtil::basic_block *> canditates = {};
  // iterate over every explored block and look for any that have exactly 2
  // successors, this is because the stack check is a js.
  for (const auto &[vip, block] : rtn->explored_blocks) {
    if (block->back().base != &vtil::ins::js)
      continue;
    if (block->next.size() != 2)
      continue;
    canditates.push_back(block.get());
  }
  return canditates;
}

static bool has_movsb(const cfg_fn &cfg, vtil::basic_block *blk) {
  // iterate over every instruction and see if it has the rep attrib. we'll need
  // to do this over the raw basic block and not within vtil IL.
  const auto &blocks = cfg.get_blocks();
  std::uint32_t rva = vtil::from_vip(blk->entry_vip).rva;
  if (!rva) {
    spdlog::warn("[passes] no rva for block {:x}", blk->entry_vip);
    return false;
  }

  auto it = blocks.find(rva);
  if (it == blocks.end()) {
    spdlog::warn("[passes] cannot find movsb in block outside of cfg");
    return false;
  }

  for (const auto &id : it->second.instrs) {
    if (!(id.instr.attributes & ZYDIS_ATTRIB_HAS_REP) &&
        id.instr.mnemonic != ZYDIS_MNEMONIC_MOVSB)
      continue;
    spdlog::info("[passes] found rep movsb at {:x}", id.rva);
    return true;
  }
  return false;
}

static std::vector<vtil::basic_block *> walk_arm(vtil::basic_block *start,
                                                 vtil::basic_block *join) {
  // walk every basic block within the reloc to see the full path of what to
  // delete when we overwrite the js
  std::vector<vtil::basic_block *> path;

  vtil::basic_block *curr = start;
  for (std::int32_t idx = 0; idx < 8; ++idx) {
    if (curr == join)
      return path;
    if (curr->next.size() != 1 || curr->prev.size() != 1)
      return {};
    path.push_back(curr);
    curr = curr->next[0];
  }

  return {};
}

static void unlink(vtil::basic_block *a, vtil::basic_block *b) {
  std::erase(a->next, b);
  std::erase(b->prev, a);
}

std::size_t vtil::passes::collapse_stack_checks(vtil::routine *rtn,
                                                const cfg_fn &cfg,
                                                pe_aware_tracer &tr) {
  std::size_t result = 0;
  const auto &candidates = get_canditates(rtn);

  for (const auto &cand : candidates) {
    for (std::int32_t side = 0; side < 2; ++side) {
      auto *join = cand->next[1 - side];
      auto path = walk_arm(cand->next[side], join);
      if (path.empty())
        continue;
      if (std::none_of(path.begin(), path.end(), [&cfg](vtil::basic_block *b) {
            return has_movsb(cfg, b);
          }))
        continue;

      // maintain a clean cache for these entries
      tr.flush(join);
      tr.flush(cand);
      for (auto *b : path)
        tr.flush(b);

      // drop js and turn into unconditional branch straight to dispatch
      cand->pop_back();
      cand->jmp(join->entry_vip);

      // unlink all old blocks that followed reloc
      unlink(cand, path.front());
      for (std::int32_t idx = 0; idx + 1 < path.size(); ++idx)
        unlink(path[idx], path[idx + 1]);

      unlink(path.back(), join);

      // delete said blocks.
      for (auto *b : path)
        rtn->delete_block(b);

      ++result;
      break;
    }
  }

  if (result)
    spdlog::info("[passses] found {} stack check branches, removed all",
                 result);

  return result;
}
