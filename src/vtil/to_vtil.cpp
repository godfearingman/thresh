#include "to_vtil.hpp"
static void fill_block(vtil::routine *rtn, const basic_block &cfg_block,
                       vtil::basic_block *vtil_block,
                       std::uint32_t bytecode_vip) {

  auto vip = [bytecode_vip](std::uint32_t rva) {
    return vtil::to_vip({.rva = rva, .bytecode_vip = bytecode_vip});
  };
  auto has = [&](std::uint32_t rva) {
    return rtn->explored_blocks.count(vip(rva)) != 0;
  };

  if (cfg_block.instrs.empty()) {
    vtil_block->vexit(0);
    return;
  }

  std::size_t new_count = cfg_block.instrs.size();
  if (cfg_block.term != block_terminator::fall_through &&
      cfg_block.term != block_terminator::unk &&
      cfg_block.term != block_terminator::ret &&
      cfg_block.term != block_terminator::call &&
      cfg_block.term != block_terminator::indirect_jmp)
    new_count -= 1;

  for (std::size_t idx = 0; idx < new_count; idx++) {
    const auto &id = cfg_block.instrs[idx];
    vtil::lift_instr(vtil_block, id.rva, id.instr, id.operands.data(),
                     id.bytes.data());
  }

  const auto &succ = cfg_block.successors;

  switch (cfg_block.term) {
  case block_terminator::jmp:
  case block_terminator::tail_call:
  case block_terminator::call:
  case block_terminator::fall_through:
    if (succ.empty() || !has(succ[0])) {
      vtil_block->vexit(0);
      break;
    }
    vtil_block->jmp(vip(succ[0]));
    vtil_block->fork(vip(succ[0]));
    break;

  case block_terminator::jcc: {
    if (succ.size() < 2 || !has(succ[0]) || !has(succ[1])) {
      vtil_block->vexit(0);
      break;
    }
    auto cond =
        vtil::jcc_condition(vtil_block, cfg_block.instrs.back().instr.mnemonic);
    vtil_block->js(cond, vip(succ[0]), vip(succ[1]));
    vtil_block->fork(vip(succ[0]));
    vtil_block->fork(vip(succ[1]));
    break;
  }
  case block_terminator::indirect_jmp:
  case block_terminator::ret:
    if (vtil_block->empty() || !vtil_block->back().base->is_branching())
      vtil_block->vexit(0);
    break;
  case block_terminator::unk:
  default:
    vtil_block->vexit(0);
    break;
  }
}

std::size_t vtil::lift_pending(vtil::routine *rtn, cfg_fn &cfg,
                               std::uint32_t root, std::uint32_t bytecode_vip) {
  const auto &blocks = cfg.get_blocks();

  std::vector<std::uint32_t> fresh;
  std::vector<std::uint32_t> work{root};

  while (!work.empty()) {
    auto rva = work.back();
    work.pop_back();

    const auto key = vtil::to_vip({.rva = rva, .bytecode_vip = bytecode_vip});

    if (!blocks.count(rva) || cfg.is_lifted(key))
      continue;

    cfg.mark_lifted(key);
    if (!rtn->explored_blocks.count(key))
      rtn->create_block(key);

    fresh.push_back(rva);

    for (auto s : blocks.at(rva).successors)
      work.push_back(s);
  }

  for (auto rva : fresh) {
    fill_block(
        rtn, blocks.at(rva),
        rtn->explored_blocks[vtil::to_vip(
                                 {.rva = rva, .bytecode_vip = bytecode_vip})]
            .get(),
        bytecode_vip);
  }

  spdlog::info("lift_pending: +{} blocks ({} total)", fresh.size(),
               rtn->explored_blocks.size());
  return fresh.size();
}

vtil::routine *vtil::to_vtil(cfg_fn &cfg) {
  vtil::block_key bk = {.rva = cfg.get_fn_info().fn_rva, .bytecode_vip = 0};
  auto *entry = vtil::basic_block::begin(vtil::to_vip(bk));
  lift_pending(entry->owner, cfg, bk.rva, bk.bytecode_vip);
  return entry->owner;
}
