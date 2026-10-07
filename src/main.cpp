#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <functional>
#include <string>

#include "cfg/cfg.hpp"
#include "pdb/pdb.hpp"
#include "pe/pe.hpp"
#include "vtil/to_vtil.hpp"

#include "vtil/passes/chain_sections/chain_sections.hpp"
#include "vtil/passes/collapse_stack_check/collapse_stack_check.hpp"
#include "vtil/passes/dead_stack/dead_stack.hpp"
#include "vtil/passes/fold_redundant_fork/fold_redundant_fork.hpp"
#include "vtil/passes/fold_stack_align/fold_stack_align.hpp"
#include "vtil/passes/fold_tamper_fork/fold_tamper_fork.hpp"
#include "vtil/passes/indirect_jmp/indirect_jmp.hpp"
#include "vtil/passes/mark_exits/mark_exits.hpp"

#include "vtil/forward/forward.hpp"
#include "vtil/forward/report/report.hpp"

#include "spdlog/spdlog.h"

#undef min
int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::string pdb_path =
      "C:\\Users\\sohai\\source\\repos\\obf\\build\\Release\\tests\\virt\\test."
      "pdb";
  std::string file_path =
      "C:\\Users\\sohai\\source\\repos\\obf\\build\\Release\\tests\\virt\\test."
      "dll";
  pdb::pdb_parser pdb(pdb_path);

  auto fns = pdb.get_fns();

  if (!fns.has_value()) {
    spdlog::error(" failed to get functions with error {}",
                  fns.error().c_str());
    std::getchar();
    return 0;
  }

  auto file_bytes = pdb.get_file_info(file_path);
  if (!file_bytes.has_value()) {
    spdlog::error(" failed to get file info with error {}",
                  file_bytes.error().c_str());
    std::getchar();
    return 0;
  }

  const Pe *pe = new Pe(*file_bytes, "main image");
  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  auto run_test = [&](const char *name) {
    auto fit = std::find_if((*fns).begin(), (*fns).end(), [&](const auto &fn) {
      return fn.fn_name.contains(name);
    });
    if (fit == (*fns).end()) {
      spdlog::error("{} not found", name);
      return;
    }

    cfg_fn tcfg(*fit, *pe, decoder);
    tcfg.build_blocks();
    auto *trtn = vtil::to_vtil(tcfg);
    std::unordered_set<vtil::vip_t> cleaned;
    std::unordered_set<std::uint32_t> exit_vips;

    vtil::optimizer::apply_all(trtn);

    int iter = 0;
    pe_aware_tracer tr{*pe};
    vtil::forward::states fs;
    fs.entries.insert(trtn->entry_point);

    vtil::passes::fold_stack_align(trtn, tr);
    trtn->entry_point->insert(
        trtn->entry_point->begin(),
        vtil::instruction{&vtil::ins::band,
                          {vtil::REG_FLAGS, vtil::operand{~0x100ull, 64}}});
    while (true) {
      while (true) {
        std::vector<vtil::basic_block *> fresh;
        for (auto &[v, b] : trtn->explored_blocks)
          if (cleaned.insert(v).second)
            fresh.push_back(b.get());
        spdlog::info("iter {}: cleaning {} fresh blocks", iter + 1,
                     fresh.size());
        vtil::transform_parallel(fresh, [](vtil::basic_block *blk) {
          vtil::optimizer::stack_pinning_pass{}.pass(blk, false);
          vtil::optimizer::istack_ref_substitution_pass{}.pass(blk, false);
          vtil::optimizer::stack_propagation_pass{}.pass(blk, false);
          vtil::optimizer::mov_propagation_pass{}.pass(blk, false);
          vtil::optimizer::dead_code_elimination_pass{}.pass(blk, false);
        });
        for (auto *b : fresh)
          tr.flush(b);

        std::vector<vtil::basic_block *> ordered;
        std::unordered_set<vtil::basic_block *> pending(fresh.begin(),
                                                        fresh.end());
        for (auto *b : fs.dirty)
          pending.insert(const_cast<vtil::basic_block *>(b));

        std::function<void(vtil::basic_block *)> visit =
            [&](vtil::basic_block *b) {
              if (!pending.erase(b))
                return;

              for (auto *p : b->prev)
                visit(p);
              ordered.push_back(b);
            };

        for (auto *b : fresh)
          visit(b);
        for (auto *b : fs.dirty)
          visit(const_cast<vtil::basic_block *>(b));

        fs.dirty.clear();

        vtil::passes::fold_stack_align(trtn, tr);
        std::size_t folded = vtil::forward::run(ordered, fs, *pe);

        for (auto *b : ordered)
          tr.flush(b);

        auto resolved =
            vtil::passes::resolve_indirects(trtn, tcfg, *pe, tr, exit_vips, fs);
        vtil::passes::collapse_stack_checks(trtn, tcfg, tr);
        spdlog::info("iter {}: optimising {} blocks", ++iter,
                     trtn->explored_blocks.size());
        spdlog::info("iter {}: done", iter);
        if (!resolved && !folded && fs.dirty.empty()) {
          spdlog::info("finished passes on iter {}", iter);
          break;
        }
      }
      tr.flush();
      if (!vtil::passes::chain_sections(trtn, tcfg, *pe, tr, fs))
        break;
    }

    vtil::forward::report(trtn, fs, *pe);
    vtil::passes::mark_exits(trtn);

    auto count = [&] {
      std::size_t n = 0;
      for (const auto &[v, b] : trtn->explored_blocks)
        n += b->size();
      return n;
    };

    // how much obfuscated code we chewed through vs what it reduced to. note
    // that native is counted once per rva while the vm handlers get lifted
    // again for every vip, which is why lifted is so much larger.
    std::size_t native = 0;
    for (const auto &[rva, b] : tcfg.get_blocks())
      native += b.instrs.size();
    std::size_t lifted = count();

    vtil::optimizer::apply_all_profiled(trtn);
    vtil::passes::fold_tamper_forks(trtn, tr, *pe);
    vtil::passes::dead_stack_removal(trtn, tr);
    vtil::passes::fold_redundant_forks(trtn, tr);

    spdlog::info("[result] {} native instrs -> {} il lifted -> {} il final",
                 native, lifted, count());

    vtil::debug::dump(trtn);
    vtil::print_unhandled();
  };

  run_test("GetVer_0");
  std::getchar();
  return 0;
}
