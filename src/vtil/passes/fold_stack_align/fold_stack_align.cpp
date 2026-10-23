#include "fold_stack_align.hpp"

std::size_t vtil::passes::fold_stack_align(vtil::routine *rtn,
                                           pe_aware_tracer &tr,
                                           vtil::forward::states &fs,
                                           const Pe &pe) {
  std::size_t result = 0;
  // once we enter a function, we need to make sure there are no stack alignment
  // instructiosn going on so that vtil can continue treating sp as a linear
  // expression.

  // before we used to tie the sp to the start of a function but now that we've
  // got our state tracker we can just leave it unbound to the block because
  // that's what our vm state starts with anyway
  auto sp0 = vtil::symbolic::variable{vtil::REG_SP}.to_expression();

  for (auto &[vip, block] : rtn->explored_blocks) {
    const auto rva = vtil::from_vip(vip).rva;
    for (auto it = block->begin(); it != block->end(); ++it) {
      // check every instruction and try to match and reg, c
      if (it->base != &vtil::ins::band || !it->operands[0].is_register() ||
          !it->operands[1].is_immediate() || it->operands[1].imm().i64 != -0x10)
        continue;
      spdlog::info("[passes] found stack alignment instruction within rva {:x}",
                   rva);

      // use our forward state machine to find the value of the first operand in
      // the and instruction before the instruction is actually executed
      auto val =
          forward::value_before(block.get(), it, it->operands[0].reg(), fs, pe);
      if (!val)
        continue;

      auto c = (val - sp0).simplify();

      // if c comes out as a constant then we can simplify it as we've proven
      // val == entry_rsp + c
      if (c.is_constant()) {
        auto r = (8 + *c.get<std::int64_t>()) & 0xf;
        spdlog::info("[passes] value came back as constant, r = {:x}", r);
        if (r == 0) {
          // if r is 0 then we don't need to do anything because rsp is already
          // 16 byte aligned, replace it with a nop
          (+it)->operands = {};
          (+it)->base = &vtil::ins::nop;
          spdlog::info("[passes] replaced with nop");
        } else {
          // now we need to simplify it into a linear expression
          (+it)->operands[1] = vtil::operand(r, 64);
          (+it)->base = &vtil::ins::sub;
          spdlog::info("[passes] replaced with sub sp, {:x}", r);
        }
      } else {
        spdlog::warn(
            "[passes] failed to trace c back to constant in block {:x}", rva);
        continue;
      }
      result++;
      tr.flush(block.get());
      fs.invalidate(block.get());
    }
  }

  return result;
}
