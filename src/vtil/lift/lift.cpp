#include "lift.hpp"
#include "spdlog/spdlog.h"

static std::unordered_map<ZydisMnemonic, std::size_t> unhandled_counts;

static vtil::handler_map_t &get_handlers() {
  static vtil::handler_map_t map = {
      {ZYDIS_MNEMONIC_MOV, vtil_handler::mov},
      {ZYDIS_MNEMONIC_LEA, vtil_handler::lea},
      {ZYDIS_MNEMONIC_ADD, vtil_handler::add},
      {ZYDIS_MNEMONIC_SUB, vtil_handler::sub},
      {ZYDIS_MNEMONIC_AND, vtil_handler::band},
      {ZYDIS_MNEMONIC_XOR, vtil_handler::bxor},
      {ZYDIS_MNEMONIC_OR, vtil_handler::bor},
      {ZYDIS_MNEMONIC_CMP, vtil_handler::cmp},
      {ZYDIS_MNEMONIC_MOVZX, vtil_handler::mov},
      {ZYDIS_MNEMONIC_NOP, vtil_handler::nop},
      {ZYDIS_MNEMONIC_NOT, vtil_handler::_not},
      {ZYDIS_MNEMONIC_TEST, vtil_handler::test},
      {ZYDIS_MNEMONIC_PUSH, vtil_handler::push},
      {ZYDIS_MNEMONIC_POP, vtil_handler::pop},
      {ZYDIS_MNEMONIC_PUSHFQ, vtil_handler::pushfq},
      {ZYDIS_MNEMONIC_POPFQ, vtil_handler::popfq},
      {ZYDIS_MNEMONIC_CLC, vtil_handler::clc},
      {ZYDIS_MNEMONIC_CMC, vtil_handler::cmc},
      {ZYDIS_MNEMONIC_STC, vtil_handler::stc},
      {ZYDIS_MNEMONIC_MOVSX, vtil_handler::movsx},
      {ZYDIS_MNEMONIC_MOVSXD, vtil_handler::movsx},
      {ZYDIS_MNEMONIC_INC, vtil_handler::inc_dec},
      {ZYDIS_MNEMONIC_DEC, vtil_handler::inc_dec},
      {ZYDIS_MNEMONIC_XCHG, vtil_handler::xchg},
      {ZYDIS_MNEMONIC_BT, vtil_handler::bt},
      {ZYDIS_MNEMONIC_BTS, vtil_handler::bt},
      {ZYDIS_MNEMONIC_BTR, vtil_handler::bt},
      {ZYDIS_MNEMONIC_BTC, vtil_handler::bt},
      {ZYDIS_MNEMONIC_BSWAP, vtil_handler::bswap},
      {ZYDIS_MNEMONIC_LAHF, vtil_handler::lahf},
      {ZYDIS_MNEMONIC_ROL, vtil_handler::ro},
      {ZYDIS_MNEMONIC_ROR, vtil_handler::ro},
      {ZYDIS_MNEMONIC_RCL, vtil_handler::rcl},
      {ZYDIS_MNEMONIC_ADC, vtil_handler::adc_sbb},
      {ZYDIS_MNEMONIC_SBB, vtil_handler::adc_sbb},
      {ZYDIS_MNEMONIC_RET, vtil_handler::ret},
      {ZYDIS_MNEMONIC_CALL, vtil_handler::call},
      {ZYDIS_MNEMONIC_SHL, vtil_handler::shl},
      {ZYDIS_MNEMONIC_SHR, vtil_handler::shr},
      {ZYDIS_MNEMONIC_SAR, vtil_handler::sar},
      {ZYDIS_MNEMONIC_SHLD, vtil_handler::shld},
      {ZYDIS_MNEMONIC_SHRD, vtil_handler::shrd},
      {ZYDIS_MNEMONIC_BSF, vtil_handler::bsf},
      {ZYDIS_MNEMONIC_NEG, vtil_handler::neg},
      {ZYDIS_MNEMONIC_JMP, vtil_handler::jmp},
      {ZYDIS_MNEMONIC_RCR, vtil_handler::rcr},
      {ZYDIS_MNEMONIC_XADD, vtil_handler::xadd},
      {ZYDIS_MNEMONIC_CBW, vtil_handler::cbw_cwde_cdqe},
      {ZYDIS_MNEMONIC_CWDE, vtil_handler::cbw_cwde_cdqe},
      {ZYDIS_MNEMONIC_CDQE, vtil_handler::cbw_cwde_cdqe},
      {ZYDIS_MNEMONIC_CWD, vtil_handler::cwd_cdq_cqo},
      {ZYDIS_MNEMONIC_CDQ, vtil_handler::cwd_cdq_cqo},
      {ZYDIS_MNEMONIC_CQO, vtil_handler::cwd_cdq_cqo},
      {ZYDIS_MNEMONIC_BSR, vtil_handler::bsf},
      {ZYDIS_MNEMONIC_CPUID, vtil_handler::cpuid},
      {ZYDIS_MNEMONIC_RDTSC, vtil_handler::rdtsc},

      // setcc garbage
      {ZYDIS_MNEMONIC_SETNBE, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNB, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETB, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETBE, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETZ, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNLE, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNL, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETL, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETLE, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNZ, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNO, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNP, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETNS, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETO, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETP, vtil_handler::setcc},
      {ZYDIS_MNEMONIC_SETS, vtil_handler::setcc},

      // cmovcc garbage
      {ZYDIS_MNEMONIC_CMOVNBE, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNB, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVB, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVBE, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVZ, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNLE, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNL, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVL, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVLE, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNZ, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNO, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNP, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVNS, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVO, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVP, vtil_handler::cmovcc},
      {ZYDIS_MNEMONIC_CMOVS, vtil_handler::cmovcc},
  };
  return map;
}

// VTIL memory operands need a full-width GPR base (and index, if present).
// Anything else trips instruction.cpp:66, so route it to the hint path.
static bool memops_liftable(const ZydisDecodedInstruction &instr,
                            const ZydisDecodedOperand *ops) {
  for (std::int32_t i = 0; i < instr.operand_count_visible; ++i) {
    const auto &op = ops[i];
    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
      continue;

    if (op.mem.base == ZYDIS_REGISTER_NONE &&
        op.mem.index == ZYDIS_REGISTER_NONE)
      return false;
    if (op.mem.base != ZYDIS_REGISTER_NONE &&
        op.mem.base != ZYDIS_REGISTER_RIP &&
        vtil::zydis_to_vtil_reg(op.mem.base).reg().bit_count !=
            vtil::arch::bit_count)
      return false;
    if (op.mem.index != ZYDIS_REGISTER_NONE &&
        vtil::zydis_to_vtil_reg(op.mem.index).reg().bit_count !=
            vtil::arch::bit_count)
      return false;
    if (op.mem.segment == ZYDIS_REGISTER_FS)
      return false; // segment base not modelled
  }
  return true;
}

static void lift_fallback(vtil::basic_block *block,
                          const ZydisDecodedInstruction &instr,
                          const ZydisDecodedOperand *ops,
                          const std::uint8_t *raw_bytes) {
  for (std::int32_t idx = 0; idx < instr.operand_count; idx++) {
    const auto &op = ops[idx];
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER &&
        (op.actions & ZYDIS_OPERAND_ACTION_READ))
      block->vpinr(vtil::zydis_to_vtil_reg(op.reg.value));
    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      if (op.mem.index != ZYDIS_REGISTER_NONE)
        block->vpinr(vtil::zydis_to_vtil_reg(op.mem.index));
      if (op.mem.base != ZYDIS_REGISTER_NONE)
        block->vpinr(vtil::zydis_to_vtil_reg(op.mem.base));
    }
  }

  for (std::int32_t idx = 0; idx < instr.length; idx++)
    block->vemit(raw_bytes[idx]);

  for (std::int32_t idx = 0; idx < instr.operand_count; idx++) {
    const auto &op = ops[idx];
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER &&
        (op.actions & ZYDIS_OPERAND_ACTION_WRITE))
      block->vpinw(vtil::zydis_to_vtil_reg(op.reg.value));
  }

  if (instr.cpu_flags) {
    auto m = instr.cpu_flags->modified;
    if (m & ZYDIS_CPUFLAG_CF)
      block->vpinw(vtil::flags::CF);
    if (m & ZYDIS_CPUFLAG_ZF)
      block->vpinw(vtil::flags::ZF);
    if (m & ZYDIS_CPUFLAG_SF)
      block->vpinw(vtil::flags::SF);
    if (m & ZYDIS_CPUFLAG_OF)
      block->vpinw(vtil::flags::OF);
    if (m & ZYDIS_CPUFLAG_PF)
      block->vpinw(vtil::flags::PF);
    if (m & ZYDIS_CPUFLAG_AF)
      block->vpinw(vtil::flags::AF);
  }

  unhandled_counts[instr.mnemonic]++;
}

void vtil::lift_instr(vtil::basic_block *block, std::uint64_t vip,
                      const ZydisDecodedInstruction &instr,
                      const ZydisDecodedOperand *ops,
                      const std::uint8_t *raw_bytes) {
  vtil::batch_translator translator{block};
  vtil::operative::translator = &translator;

  block->mov(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RIP), vip + instr.length);

  auto &handlers = get_handlers();
  auto it = handlers.find(instr.mnemonic);

  if (it == handlers.end() || !memops_liftable(instr, ops))
    lift_fallback(block, instr, ops, raw_bytes);
  else
    it->second(block, instr, ops);
}
void vtil::print_unhandled() {
  if (unhandled_counts.empty()) {
    spdlog::info("no unhandled mnemonics encountered");
    return;
  }

  std::vector<std::pair<ZydisMnemonic, std::size_t>> sorted(
      unhandled_counts.begin(), unhandled_counts.end());
  std::sort(sorted.begin(), sorted.end(),
            [](auto &a, auto &b) { return a.second > b.second; });

  std::size_t total = 0;
  for (auto &[_, c] : sorted)
    total += c;

  spdlog::info(
      "=== unhandled mnemonics: {} unique, {} total ===", sorted.size(), total);
  for (auto &[mn, count] : sorted) {
    spdlog::info("  {:<12} {:>6}  ({:>5.1f}%)", ZydisMnemonicGetString(mn),
                 count, 100.0 * count / total);
  }
}
