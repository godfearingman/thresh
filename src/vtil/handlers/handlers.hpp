#pragma once

#include "spdlog/spdlog.h"

#include "../lift/flags.hpp"
#include "../regs/regs.hpp"

namespace vtil {
vtil::operand jcc_condition(vtil::basic_block *block, ZydisMnemonic mnemonic);
}

#define CC_LIST(X)                                                             \
  X(O)                                                                         \
  X(NO)                                                                        \
  X(B)                                                                         \
  X(NB) X(Z) X(NZ) X(BE) X(NBE) X(S) X(NS) X(P) X(NP) X(L) X(NL) X(LE) X(NLE)

inline ZydisMnemonic setcc_to_jcc(ZydisMnemonic m) {
  switch (m) {
#define X(cc)                                                                  \
  case ZYDIS_MNEMONIC_SET##cc:                                                 \
    return ZYDIS_MNEMONIC_J##cc;
    CC_LIST(X)
#undef X
  default:
    return ZYDIS_MNEMONIC_INVALID;
  }
}

inline ZydisMnemonic cmovcc_to_jcc(ZydisMnemonic m) {
  switch (m) {
#define X(cc)                                                                  \
  case ZYDIS_MNEMONIC_CMOV##cc:                                                \
    return ZYDIS_MNEMONIC_J##cc;
    CC_LIST(X)
#undef X
  default:
    return ZYDIS_MNEMONIC_INVALID;
  }
}

// clang-format off
// vtil::basic_block *block, const ZydisDecodedInstruction &instr, const ZydisDecodedOperand *ops
// clang-format on

#define DEFINE_BINOP(mn, name)                                                 \
  inline void name(vtil::basic_block *block,                                   \
                   const ZydisDecodedInstruction &insn,                        \
                   const ZydisDecodedOperand *ops) {                           \
    auto lhs = vtil::load_operand(block, insn, ops, 0);                        \
    auto rhs = vtil::load_operand(block, insn, ops, 1);                        \
    auto tmp = block->tmp(lhs.bit_count());                                    \
    block->mov(tmp, lhs)->name(tmp, rhs);                                      \
    vtil::process_flags<vtil::flags::name>(block, lhs, rhs, {tmp});            \
    vtil::store_operand(block, insn, ops, 0, {tmp});                           \
  }

namespace vtil_handler {
// mov dst, src
inline void mov(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  auto src = vtil::load_operand(block, instr, ops, 1);
  vtil::store_operand(block, instr, ops, 0, src);
}
// lea rax, [rbx + rcx*4 + 0x10]
inline void lea(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  auto src = vtil::get_disp_from_operand(block, ops[1]);
  vtil::store_operand(block, instr, ops, 0, src);
}

// cmp reg, reg
inline void cmp(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  auto lhs = vtil::load_operand(block, instr, ops, 0);
  auto rhs = vtil::load_operand(block, instr, ops, 1);
  auto tmp = block->tmp(lhs.bit_count());
  block->mov(tmp, lhs)->sub(tmp, rhs);
  vtil::process_flags<vtil::flags::sub>(block, lhs, rhs, {tmp});
}

// nop
inline void nop(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {}

// not
inline void _not(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto src = vtil::load_operand(block, instr, ops, 0);
  auto tmp = block->tmp(src.bit_count());
  block->mov(tmp, src)->bnot(tmp);
  vtil::store_operand(block, instr, ops, 0, tmp);
}

// test reg, reg
inline void test(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto lhs = vtil::load_operand(block, instr, ops, 0);
  auto rhs = vtil::load_operand(block, instr, ops, 1);
  auto tmp = block->tmp(lhs.bit_count());
  block->mov(tmp, lhs)->band(tmp, rhs);
  vtil::process_flags<vtil::flags::band>(block, lhs, rhs, {tmp});
}

// push reg/imm/mem
inline void push(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  auto operand = vtil::load_operand(block, instr, ops, 0);
  block->sub(reg_rsp, 8);
  block->str(reg_rsp, 0, operand);
}

// pop reg
inline void pop(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  auto tmp = block->tmp(64);
  block->ldd(tmp, reg_rsp, 0);
  block->add(reg_rsp, 8);
  vtil::store_operand(block, instr, ops, 0, tmp);
}

// pushfq
inline void pushfq(vtil::basic_block *block,
                   const ZydisDecodedInstruction &instr,
                   const ZydisDecodedOperand *ops) {
  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  block->sub(reg_rsp, 8);
  block->str(reg_rsp, 0, vtil::REG_FLAGS);
}

// popfq
inline void popfq(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  auto tmp = block->tmp(64);
  block->ldd(tmp, reg_rsp, 0);
  block->add(reg_rsp, 8);
  block->mov(vtil::REG_FLAGS, tmp);
}

// clc
inline void clc(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  block->mov(vtil::flags::CF, vtil::operand(0, 1));
}

// cmc
inline void cmc(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  block->bnot(vtil::flags::CF);
}

// stc
inline void stc(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  block->mov(vtil::flags::CF, vtil::operand(1, 1));
}

// movsx(d) reg, val
inline void movsx(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  auto src = vtil::load_operand(block, instr, ops, 1);
  auto tmp = block->tmp(64);
  block->movsx(tmp, src);
  vtil::store_operand(block, instr, ops, 0, tmp);
}

// xchg reg/mem, reg/mem
inline void xchg(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto lhs = vtil::load_operand(block, instr, ops, 0);
  auto rhs = vtil::load_operand(block, instr, ops, 1);
  vtil::store_operand(block, instr, ops, 0, rhs);
  vtil::store_operand(block, instr, ops, 1, lhs);
}

// setcc
inline void setcc(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  auto tmp = block->tmp(8);
  auto cond = vtil::jcc_condition(block, setcc_to_jcc(instr.mnemonic));
  block->mov(tmp, cond);
  vtil::store_operand(block, instr, ops, 0, tmp);
}

// cmovcc
inline void cmovcc(vtil::basic_block *block,
                   const ZydisDecodedInstruction &instr,
                   const ZydisDecodedOperand *ops) {
  auto cond = vtil::jcc_condition(block, cmovcc_to_jcc(instr.mnemonic));
  auto dst = vtil::load_operand(block, instr, ops, 0);
  auto src = vtil::load_operand(block, instr, ops, 1);
  auto bit_count = ops[0].size;

  auto not_cond = block->tmp(1);
  block->mov(not_cond, cond);
  block->bnot(not_cond);

  auto res = block->tmp(bit_count);
  block->ifs(res, cond, src);

  auto keep = block->tmp(bit_count);
  block->ifs(keep, not_cond, dst);

  block->bor(res, keep);
  vtil::store_operand(block, instr, ops, 0, res);
}

// bt
inline void bt(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
               const ZydisDecodedOperand *ops) {
  auto val = vtil::load_operand(block, instr, ops, 0);
  auto idx = vtil::load_operand(block, instr, ops, 1);
  auto bit_count = ops[0].size;

  auto new_idx = block->tmp(bit_count);
  block->mov(new_idx, idx);
  block->band(new_idx, vtil::operand(bit_count - 1, bit_count));

  auto temp = block->tmp(bit_count);
  block->mov(temp, val);
  block->bshr(temp, new_idx);

  vtil::register_desc low = temp;
  low.bit_count = 1;
  low.bit_offset = 0;

  block->mov(vtil::flags::CF, low);

  auto mask = block->tmp(bit_count);
  block->mov(mask, vtil::operand(1, bit_count));
  block->bshl(mask, new_idx);

  auto res = block->tmp(bit_count);
  block->mov(res, val);

  switch (instr.mnemonic) {
  case ZYDIS_MNEMONIC_BTS:
    block->bor(res, mask);
    break;
  case ZYDIS_MNEMONIC_BTR:
    block->bnot(mask);
    block->band(res, mask);
    break;
  case ZYDIS_MNEMONIC_BTC:
    block->bxor(res, mask);
    break;
  default:
    break;
  }
  vtil::store_operand(block, instr, ops, 0, res);
}

// bswap
inline void bswap(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  auto val = vtil::load_operand(block, instr, ops, 0);
  auto bit_count = ops[0].size;
  auto n = bit_count / 8;

  auto res = block->tmp(bit_count);
  block->mov(res, vtil::operand(0, bit_count));
  for (std::int32_t idx = 0; idx < n; idx++) {
    std::int32_t idx_work = idx * 8;
    auto temp = block->tmp(bit_count);
    block->mov(temp, val);
    block->bshr(temp, vtil::operand(idx_work, bit_count));
    block->band(temp, vtil::operand(0xff, bit_count));

    idx_work = (n - 1 - idx) * 8;
    block->bshl(temp, vtil::operand(idx_work, bit_count));
    block->bor(res, temp);
  }

  vtil::store_operand(block, instr, ops, 0, res);
}

// lahf
inline void lahf(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto res = block->tmp(8);
  block->mov(res, vtil::operand(2, 8));

  auto flag = block->tmp(8);
  block->mov(flag, vtil::flags::CF);
  block->bor(res, flag);

  block->mov(flag, vtil::flags::PF);
  block->bshl(flag, vtil::operand(2, 8));
  block->bor(res, flag);

  block->mov(flag, vtil::flags::AF);
  block->bshl(flag, vtil::operand(4, 8));
  block->bor(res, flag);

  block->mov(flag, vtil::flags::ZF);
  block->bshl(flag, vtil::operand(6, 8));
  block->bor(res, flag);

  block->mov(flag, vtil::flags::SF);
  block->bshl(flag, vtil::operand(7, 8));
  block->bor(res, flag);

  vtil::register_desc ah = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX).reg();
  ah.bit_offset = 8;
  ah.bit_count = 8;
  block->mov(ah, res);
}

// ro(l/r)
inline void ro(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
               const ZydisDecodedOperand *ops) {
  bool left = (instr.mnemonic == ZYDIS_MNEMONIC_ROL);
  auto val = vtil::load_operand(block, instr, ops, 0);
  auto cnt = vtil::load_operand(block, instr, ops, 1);
  auto bit_count = ops[0].size;

  std::uint64_t cnt_mask = (bit_count == 64) ? 0x3f : 0x1f;
  auto mask = block->tmp(bit_count);
  block->mov(mask, cnt);
  block->band(mask, vtil::operand(cnt_mask, bit_count));

  auto res = block->tmp(bit_count);
  block->mov(res, val);
  left ? block->brol(res, mask) : block->bror(res, mask);

  vtil::register_desc cf_bit = res;
  cf_bit.bit_count = 1;
  cf_bit.bit_offset = left ? 0 : (bit_count - 1);

  block->mov(vtil::flags::CF, cf_bit);
  vtil::store_operand(block, instr, ops, 0, res);
}

// rcl
inline void rcl(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto bit_count = ops[0].size;
  const std::uint64_t cnt_mask = (bit_count == 64) ? 0x3f : 0x1f;

  auto val = vtil::load_operand(block, instr, ops, 0);
  auto cnt = vtil::load_operand(block, instr, ops, 1);

  auto n = block->tmp(bit_count);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cnt_mask, bit_count));
  if (bit_count < 32) {
    block->rem(n, vtil::operand(std::uint64_t(0), bit_count),
               vtil::operand(std::uint64_t(bit_count + 1), bit_count));
  }

  auto rot = block->tmp(bit_count);
  block->mov(rot, val);
  block->bshl(rot, n);

  auto nm1 = block->tmp(bit_count);
  block->mov(nm1, n);
  block->sub(nm1, vtil::operand(std::uint64_t(1), bit_count));

  auto t = block->tmp(bit_count);
  block->mov(t, vtil::flags::CF);
  block->bshl(t, nm1);
  block->bor(rot, t);

  auto rsh = block->tmp(bit_count);
  block->mov(rsh, vtil::operand(std::uint64_t(bit_count + 1), bit_count));
  block->sub(rsh, n);

  block->mov(t, val);
  block->bshr(t, rsh);
  block->bor(rot, t);

  auto cfsh = block->tmp(bit_count);
  block->mov(cfsh, vtil::operand(std::uint64_t(bit_count), bit_count));
  block->sub(cfsh, n);

  auto cfv = block->tmp(bit_count);
  block->mov(cfv, val);
  block->bshr(cfv, cfsh);

  vtil::register_desc new_cf = cfv;
  new_cf.bit_count = 1;
  new_cf.bit_offset = 0;

  auto is_zero = block->tmp(1);
  block->te(is_zero, n, vtil::operand(std::uint64_t(0), bit_count));
  auto not_zero = block->tmp(1);
  block->mov(not_zero, is_zero);
  block->bnot(not_zero);

  auto a = block->tmp(bit_count);
  block->ifs(a, is_zero, val);
  auto b = block->tmp(bit_count);
  block->ifs(b, not_zero, rot);
  auto res = block->tmp(bit_count);
  block->mov(res, a);
  block->bor(res, b);

  auto old_cf = block->tmp(1);
  block->mov(old_cf, vtil::flags::CF);

  auto ca = block->tmp(1);
  block->ifs(ca, is_zero, old_cf);
  auto cb = block->tmp(1);
  block->ifs(cb, not_zero, new_cf);
  block->bor(ca, cb);
  block->mov(vtil::flags::CF, ca);

  vtil::store_operand(block, instr, ops, 0, res);
}

inline void adc_sbb(vtil::basic_block *block,
                    const ZydisDecodedInstruction &instr,
                    const ZydisDecodedOperand *ops) {
  const auto bit_count = ops[0].size;
  const bool is_adc = (instr.mnemonic == ZYDIS_MNEMONIC_ADC);

  auto lhs = vtil::load_operand(block, instr, ops, 0);
  auto rhs = vtil::load_operand(block, instr, ops, 1);

  auto cf = block->tmp(bit_count);
  block->mov(cf, vtil::flags::CF);

  auto rhs_cf = block->tmp(bit_count);
  block->mov(rhs_cf, rhs);
  block->add(rhs_cf, cf);

  auto res = block->tmp(bit_count);
  block->mov(res, lhs);
  is_adc ? block->add(res, rhs_cf) : block->sub(res, rhs_cf);

  if (is_adc)
    vtil::process_flags<vtil::flags::add>(block, lhs, rhs_cf, res);
  else
    vtil::process_flags<vtil::flags::sub>(block, lhs, rhs_cf, res);

  vtil::store_operand(block, instr, ops, 0, res);
}

inline void inc_dec(vtil::basic_block *block,
                    const ZydisDecodedInstruction &instr,
                    const ZydisDecodedOperand *ops) {
  const auto bit_count = ops[0].size;
  const bool is_inc = (instr.mnemonic == ZYDIS_MNEMONIC_INC);

  auto lhs = vtil::load_operand(block, instr, ops, 0);
  auto one = vtil::operand(std::uint64_t(1), bit_count);

  auto res = block->tmp(bit_count);
  block->mov(res, lhs);
  is_inc ? block->add(res, one) : block->sub(res, one);

  auto saved_cf = block->tmp(1);
  block->mov(saved_cf, vtil::flags::CF);

  if (is_inc)
    vtil::process_flags<vtil::flags::add>(block, lhs, one, res);
  else
    vtil::process_flags<vtil::flags::sub>(block, lhs, one, res);

  block->mov(vtil::flags::CF, saved_cf);

  vtil::store_operand(block, instr, ops, 0, res);
}

inline void ret(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  std::uint64_t extra = 0;
  if (instr.operand_count_visible > 0 &&
      ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    extra = ops[0].imm.value.u;

  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  auto retaddr = block->tmp(64);
  block->ldd(retaddr, reg_rsp, 0);
  block->add(reg_rsp, 8);
  if (extra)
    block->add(vtil::REG_SP, vtil::operand(extra, 64));
  block->jmp(retaddr);
}

inline void call(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  auto reg_rsp = vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RSP);
  auto retaddr = block->tmp(64);
  block->mov(retaddr, vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RIP));
  block->sub(reg_rsp, 8);
  block->str(reg_rsp, 0, retaddr);
}

inline void jmp(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  auto op = vtil::load_operand(block, instr, ops, 0);
  if (!op.is_immediate() && op.bit_count() != 64) {
    // vtil rejects far jmp through memory since it's m16:32 and load_operand
    // will hand back 48 bits which fails on assertion. guard against that, they
    // shouldnt even exist regardless and is most likley just junk.
    spdlog::warn("[lift] unliftable jmp operand ({} bits) in block {:x}",
                 op.bit_count(), block->entry_vip);
    block->vexit(0);
    return;
  }
  block->jmp(op);
}

// DELETE LATER

inline void commit_shift_flags(vtil::basic_block *block, int width,
                               vtil::operand res, vtil::operand n,
                               vtil::operand cf, vtil::operand of) {
  auto zf = block->tmp(1);
  block->te(zf, res, vtil::operand(0, width));

  auto sf = block->tmp(1);
  block->mov(sf, res.reg().select(1, width - 1));

  auto pc = block->tmp(width);
  block->mov(pc, res);
  block->band(pc, vtil::operand(0xff, width));
  block->popcnt(pc);
  auto pf = block->tmp(1);
  block->mov(pf, pc.select(1, 0));
  block->bnot(pf);

  auto nz = block->tmp(1);
  block->tne(nz, n, vtil::operand(0, width));
  auto nzn = block->tmp(1);
  block->mov(nzn, nz);
  block->bnot(nzn);

  auto commit = [&](vtil::register_desc f, vtil::operand nv) {
    auto a = block->tmp(1);
    auto b = block->tmp(1);
    block->mov(a, nv);
    block->band(a, nz);
    block->mov(b, f);
    block->band(b, nzn);
    block->bor(a, b);
    block->mov(f, a);
  };

  commit(vtil::flags::CF, cf);
  commit(vtil::flags::OF, of);
  commit(vtil::flags::ZF, zf);
  commit(vtil::flags::SF, sf);
  commit(vtil::flags::PF, pf);
}

// shl / sal
inline void shl(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const auto cmask = (width == 64) ? 0x3full : 0x1full;

  auto dst = load_operand(block, instr, ops, 0);
  auto cnt = load_operand(block, instr, ops, 1);

  auto n = block->tmp(width);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cmask, width));

  auto res = block->tmp(width);
  block->mov(res, dst);
  block->bshl(res, n);

  // cf = bit (width - n) of the original dest
  auto sh = block->tmp(width);
  block->mov(sh, vtil::operand(width, width));
  block->sub(sh, n);
  auto cfw = block->tmp(width);
  block->mov(cfw, dst);
  block->bshr(cfw, sh);
  auto cf = block->tmp(1);
  block->mov(cf, cfw.select(1, 0));

  // of = msb(res) ^ cf   (only architecturally defined for n == 1)
  auto of = block->tmp(1);
  block->mov(of, res.select(1, width - 1));
  block->bxor(of, cf);

  commit_shift_flags(block, width, res, n, cf, of);
  store_operand(block, instr, ops, 0, res);
}

// shr
inline void shr(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const auto cmask = (width == 64) ? 0x3full : 0x1full;

  auto dst = load_operand(block, instr, ops, 0);
  auto cnt = load_operand(block, instr, ops, 1);

  auto n = block->tmp(width);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cmask, width));

  auto res = block->tmp(width);
  block->mov(res, dst);
  block->bshr(res, n);

  // cf = bit (n - 1) of the original dest
  auto sh = block->tmp(width);
  block->mov(sh, n);
  block->sub(sh, vtil::operand(1, width));
  auto cfw = block->tmp(width);
  block->mov(cfw, dst);
  block->bshr(cfw, sh);
  auto cf = block->tmp(1);
  block->mov(cf, cfw.select(1, 0));

  // of = msb of the original dest
  auto of = block->tmp(1);
  block->mov(of, dst.reg().select(1, width - 1));

  commit_shift_flags(block, width, res, n, cf, of);
  store_operand(block, instr, ops, 0, res);
}

// sar
inline void sar(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const auto cmask = (width == 64) ? 0x3full : 0x1full;

  auto dst = load_operand(block, instr, ops, 0);
  auto cnt = load_operand(block, instr, ops, 1);

  auto n = block->tmp(width);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cmask, width));

  auto res = block->tmp(width);
  if (width < 64) {
    // sign-extend to 64, logical-shift, truncate back
    auto ext = block->tmp(64);
    block->movsx(ext, dst);
    block->bshr(ext, n);
    block->mov(res, ext);
  } else {
    // res = (dst >> n) | (sign ? ~0 << (64 - n) : 0)
    auto lsr = block->tmp(64);
    block->mov(lsr, dst);
    block->bshr(lsr, n);

    auto sign = block->tmp(1);
    block->mov(sign, dst.reg().select(1, 63));

    auto smask = block->tmp(64);
    block->mov(smask, sign);
    block->neg(smask); // 0 -> 0, 1 -> all ones

    auto sh = block->tmp(64);
    block->mov(sh, vtil::operand(64, 64));
    block->sub(sh, n);

    auto fill = block->tmp(64);
    block->mov(fill, vtil::operand(~0ull, 64));
    block->bshl(fill, sh);
    block->band(fill, smask);

    // n == 0 must leave dst untouched, so kill the fill in that case
    auto nz = block->tmp(1);
    block->tne(nz, n, vtil::operand(0, 64));
    auto nzm = block->tmp(64);
    block->mov(nzm, nz);
    block->neg(nzm);
    block->band(fill, nzm);

    block->mov(res, lsr);
    block->bor(res, fill);
  }

  // cf = bit (n - 1) of the original dest
  auto sh2 = block->tmp(width);
  block->mov(sh2, n);
  block->sub(sh2, vtil::operand(1, width));
  auto cfw = block->tmp(width);
  block->mov(cfw, dst);
  block->bshr(cfw, sh2);
  auto cf = block->tmp(1);
  block->mov(cf, cfw.select(1, 0));

  // sar always clears OF
  auto of = block->tmp(1);
  block->mov(of, vtil::operand(0, 1));

  commit_shift_flags(block, width, res, n, cf, of);
  store_operand(block, instr, ops, 0, res);
}

// shld dest, src, count  ->  dest = (dest << n) | (src >> (width - n))
inline void shld(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const auto cmask = (width == 64) ? 0x3full : 0x1full;

  auto dst = load_operand(block, instr, ops, 0);
  auto src = load_operand(block, instr, ops, 1);
  auto cnt = load_operand(block, instr, ops, 2);

  auto n = block->tmp(width);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cmask, width));

  auto inv = block->tmp(width);
  block->mov(inv, vtil::operand(width, width));
  block->sub(inv, n);

  auto lo = block->tmp(width);
  block->mov(lo, src);
  block->bshr(lo, inv);

  auto res = block->tmp(width);
  block->mov(res, dst);
  block->bshl(res, n);
  block->bor(res, lo);

  // cf = bit (width - n) of the original dest
  auto cfw = block->tmp(width);
  block->mov(cfw, dst);
  block->bshr(cfw, inv);
  auto cf = block->tmp(1);
  block->mov(cf, cfw.select(1, 0));

  auto of = block->tmp(1);
  block->mov(of, res.select(1, width - 1));
  block->bxor(of, dst.reg().select(1, width - 1));

  commit_shift_flags(block, width, res, n, cf, of);
  store_operand(block, instr, ops, 0, res);
}

inline void neg(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const std::uint64_t smin = 1ull << (width - 1);

  auto dst = load_operand(block, instr, ops, 0);

  // flags that depend on the *original* value
  auto cf = block->tmp(1);
  block->tne(cf, dst, vtil::operand(0, width)); // CF = src != 0

  auto of = block->tmp(1);
  block->te(of, dst, vtil::operand(smin, width)); // OF = src == INT_MIN

  auto low = block->tmp(width);
  block->mov(low, dst);
  block->band(low, vtil::operand(0xf, width));
  auto af = block->tmp(1);
  block->tne(af, low, vtil::operand(0, width)); // AF = borrow out of nibble

  auto res = block->tmp(width);
  block->mov(res, dst);
  block->neg(res);

  auto zf = block->tmp(1);
  block->te(zf, res, vtil::operand(0, width));

  auto sf = block->tmp(1);
  block->mov(sf, res.select(1, width - 1));

  auto pc = block->tmp(width);
  block->mov(pc, res);
  block->band(pc, vtil::operand(0xff, width));
  block->popcnt(pc);
  auto pf = block->tmp(1);
  block->mov(pf, pc.select(1, 0));
  block->bnot(pf);

  block->mov(vtil::flags::CF, cf);
  block->mov(vtil::flags::OF, of);
  block->mov(vtil::flags::AF, af);
  block->mov(vtil::flags::ZF, zf);
  block->mov(vtil::flags::SF, sf);
  block->mov(vtil::flags::PF, pf);

  store_operand(block, instr, ops, 0, res);
}

// shrd dest, src, count  ->  dest = (dest >> n) | (src << (width - n))
inline void shrd(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;
  const auto cmask = (width == 64) ? 0x3full : 0x1full;

  auto dst = load_operand(block, instr, ops, 0);
  auto src = load_operand(block, instr, ops, 1);
  auto cnt = load_operand(block, instr, ops, 2);

  auto n = block->tmp(width);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cmask, width));

  auto inv = block->tmp(width);
  block->mov(inv, vtil::operand(width, width));
  block->sub(inv, n);

  auto hi = block->tmp(width);
  block->mov(hi, src);
  block->bshl(hi, inv);

  auto res = block->tmp(width);
  block->mov(res, dst);
  block->bshr(res, n);
  block->bor(res, hi);

  // cf = bit (n - 1) of the original dest
  auto sh = block->tmp(width);
  block->mov(sh, n);
  block->sub(sh, vtil::operand(1, width));
  auto cfw = block->tmp(width);
  block->mov(cfw, dst);
  block->bshr(cfw, sh);
  auto cf = block->tmp(1);
  block->mov(cf, cfw.select(1, 0));

  auto of = block->tmp(1);
  block->mov(of, res.select(1, width - 1));
  block->bxor(of, dst.reg().select(1, width - 1));

  commit_shift_flags(block, width, res, n, cf, of);
  store_operand(block, instr, ops, 0, res);
}

// bsf dest, src
inline void bsf(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto width = ops[0].size;

  auto src = load_operand(block, instr, ops, 1);

  auto zf = block->tmp(1);
  block->te(zf, src, vtil::operand(0, width));
  block->mov(vtil::flags::ZF, zf);

  // dest is architecturally undefined when src == 0; leave whatever bsf gives
  auto res = block->tmp(width);
  block->mov(res, src);
  instr.mnemonic == ZYDIS_MNEMONIC_BSR ? block->bsr(res) : block->bsf(res);

  store_operand(block, instr, ops, 0, res);
}

// rcr
inline void rcr(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops) {
  const auto bit_count = ops[0].size;
  const std::uint64_t cnt_mask = (bit_count == 64) ? 0x3f : 0x1f;

  auto val = vtil::load_operand(block, instr, ops, 0);
  auto cnt = vtil::load_operand(block, instr, ops, 1);

  auto n = block->tmp(bit_count);
  block->mov(n, cnt);
  block->band(n, vtil::operand(cnt_mask, bit_count));
  if (bit_count < 32) {
    block->rem(n, vtil::operand(std::uint64_t(0), bit_count),
               vtil::operand(std::uint64_t(bit_count + 1), bit_count));
  }

  // rot = (val >> n) | (CF << (width - n)) | (val << (width + 1 - n))
  auto rot = block->tmp(bit_count);
  block->mov(rot, val);
  block->bshr(rot, n);

  auto csh = block->tmp(bit_count);
  block->mov(csh, vtil::operand(std::uint64_t(bit_count), bit_count));
  block->sub(csh, n);

  auto t = block->tmp(bit_count);
  block->mov(t, vtil::flags::CF);
  block->bshl(t, csh);
  block->bor(rot, t);

  auto lsh = block->tmp(bit_count);
  block->mov(lsh, vtil::operand(std::uint64_t(bit_count + 1), bit_count));
  block->sub(lsh, n);

  block->mov(t, val);
  block->bshl(t, lsh);
  block->bor(rot, t);

  // new CF = bit (n - 1) of the original value
  auto cfsh = block->tmp(bit_count);
  block->mov(cfsh, n);
  block->sub(cfsh, vtil::operand(std::uint64_t(1), bit_count));

  auto cfv = block->tmp(bit_count);
  block->mov(cfv, val);
  block->bshr(cfv, cfsh);

  vtil::register_desc new_cf = cfv;
  new_cf.bit_count = 1;
  new_cf.bit_offset = 0;

  // n == 0 leaves both dest and CF untouched
  auto is_zero = block->tmp(1);
  block->te(is_zero, n, vtil::operand(std::uint64_t(0), bit_count));
  auto not_zero = block->tmp(1);
  block->mov(not_zero, is_zero);
  block->bnot(not_zero);

  auto a = block->tmp(bit_count);
  block->ifs(a, is_zero, val);
  auto b = block->tmp(bit_count);
  block->ifs(b, not_zero, rot);
  auto res = block->tmp(bit_count);
  block->mov(res, a);
  block->bor(res, b);

  auto old_cf = block->tmp(1);
  block->mov(old_cf, vtil::flags::CF);

  auto ca = block->tmp(1);
  block->ifs(ca, is_zero, old_cf);
  auto cb = block->tmp(1);
  block->ifs(cb, not_zero, new_cf);
  block->bor(ca, cb);
  block->mov(vtil::flags::CF, ca);

  vtil::store_operand(block, instr, ops, 0, res);
}

// xadd dst, src  ->  tmp = dst + src; src = dst; dst = tmp
inline void xadd(vtil::basic_block *block, const ZydisDecodedInstruction &instr,
                 const ZydisDecodedOperand *ops) {
  const auto bit_count = ops[0].size;

  auto dst = vtil::load_operand(block, instr, ops, 0);
  auto src = vtil::load_operand(block, instr, ops, 1);

  auto res = block->tmp(bit_count);
  block->mov(res, dst);
  block->add(res, src);

  vtil::process_flags<vtil::flags::add>(block, dst, src, res);

  // src first, dst last: for `xadd r9b, r9b` the sum must win
  vtil::store_operand(block, instr, ops, 1, dst);
  vtil::store_operand(block, instr, ops, 0, res);
}
// cbw: ax = sext(al) | cwde: eax = sext(ax) | cdqe: rax = sext(eax)
inline void cbw_cwde_cdqe(vtil::basic_block *block,
                          const ZydisDecodedInstruction &instr,
                          const ZydisDecodedOperand *ops) {
  ZydisRegister src_r = ZYDIS_REGISTER_EAX, dst_r = ZYDIS_REGISTER_RAX; // cdqe
  if (instr.mnemonic == ZYDIS_MNEMONIC_CBW) {
    src_r = ZYDIS_REGISTER_AL;
    dst_r = ZYDIS_REGISTER_AX;
  }
  if (instr.mnemonic == ZYDIS_MNEMONIC_CWDE) {
    src_r = ZYDIS_REGISTER_AX;
    dst_r = ZYDIS_REGISTER_EAX;
  }

  auto dst = vtil::zydis_to_vtil_reg(dst_r);
  auto tmp = block->tmp(dst.bit_count());
  block->movsx(tmp, vtil::zydis_to_vtil_reg(src_r));

  if (dst_r == ZYDIS_REGISTER_EAX) { // 32-bit write zero-extends into rax
    auto wide = block->tmp(64);
    block->mov(wide, tmp);
    block->mov(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX), wide);
  } else {
    block->mov(dst, tmp);
  }
}
inline void cwd_cdq_cqo(vtil::basic_block *block,
                        const ZydisDecodedInstruction &instr,
                        const ZydisDecodedOperand *ops) {
  ZydisRegister a_r = ZYDIS_REGISTER_RAX, d_r = ZYDIS_REGISTER_RDX; // cqo
  if (instr.mnemonic == ZYDIS_MNEMONIC_CWD) {
    a_r = ZYDIS_REGISTER_AX;
    d_r = ZYDIS_REGISTER_DX;
  }
  if (instr.mnemonic == ZYDIS_MNEMONIC_CDQ) {
    a_r = ZYDIS_REGISTER_EAX;
    d_r = ZYDIS_REGISTER_EDX;
  }

  auto a = vtil::zydis_to_vtil_reg(a_r);
  const auto w = a.bit_count();

  auto sign = block->tmp(1);
  block->mov(sign, a.reg().select(1, w - 1));
  auto fill = block->tmp(w);
  block->mov(fill, sign);
  block->neg(fill); // 0 -> 0, 1 -> all ones

  if (d_r == ZYDIS_REGISTER_EDX) { // 32-bit write zero-extends into rdx
    auto wide = block->tmp(64);
    block->mov(wide, fill);
    block->mov(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RDX), wide);
  } else {
    block->mov(vtil::zydis_to_vtil_reg(d_r), fill);
  }
}
// cpuid: model a fixed reference CPU (Intel i7-9700K, family 6 model 0x9E, no
// hypervisor bit). Leaf 0 -> "GenuineIntel", every other leaf -> leaf 1 values.
// An explicit environment assumption, like TF = 0: without it VM branches on
// the CPU's family/model can't be decided.
inline void cpuid(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  auto leaf = block->tmp(32);
  block->mov(leaf, vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_EAX));

  auto is0 = block->tmp(1);
  block->te(is0, leaf, vtil::operand(std::uint64_t(0), 32));
  auto not0 = block->tmp(1);
  block->mov(not0, is0);
  block->bnot(not0);

  // 32-bit results zero-extend into the full 64-bit registers
  auto set = [&](ZydisRegister r, std::uint64_t leaf0, std::uint64_t leaf1) {
    auto a = block->tmp(64);
    block->ifs(a, is0, vtil::operand(leaf0, 64));
    auto b = block->tmp(64);
    block->ifs(b, not0, vtil::operand(leaf1, 64));
    block->bor(a, b);
    block->mov(vtil::zydis_to_vtil_reg(r), a);
  };
  // leaf 1 eax (signature) and ebx (brand/clflush/apic) are the function's real
  // inputs, so leave them symbolic: two global virtual registers that are never
  // written, read here as 32-bit values zero-extended into rax/rbx.
  auto set_sym = [&](ZydisRegister r, std::uint64_t leaf0, std::uint32_t id) {
    auto a = block->tmp(64);
    block->ifs(a, is0, vtil::operand(leaf0, 64));
    auto sym = block->tmp(64);
    block->mov(sym,
               vtil::register_desc{vtil::register_virtual, 0xC000ull + id, 32});
    auto b = block->tmp(64);
    block->ifs(b, not0, sym);
    block->bor(a, b);
    block->mov(vtil::zydis_to_vtil_reg(r), a);
  };
  //                            leaf 0                   leaf 1 / other
  set_sym(ZYDIS_REGISTER_RAX, 0x16, /* max */ 0);          // cpuid.1.eax
  set_sym(ZYDIS_REGISTER_RBX, 0x756E6547, /* "Genu" */ 1); // cpuid.1.ebx
  set(ZYDIS_REGISTER_RDX, 0x49656E69, /* "ineI" */ 0xBFEBFBFF);
  set(ZYDIS_REGISTER_RCX, 0x6C65746E, /* "ntel" */ 0x7FFAFBBF);
}
// rdtsc: frozen clock. Timing anti-debug compares two reads; a constant makes
// the delta 0 (i.e. "not being debugged"). edx:eax = 0, upper halves zeroed.
inline void rdtsc(vtil::basic_block *block,
                  const ZydisDecodedInstruction &instr,
                  const ZydisDecodedOperand *ops) {
  block->mov(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX),
             vtil::operand(std::uint64_t(0), 64));
  block->mov(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RDX),
             vtil::operand(std::uint64_t(0), 64));
}
// native-lifter macro lul shotu out i guess.. stole all the fun
DEFINE_BINOP(ZYDIS_MNEMONIC_ADD, add)
DEFINE_BINOP(ZYDIS_MNEMONIC_SUB, sub)
DEFINE_BINOP(ZYDIS_MNEMONIC_AND, band)
DEFINE_BINOP(ZYDIS_MNEMONIC_XOR, bxor)
DEFINE_BINOP(ZYDIS_MNEMONIC_OR, bor)

} // namespace vtil_handler
