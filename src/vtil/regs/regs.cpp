#include "regs.hpp"
#include "spdlog/spdlog.h"
// clang-format off
#define ZYDIS_CAPSTONE_REG_MAP(X)                                              \
                                                             \
  X(RAX)                                                                       \
  X(RBX) X(RCX) X(RDX) X(RSI) X(RDI) X(RBP) X(RSP) X(R8) X(R9) X(R10) X(R11)   \
      X(R12) X(R13) X(R14) X(R15)                                  \
      X(EAX) X(EBX) X(ECX) X(EDX) X(ESI) X(EDI) X(EBP) X(ESP) X(R8D) X(R9D)    \
          X(R10D) X(R11D) X(R12D) X(R13D) X(R14D) X(R15D)          \
      X(AX) X(BX) X(CX) X(DX) X(SI) X(DI) X(BP) X(SP) X(R8W) X(R9W) X(R10W)    \
          X(R11W) X(R12W) X(R13W) X(R14W) X(R15W)               \
      X(AL) X(BL) X(CL) X(DL) X(SIL) X(DIL) X(BPL) X(SPL) X(R8B) X(R9B)        \
          X(R10B) X(R11B) X(R12B) X(R13B) X(R14B) X(R15B)      \
      X(AH) X(BH) X(CH) X(DH)                         \
      X(RIP) X(EIP) X(IP)                               \
      X(CS) X(DS) X(ES) X(FS) X(GS) X(SS)                             \
      X(MM0) X(MM1) X(MM2) X(MM3) X(MM4) X(MM5) X(MM6) X(MM7)     \
      X(ST0) X(ST1) X(ST2) X(ST3) X(ST4) X(ST5) X(ST6) X(ST7)    \
      X(XMM0) X(XMM1) X(XMM2) X(XMM3) X(XMM4) X(XMM5) X(XMM6) X(XMM7) X(XMM8)  \
          X(XMM9) X(XMM10) X(XMM11) X(XMM12) X(XMM13) X(XMM14)                 \
              X(XMM15)                                \
      X(XMM16) X(XMM17) X(XMM18) X(XMM19) X(XMM20) X(XMM21) X(XMM22) X(XMM23)  \
          X(XMM24) X(XMM25) X(XMM26) X(XMM27) X(XMM28) X(XMM29) X(XMM30)       \
              X(XMM31)                                           \
      X(YMM0) X(YMM1) X(YMM2) X(YMM3) X(YMM4) X(YMM5) X(YMM6) X(YMM7) X(YMM8)  \
          X(YMM9) X(YMM10) X(YMM11) X(YMM12) X(YMM13) X(YMM14)                 \
              X(YMM15)                                          \
      X(YMM16) X(YMM17) X(YMM18) X(YMM19) X(YMM20) X(YMM21) X(YMM22) X(YMM23)  \
          X(YMM24) X(YMM25) X(YMM26) X(YMM27) X(YMM28) X(YMM29) X(YMM30)       \
              X(YMM31)                                           \
      X(ZMM0) X(ZMM1) X(ZMM2) X(ZMM3) X(ZMM4) X(ZMM5) X(ZMM6) X(ZMM7) X(ZMM8)  \
          X(ZMM9) X(ZMM10) X(ZMM11) X(ZMM12) X(ZMM13) X(ZMM14) X(ZMM15)        \
              X(ZMM16) X(ZMM17) X(ZMM18) X(ZMM19) X(ZMM20) X(ZMM21) X(ZMM22)   \
                  X(ZMM23) X(ZMM24) X(ZMM25) X(ZMM26) X(ZMM27) X(ZMM28)        \
                      X(ZMM29) X(ZMM30) X(ZMM31)                  \
      X(CR0) X(CR1) X(CR2) X(CR3) X(CR4) X(CR5) X(CR6) X(CR7) X(CR8) X(CR9)    \
          X(CR10) X(CR11) X(CR12) X(CR13) X(CR14) X(CR15)           \
      X(DR0) X(DR1) X(DR2) X(DR3) X(DR4) X(DR5) X(DR6) X(DR7) X(DR8) X(DR9)    \
          X(DR10) X(DR11) X(DR12) X(DR13) X(DR14) X(DR15)    \
      X(K0) X(K1) X(K2) X(K3) X(K4) X(K5) X(K6) X(K7)
// clang-format on

x86_reg vtil::zydis_to_capstone(ZydisRegister reg) {
  switch (reg) {
#define X(NAME)                                                                \
  case ZYDIS_REGISTER_##NAME:                                                  \
    return X86_REG_##NAME;
    ZYDIS_CAPSTONE_REG_MAP(X)
#undef X
  case ZYDIS_REGISTER_RFLAGS:
  case ZYDIS_REGISTER_EFLAGS:
  case ZYDIS_REGISTER_FLAGS:
    return X86_REG_EFLAGS;
  default:
    return X86_REG_INVALID;
  }
}

vtil::operand vtil::zydis_to_vtil_reg(ZydisRegister reg) {
  return vtil::register_cast<x86_reg>{}(vtil::zydis_to_capstone(reg));
}

vtil::register_desc vtil::get_disp_from_operand(vtil::basic_block *block,
                                                const ZydisDecodedOperand &op) {
  // assume [reg + reg * scale + disp]
  const bool gs = op.mem.segment == ZYDIS_REGISTER_GS;
  // handle [base]
  if (!gs && op.mem.base != ZYDIS_REGISTER_NONE && !op.mem.disp.value &&
      op.mem.index == ZYDIS_REGISTER_NONE)
    return vtil::register_cast<x86_reg>{}(vtil::zydis_to_capstone(op.mem.base));

  // handle idx * scale
  auto current_off = block->tmp(64);
  if (op.mem.index != ZYDIS_REGISTER_NONE) {
    block->mov(current_off, vtil::zydis_to_vtil_reg(op.mem.index));
    // handle idx * scale
    if (op.mem.scale > 1)
      block->mul(current_off, op.mem.scale);
  }

  // now merge it all together if existing
  if (op.mem.base != ZYDIS_REGISTER_NONE) {
    // check if we had to handle a idx
    if (op.mem.index != ZYDIS_REGISTER_NONE)
      block->add(current_off, vtil::zydis_to_vtil_reg(op.mem.base));
    else
      // if we didn't we just need to move the value in
      block->mov(current_off, vtil::zydis_to_vtil_reg(op.mem.base));
  }

  // lastly handle the disp
  if (op.mem.disp.value) {
    if (op.mem.index != ZYDIS_REGISTER_NONE ||
        op.mem.base != ZYDIS_REGISTER_NONE)
      block->add(current_off, op.mem.disp.value);
    else
      block->mov(current_off, op.mem.disp.value);
  }

  if (gs) {
    if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE &&
        !op.mem.disp.value)
      block->mov(current_off, vtil::operand(std::uint64_t(0), 64)); // gs:[0]
    block->add(current_off, vtil::operand(fake_env::TEB, 64));
  }
  return current_off;
}

vtil::operand vtil::load_operand(vtil::basic_block *block,
                                 const ZydisDecodedInstruction &instr,
                                 const ZydisDecodedOperand *ops,
                                 std::size_t idx) {
  const auto &op = ops[idx];
  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_IMMEDIATE:
    return vtil::operand(op.imm.value.u,
                         op.imm.is_signed ? instr.operand_width : op.size);
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    auto temp = block->tmp(op.size);
    block->mov(temp, vtil::zydis_to_vtil_reg(op.reg.value));
    return vtil::operand(temp);
  }
  case ZYDIS_OPERAND_TYPE_MEMORY: {
    auto temp = block->tmp(op.size);
    block->ldd(temp, vtil::get_disp_from_operand(block, op), 0);
    return vtil::operand(temp);
  }
  default:
    unreachable();
  }
}

void vtil::store_operand(vtil::basic_block *block,
                         const ZydisDecodedInstruction &instr,
                         const ZydisDecodedOperand *ops, std::size_t idx,
                         const vtil::operand &src) {
  const auto &op = ops[idx];
  switch (op.type) {
  case ZYDIS_OPERAND_TYPE_REGISTER: {
    vtil::operand dst = vtil::zydis_to_vtil_reg(op.reg.value);
    if (dst.bit_count() == 32) {
      // on 32 bit registers we need to zero the upper bits
      vtil::operand full = dst;
      full.reg().bit_count = 64;
      auto wide = block->tmp(64);
      block->mov(wide, src);
      block->mov(full, wide);
      break;
    }
    block->mov(dst, src);
    break;
  }
  case ZYDIS_OPERAND_TYPE_MEMORY: {
    block->str(vtil::get_disp_from_operand(block, op), 0, src);
    break;
  }
  case ZYDIS_OPERAND_TYPE_IMMEDIATE:
  default:
    unreachable();
  }
}
