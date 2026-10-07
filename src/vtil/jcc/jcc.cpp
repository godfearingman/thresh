#include "jcc.hpp"

vtil::operand vtil::jcc_condition(vtil::basic_block *block, ZydisMnemonic mn) {
  auto tmp = block->tmp(1);
  switch (mn) {
  case ZYDIS_MNEMONIC_JZ: // zf == 1
    block->mov(tmp, vtil::flags::ZF);
    break;
  case ZYDIS_MNEMONIC_JNZ: // zf == 0
    block->mov(tmp, vtil::flags::ZF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JB: // cf == 1
    block->mov(tmp, vtil::flags::CF);
    break;
  case ZYDIS_MNEMONIC_JNB: // cf == 0
    block->mov(tmp, vtil::flags::CF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JBE: // cf == 1 or zf == 1
    block->mov(tmp, vtil::flags::CF);
    block->bor(tmp, vtil::flags::ZF);
    break;
  case ZYDIS_MNEMONIC_JNBE: { // cf == 0 and zf == 0
    block->mov(tmp, vtil::flags::CF);
    block->bxor(tmp, 1);

    auto tmp2 = block->tmp(1);
    block->mov(tmp2, vtil::flags::ZF);
    block->bxor(tmp2, 1);

    block->band(tmp, tmp2);

    break;
  }
  case ZYDIS_MNEMONIC_JS: // sf == 1
    block->mov(tmp, vtil::flags::SF);
    break;
  case ZYDIS_MNEMONIC_JNS: // sf == 0
    block->mov(tmp, vtil::flags::SF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JO: // of == 1
    block->mov(tmp, vtil::flags::OF);
    break;
  case ZYDIS_MNEMONIC_JNO: // of == 0
    block->mov(tmp, vtil::flags::OF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JP: // pf == 1
    block->mov(tmp, vtil::flags::PF);
    break;
  case ZYDIS_MNEMONIC_JNP: // pf == 0
    block->mov(tmp, vtil::flags::PF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JL: // SF != OF
    block->mov(tmp, vtil::flags::SF);
    block->bxor(tmp, vtil::flags::OF);
    break;
  case ZYDIS_MNEMONIC_JNL: // SF == OF
    block->mov(tmp, vtil::flags::SF);
    block->bxor(tmp, vtil::flags::OF);
    block->bxor(tmp, 1);
    break;
  case ZYDIS_MNEMONIC_JLE: { // zf == 1 or sf != of
    block->mov(tmp, vtil::flags::ZF);

    auto tmp2 = block->tmp(1);
    block->mov(tmp2, vtil::flags::SF);
    block->bxor(tmp2, vtil::flags::OF);

    block->bor(tmp, tmp2);
    break;
  }
  case ZYDIS_MNEMONIC_JNLE: { // ZF == 0 AND SF == OF
    block->mov(tmp, vtil::flags::ZF);
    block->bxor(tmp, 1);

    auto tmp2 = block->tmp(1);
    block->mov(tmp2, vtil::flags::SF);
    block->bxor(tmp2, vtil::flags::OF);
    block->bxor(tmp2, 1);

    block->band(tmp, tmp2);
    break;
  }

  case ZYDIS_MNEMONIC_JCXZ: // cx == 0
    block->te(tmp, vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_CX), 0);
    break;
  case ZYDIS_MNEMONIC_JECXZ: // ecx == 0
    block->te(tmp, vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_ECX), 0);
    break;
  case ZYDIS_MNEMONIC_JRCXZ: // rcx == 0
    block->te(tmp, vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RCX), 0);
    break;

  default:
    break;
  }
  return tmp;
}
