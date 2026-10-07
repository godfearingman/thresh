#pragma once

#include "Zydis/Zydis.h"
#include "vtil/vtil"
#include "../../pe/fake_mem/fake_mem.hpp"

namespace vtil {
x86_reg zydis_to_capstone(ZydisRegister reg);
vtil::operand zydis_to_vtil_reg(ZydisRegister reg);
vtil::register_desc get_disp_from_operand(vtil::basic_block *block,
                                          const ZydisDecodedOperand &op);
vtil::operand load_operand(vtil::basic_block *block,
                           const ZydisDecodedInstruction &instr,
                           const ZydisDecodedOperand *ops, std::size_t idx);
void store_operand(vtil::basic_block *block,
                   const ZydisDecodedInstruction &instr,
                   const ZydisDecodedOperand *ops, std::size_t idx,
                   const vtil::operand &src);
} // namespace vtil
