#pragma once

#include "../handlers/handlers.hpp"
#include "flags.hpp"

namespace vtil {
using handler_fn =
    std::function<void(vtil::basic_block *, const ZydisDecodedInstruction &,
                       const ZydisDecodedOperand *)>;
using handler_map_t = std::unordered_map<ZydisMnemonic, handler_fn>;

void print_unhandled();

void lift_instr(vtil::basic_block *block, std::uint64_t vip,
                const ZydisDecodedInstruction &instr,
                const ZydisDecodedOperand *ops, const std::uint8_t *raw_bytes);

} // namespace vtil
