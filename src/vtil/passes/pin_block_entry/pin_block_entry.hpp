#pragma once

#include <map>

#include "vtil/vtil"

#include "../../../pe/tracer/tracer.hpp"
#include "../../regs/regs.hpp"

namespace vtil::passes {
std::size_t pin_block_entry(const std::vector<vtil::basic_block *> &blocks,
                            pe_aware_tracer &tr);
}
