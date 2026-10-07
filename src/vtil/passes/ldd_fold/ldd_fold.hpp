#pragma once

#include "Zydis/Zydis.h"
#include "vtil/vtil"

#include "../../../cfg/cfg.hpp"
#include "../../../pe/tracer/tracer.hpp"
#include "../../regs/regs.hpp"
#include "../../to_vtil.hpp"

namespace vtil::passes {
std::size_t fold_ldd(const std::vector<vtil::basic_block *> &blocks,
                     pe_aware_tracer &tr);
}
