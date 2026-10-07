#pragma once

#include "vtil/vtil"

#include "../../../pe/tracer/tracer.hpp"
#include "../../block_key/block_key.hpp"

namespace vtil::passes {
std::size_t fold_stack_align(vtil::routine *rtn, pe_aware_tracer &tr);
}
