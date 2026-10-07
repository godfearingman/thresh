#pragma once

#include "vtil/vtil"

#include "../../../pe/tracer/tracer.hpp"

namespace vtil::passes {
std::size_t dead_stack_removal(vtil::routine *rtn, pe_aware_tracer &tr);
}
