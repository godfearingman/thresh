#pragma once 
#include "vtil/vtil"

#include "../../../pe/tracer/tracer.hpp"

namespace vtil::passes {
std::size_t fold_redundant_forks(vtil::routine *rtn, pe_aware_tracer &tr);
}
