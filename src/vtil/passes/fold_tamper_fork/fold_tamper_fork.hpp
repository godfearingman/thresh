#pragma once

#include "vtil/vtil"

#include "../../../pe/pe.hpp"
#include "../../../pe/tracer/tracer.hpp"
#include "../../forward/forward.hpp"

namespace vtil::passes {
std::size_t fold_tamper_forks(vtil::routine *rtn, pe_aware_tracer &tr,
                              const Pe &pe);
}
