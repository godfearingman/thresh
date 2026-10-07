#pragma once

#include "vtil/vtil"

#include "../../../cfg/cfg.hpp"
#include "../../../pe/tracer/tracer.hpp"
#include "../../forward/forward.hpp"
#include "../../to_vtil.hpp"

namespace vtil::passes {
std::size_t chain_sections(vtil::routine *rtn, cfg_fn &cfg, const Pe &pe,
                           pe_aware_tracer &tr, const vtil::forward::states &fs);
}
