#pragma once

#include "Zydis/Zydis.h"
#include "vtil/vtil"

#include "../../../cfg/cfg.hpp"
#include "../../../pe/tracer/tracer.hpp"
#include "../../forward/forward.hpp"
#include "../../regs/regs.hpp"
#include "../../to_vtil.hpp"
#include "../../vm_profile/vm_profile.hpp"

namespace vtil::passes {
std::size_t resolve_indirects(vtil::routine *rtn, cfg_fn &cfg, const Pe &pe,
                              pe_aware_tracer &tr,
                              std::unordered_set<std::uint32_t> &exit_vips,
                              vtil::forward::states &fs);
}
