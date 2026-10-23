#pragma once

#include <algorithm>

#include "Zydis/Zydis.h"
#include "spdlog/spdlog.h"
#include "vtil/vtil"

#include "../../../vtil/forward/forward.hpp"

#include "../../../cfg/cfg.hpp"
#include "../../../pe/tracer/tracer.hpp"

namespace vtil::passes {
std::size_t collapse_stack_checks(vtil::routine *rtn, const cfg_fn &cfg,
                                  pe_aware_tracer &tr,
                                  vtil::forward::states &fs);
}
