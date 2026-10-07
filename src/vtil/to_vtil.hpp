#pragma once

#include "spdlog/spdlog.h"

#include "../cfg/cfg.hpp"
#include "block_key/block_key.hpp"
#include "jcc/jcc.hpp"
#include "lift/lift.hpp"

namespace vtil {
vtil::routine *to_vtil(cfg_fn &cfg);
std::size_t lift_pending(vtil::routine *rtn, cfg_fn &cfg, std::uint32_t root,
                         std::uint32_t bytecode_vip);
} // namespace vtil
