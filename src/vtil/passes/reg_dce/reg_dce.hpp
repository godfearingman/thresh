#pragma once

#include <deque>

#include "spdlog/spdlog.h"
#include "vtil/vtil"

namespace vtil::passes {
std::size_t reg_dce(vtil::routine *rtn);
}
