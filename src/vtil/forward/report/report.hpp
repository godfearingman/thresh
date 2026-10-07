#pragma once

#include "../forward.hpp"

#include "spdlog/spdlog.h"

namespace vtil::forward {
void report(const vtil::routine *rtn, const states &fs, const Pe &pe);
} // namespace vtil::forward
