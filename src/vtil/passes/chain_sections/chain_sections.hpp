#pragma once

#include <cstring>

#include "vtil/vtil"

#include "../../../cfg/cfg.hpp"
#include "../../../pe/tracer/tracer.hpp"
#include "../../forward/forward.hpp"
#include "../../to_vtil.hpp"

namespace vtil::passes {
std::size_t chain_sections(vtil::routine *rtn, cfg_fn &cfg, const Pe &pe,
                           pe_aware_tracer &tr, vtil::forward::states &fs);
// when chain_section resolves a vmexit, the target isn't always going to be
// another vm entry. when we resolved GetVer it had a clean exit into a constant
// but for Init, we return back to native code. This is an issue because we
// cannot treat non-virtualised code as virtualised which means we'll be blowing
// up vtil's path cache by just lifting all those random instructions, jccs and
// calls by treating it as virtualised code. we'll set a threshhold for what we
// encounter and see if we can classify it as vm code or native code.
struct entry_shape {
  std::size_t blocks = 0, jcc = 0, bad = 0;
  // less than or equal to 64 blocks from root and no conditional branches as
  // well as no bad instructions like cli.
  bool ok() const { return blocks <= 64 && !jcc && !bad; };
};

entry_shape classify_entry(const cfg_fn &cfg, std::uint32_t root);
} // namespace vtil::passes
