#include "mark_exits.hpp"

#include "spdlog/spdlog.h"

std::size_t vtil::passes::mark_exits(vtil::routine *rtn) {
  // currently, vtil treats any block with no successors that doesnt end in a
  // vexit as an improper end which means that it will treat any value within
  // explored blocks to be considered live, that creates an issue because all of
  // our leaf blocks end in a computed jmp thus, DCE and mov propagation do
  // absolutely nothing in this case, what we will do is walk every block and
  // check if it has no successor but ends in a jmp then we remove the jmp and
  // add a vexit instead, thus making it compliant as a completed block. this
  // should only ever be run after every pre-optimisation pass has run which
  // might resolve jmps and what not. NOTE: this pass assumes what it replaces
  // is an actual exit, since we're modeling to recompile which means not emit
  // any vmprotect code, this is """ok""" but is not a faithful view.
  std::size_t result = 0;

  for (auto &[vip, blk] : rtn->explored_blocks) {
    if (!blk->next.empty() || blk->empty() ||
        blk->back().base != &vtil::ins::jmp)
      continue;

    auto op = blk->back().operands[0];
    blk->pop_back();
    blk->vexit(op);
    ++result;
  }

  spdlog::info("[passes] marked {} leaf jmps as routine exits", result);
  return result;
}
