#pragma once

#include "Zydis/Zydis.h"
#include "spdlog/spdlog.h"
#include "vtil/vtil"

#include "../../pe/fake_mem/fake_mem.hpp"
#include "../../pe/pe.hpp"
#include "../../vtil/regs/regs.hpp"

namespace vtil::forward {
// overrides to allow our symbolic vm to access the pe fully.
struct forward_vm : vtil::symbolic_vm {
  const Pe *pe = nullptr;
  static constexpr std::size_t max_depth = 12;
  std::string site;

  vtil::symbolic::expression::reference
  read_memory(const vtil::symbolic::expression::reference &ptr,
              std::size_t bytes) const override;

  void write_register(const vtil::register_desc &reg,
                      vtil::symbolic::expression::reference value) override;

  bool write_memory(
      const vtil::symbolic::expression::reference &ptr,
      vtil::deferred_value<vtil::symbolic::expression::reference> value,
      bitcnt_t size) override;
};

// store vm states that track the state of each block, this'll be useful for
// continously storing information that vmprotect will query like TF.
struct states {
  // the symbolic state at the end of any lifted block.
  std::unordered_map<const vtil::basic_block *, vtil::symbolic_vm> at_end;

  // any blocks that are started from a fresh entry state instead of a
  // predecessors end
  std::unordered_set<const vtil::basic_block *> entries;

  // entries that were dropped but still exist, we need to recompute these later
  // on even though they aren't fresh
  std::unordered_set<const vtil::basic_block *> dirty;

  // what is needed for branch joining, this is where we merge our forks.
  std::unordered_map<const vtil::basic_block *, std::string> join_sig;
  std::map<std::string, vtil::symbolic::expression::reference> join_unk;

  // store il expression of fork condition so we can output it later
  std::unordered_map<const vtil::basic_block *,
                     vtil::symbolic::expression::reference>
      fork_cond;

  // this will record any information about jmps whose targets were resolved
  // through its register. we need to store this information so that if we need
  // to query it later when the state changes we can see what path taken to
  // resolve the jmp was. without it, all we'll see is the jmp imm
  struct res {
    vtil::operand op;
    std::uint64_t targ;
    vtil::register_desc vip_reg;
    std::optional<std::uint64_t> vip;
    vtil::vip_t key;
  };
  std::unordered_map<const vtil::basic_block *, res> resolved;
  std::unordered_map<const vtil::basic_block *, std::uint64_t> end_hash;
  std::unordered_set<const vtil::basic_block *> changed;

  const vtil::symbolic_vm *get(const vtil::basic_block *block) const;
  void invalidate(const vtil::basic_block *block);
  void forget(const vtil::basic_block *block);
};

bool never_in_image(const vtil::symbolic::expression::reference &targ,
                    const Pe &pe);

std::string describe_var(const vtil::symbolic::variable &v);

bool is_return(const vtil::symbolic::expression_reference &e);

const std::string *describe_unk(std::uint64_t id);
const vtil::symbolic::expression::reference *expr_unk(std::uint64_t id);

vtil::symbolic_vm entry_state();

std::size_t run(const std::vector<vtil::basic_block *> &blocks, states &fs,
                const Pe &pe);

std::size_t fold_loads(vtil::routine *rtn, states &fs, const Pe &pe);
vtil::symbolic::expression::reference
value_before(vtil::basic_block *block, vtil::il_const_iterator it,
             const vtil::register_desc &reg, states &fs, const Pe &pe);
} // namespace vtil::forward
