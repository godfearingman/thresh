#pragma once

#include <array>
#include <cstdint>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "Zydis/Zydis.h"
#include "spdlog/spdlog.h"

#include "../pdb/pdb.hpp"
#include "../pe/pe.hpp"
#include "../vtil/block_key/block_key.hpp"

#include "vtil/vtil"

// we're going to be using multiple different structures here, one is going to
// describe the basic block which holds all the information about each block of
// code found within the function, then we're going to have one for the function
// which is going to just be the main holder of each parsed function. and
// lastly, our terminator enum which just stores the type of block terminator
// exists, should be useful for later passes.

enum class block_terminator {
  fall_through,
  tail_call,
  jmp,
  jcc,
  ret,
  unk,
  indirect_jmp,
  call
};

struct instr_data {
  std::uint32_t rva;
  ZydisDecodedInstruction instr;
  std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;
  std::array<std::uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> bytes;
};

struct basic_block {
  // store the start of the block as well as the instructions found within
  std::uint32_t block_rva;
  std::vector<instr_data> instrs;

  // from here, we're going need store any successor blocks. typically we're
  // looking at 0-2 successors but jump tables can have multiple successors
  // depending on the index
  std::vector<std::uint32_t> successors;

  // little info about how this block terminated
  block_terminator term;
};

class cfg_fn {
public:
  // in our constructor we'll just take in the info from the pdb parser, our pe
  // file as well as our zydis decoder object
  cfg_fn(pdb::pdb_fn fn_info, const Pe &pe, ZydisDecoder decoder);
  const pdb::pdb_fn &get_fn_info() const;

private:
  std::unordered_set<vtil::vip_t> lifted;

public:
  bool is_lifted(vtil::vip_t vip) const;
  void mark_lifted(vtil::vip_t vip);

private:
  const Pe &pe;
  ZydisDecoder decoder;
  pdb::pdb_fn fn_info;
  std::unordered_map<std::uint32_t, basic_block> blocks;

public:
  // we're going to need to add a method that traverses and decodes from start
  // -> end
  std::expected<std::monostate, std::string> build_blocks();
  const std::unordered_map<std::uint32_t, basic_block> &get_blocks() const;
  void set_terminator(std::uint32_t rva, block_terminator new_term,
                      std::vector<std::uint32_t> successors);
  std::expected<std::monostate, std::string> add_root(const pdb::pdb_fn &fn);
  bool split_at(std::uint32_t rva);
  bool is_exec(std::uint64_t rva) const;
};
