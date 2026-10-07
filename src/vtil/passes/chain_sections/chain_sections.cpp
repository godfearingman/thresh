#include "chain_sections.hpp"

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

static entry_shape classify_entry(const cfg_fn &cfg, std::uint32_t root) {
  // list of any instructions to look ouit for
  static const std::unordered_set<ZydisMnemonic> not_code = {
      ZYDIS_MNEMONIC_IN,     ZYDIS_MNEMONIC_OUT,   ZYDIS_MNEMONIC_INSB,
      ZYDIS_MNEMONIC_INSD,   ZYDIS_MNEMONIC_OUTSB, ZYDIS_MNEMONIC_OUTSD,
      ZYDIS_MNEMONIC_CLI,    ZYDIS_MNEMONIC_STI,   ZYDIS_MNEMONIC_HLT,
      ZYDIS_MNEMONIC_INT,    ZYDIS_MNEMONIC_INT1,  ZYDIS_MNEMONIC_INT3,
      ZYDIS_MNEMONIC_INTO,   ZYDIS_MNEMONIC_IRETD, ZYDIS_MNEMONIC_IRETQ,
      ZYDIS_MNEMONIC_RDMSR,  ZYDIS_MNEMONIC_WRMSR, ZYDIS_MNEMONIC_INVD,
      ZYDIS_MNEMONIC_WBINVD, ZYDIS_MNEMONIC_LGDT,  ZYDIS_MNEMONIC_LIDT};

  std::vector<std::uint32_t> work{root};
  std::unordered_set<std::uint32_t> seen{root};

  entry_shape shape;
  const auto &blocks = cfg.get_blocks();
  while (!work.empty() && shape.ok()) {
    std::uint32_t rva = work.back();
    work.pop_back();

    auto it = blocks.find(rva);
    if (it == blocks.end())
      continue;

    ++shape.blocks;
    // so far we've seen handlers only jmp to eachother, never seen them jcc
    // from 1 handler to another. if one handler wants to have a different
    // outcome it's typically determined by the bytecode vip and never via an
    // explicit conditional branch.
    if (it->second.term == block_terminator::jcc)
      ++shape.jcc;

    for (const auto &id : it->second.instrs)
      if (not_code.count(id.instr.mnemonic))
        ++shape.bad;

    for (const auto &s : it->second.successors)
      if (seen.insert(s).second)
        work.push_back(s);
  }

  return shape;
}

static std::optional<std::uint64_t>
trace_op(pe_aware_tracer &tr, vtil::il_iterator it, const vtil::operand &op) {
  if (op.is_immediate())
    return op.imm().u64;
  auto expr = tr.rtrace({it, op.reg()}).simplify();
  if (!expr->is_constant())
    return std::nullopt;
  return expr->get<std::uint64_t>();
}

static std::optional<std::monostate>
add_edge(vtil::routine *rtn, vtil::basic_block *b, cfg_fn &cfg,
         pe_aware_tracer &tr, std::uint64_t cand, std::uint64_t image_base) {
  if (cand < image_base) {
    // this is not a section entry, this is just an rva, skip it.
    spdlog::warn("[passes] candidate {:x} is most likely a handler, skipping",
                 cand);
    return std::nullopt;
  }

  std::uint32_t rva = cand - image_base;
  if (!cfg.is_exec(rva)) {
    spdlog::warn("[passes] candidate {:x} is not within image memory, skipping",
                 cand);
    return std::nullopt;
  }

  // lift this as a new vmentry, create a block key for it and send it off to be
  // lited.
  vtil::block_key bk = {.rva = rva, .bytecode_vip = 0};
  vtil::vip_t key = vtil::to_vip(bk);

  if (auto r = cfg.add_root({"vm_entry", rva, 0x200}); !r.has_value())
    spdlog::warn("[passes] add_root {:x} failed: {}", rva, r.error());

  if (auto shape = classify_entry(cfg, rva); !shape.ok()) {
    spdlog::warn("[passes] candidate {:x} isn't a vm entry ({}{} blocks, {} "
                 "jcc, {} bad code), treating it as an exit",
                 rva, shape.blocks > 64 ? ">" : "", shape.blocks, shape.jcc,
                 shape.bad);
    return std::nullopt;
  }

  lift_pending(rtn, cfg, rva, 0);

  if (!rtn->explored_blocks.count(key)) {
    spdlog::warn("[passes] candidate {:x} lifted nothing, discarding", rva);
    return std::nullopt;
  }

  spdlog::info("[passes] chained rva {:x} as a new vm entry", rva);

  // lited, now add it to our vtil map.
  b->pop_back();
  b->jmp(key);
  b->fork(key);
  tr.flush(b);

  return std::monostate{};
}

std::size_t vtil::passes::chain_sections(vtil::routine *rtn, cfg_fn &cfg,
                                         const Pe &pe, pe_aware_tracer &tr,
                                         const vtil::forward::states &fs) {
  std::size_t result = 0;
  // when we're moving from vm sec 1 -> vmexit -> vm sec 2, we need to make sure
  // the stack and everything aligns as we merge them all into one block.
  std::vector<vtil::basic_block *> exits;

  for (const auto &[vip, block] : rtn->explored_blocks) {
    // collect every exit block first
    if (block->next.empty() && !block->empty())
      exits.push_back(block.get());
  }

  // now we need to grab every possible candidate from the exit blocks.
  for (const auto &b : exits) {
    auto it = std::prev(b->end());

    if (it->base == &vtil::ins::jmp) {
      // jmp has one operand and that's the candidate

      // use our vm state whenever we can
      if (auto *s = fs.get(b); s) {
        auto dst = it->operands[0];
        if (dst.is_immediate()) {
          // already constant
          if (add_edge(rtn, b, cfg, tr, dst.imm().u64, pe.get_image_base()))
            result++;
        } else if (dst.is_register()) {
          auto parsed_expr = s->read_register(dst.reg()).simplify();
          if (!parsed_expr->is_constant()) {
            if (vtil::forward::is_return(parsed_expr)) {
              auto rax = s->read_register(
                              vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX).reg())
                             .simplify();
              spdlog::info(
                  "[passes] exit {:x} returns to caller, target = {} rax = {}",
                  b->entry_vip, parsed_expr->to_string(), rax->to_string());
            } else {
              spdlog::info("[passes] exit {:x} unresolved, target = {}",
                           b->entry_vip, parsed_expr->to_string());
            }
            continue;
          }
          if (add_edge(rtn, b, cfg, tr, *parsed_expr->get<std::uint64_t>(),
                       pe.get_image_base()))
            result++;
        }

      }
      // fall back to tracer method
      else {
        auto parsed_expr = trace_op(tr, it, it->operands[0]);
        if (!parsed_expr) {
          spdlog::warn("[passes] failed to parse expr on jmp");
          continue;
        }

        if (add_edge(rtn, b, cfg, tr, *parsed_expr, pe.get_image_base()))
          result++;
      }

    } else if (it->base == &vtil::ins::js) {
      std::vector<std::uint64_t> succs;
      for (std::int32_t idx = 1; idx <= 2; ++idx) {

        if (auto *s = fs.get(b); s) {
          auto dst = it->operands[idx];
          if (dst.is_immediate()) {
            // already constant
            succs.push_back(dst.imm().u64);
          } else if (dst.is_register()) {
            auto parsed_expr = s->read_register(dst.reg()).simplify();
            if (!parsed_expr->is_constant()) {
              if (vtil::forward::is_return(parsed_expr)) {
                auto rax =
                    s->read_register(
                         vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX).reg())
                        .simplify();
                spdlog::info("[passes] exit {:x} returns to caller, target = "
                             "{} rax = {}",
                             b->entry_vip, parsed_expr->to_string(),
                             rax->to_string());
              } else {
                spdlog::info("[passes] exit {:x} unresolved, target = {}",
                             b->entry_vip, parsed_expr->to_string());
              }
              continue;
            }
            succs.push_back(*parsed_expr->get<std::uint64_t>());
          }
        } else {

          auto parsed_expr = trace_op(tr, it, it->operands[idx]);
          if (!parsed_expr) {
            spdlog::warn("[passes] failed to parse expr on js");
            continue;
          }
          succs.push_back(*parsed_expr);
        }
      }
      for (const auto &succ : succs) {
        if (add_edge(rtn, b, cfg, tr, succ, pe.get_image_base())) {
          result++;
          break;
        }
      }
    }
  }

  return result;
}
