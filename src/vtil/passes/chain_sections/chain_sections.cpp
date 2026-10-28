#include "chain_sections.hpp"

vtil::passes::entry_shape vtil::passes::classify_entry(const cfg_fn &cfg,
                                                       std::uint32_t root) {
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

  vtil::passes::entry_shape shape;
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
    else if (it->second.term == block_terminator::unk)
      ++shape.bad;

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

// return the (image rva) value stored at [sp] at the exit of a block or none
static std::optional<std::uint32_t>
return_on_stack(const vtil::basic_block *b, const cfg_fn &cfg,
                const vtil::forward::states &fs, const Pe &pe) {
  auto *s = fs.get(b);
  if (!s)
    return std::nullopt;

  const auto &it = std::prev(b->end());

  auto val = (s->read_register(vtil::REG_SP) + it->sp_offset).simplify();
  auto mem = s->read_memory(val, 8);

  if (!mem)
    return std::nullopt;
  mem.simplify();

  if (!mem->is_constant())
    return std::nullopt;

  std::uint64_t img_base = pe.get_image_base();
  std::uint64_t raw_val = *mem->get<std::uint64_t>();

  std::uint64_t rva = raw_val >= img_base ? raw_val - img_base : raw_val;
  if (!cfg.is_exec(rva) || rva >= pe.get_size())
    return std::nullopt;

  return static_cast<std::uint32_t>(rva);
}

// lift native calls, we can tell this by checking if [sp] itself is a vm entry,
// as we know vmprotect will leave its vm and store a vm-entry at [sp] when
// doing a native code call, our job here is just to identify it.
static bool native_call(vtil::routine *rtn, vtil::basic_block *b, cfg_fn &cfg,
                        pe_aware_tracer &tr, vtil::forward::states &fs,
                        std::uint64_t cand, std::uint32_t ret_rva) {

  if (!cfg.add_root({"vm_re_entry", ret_rva, 0x200}).has_value()) {
    spdlog::warn("[passes] failed to add {:x} as re-entry stub", ret_rva);
  }

  // if [sp] is not a vm entry then this isn't a native call
  const auto &entry = vtil::passes::classify_entry(cfg, ret_rva);
  if (!entry.ok())
    return false;

  vtil::lift_pending(rtn, cfg, ret_rva, 0, ret_rva);

  vtil::block_key bk = {.rva = ret_rva, .bytecode_vip = 0, .entry = ret_rva};
  // check it got lifted
  if (!rtn->explored_blocks.count(vtil::to_vip(bk)))
    return false;

  spdlog::info("[passes] lifted native call in {:x} to {:x} resume at {:x}",
               b->entry_vip, cand, ret_rva);

  auto op = b->back().operands[0];

  // remove the jmp instruction so we can replace it with a call
  b->pop_back();

  // since retaddr is stored at [sp] we know for sure the vm handled the push
  // for us, all we have to do here is make sure we have a matching pop for it.
  // we have no idea what happens in the vxcall but we need to make sure, since
  // we didn't push, that we know it at least has its matching pair. vxcall
  // doesn't handle it itself because the push happened outside of it which is
  // why we do it ourselves.
  b->shift_sp(8);

  // le call
  b->vxcall(op);
  b->fork(vtil::to_vip(bk));
  tr.flush(b);
  fs.invalidate(b);

  return true;
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
  vtil::block_key bk = {.rva = rva, .bytecode_vip = 0, .entry = rva};
  vtil::vip_t key = vtil::to_vip(bk);

  if (auto r = cfg.add_root({"vm_entry", rva, 0x200}); !r.has_value())
    spdlog::warn("[passes] add_root {:x} failed: {}", rva, r.error());

  if (auto shape = vtil::passes::classify_entry(cfg, rva); !shape.ok()) {
    spdlog::warn("[passes] candidate {:x} isn't a vm entry ({}{} blocks, {} "
                 "jcc, {} bad code), treating it as an exit",
                 rva, shape.blocks > 64 ? ">" : "", shape.blocks, shape.jcc,
                 shape.bad);
    return std::nullopt;
  }

  lift_pending(rtn, cfg, rva, 0, rva);

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

// some compiled functions in static don't have enough data in them for
// classify_entry to mark it as not a vm entry function, we do see that
// basically all the vmentry have a pushfq mnemonic within the first 8
// instructions. this function will see if it finds that. the other side of the
// test would be checking if it's in .text which obviously just is where we're
// going to find compiled code.
static bool compiled_function(const Pe &pe, std::uint32_t rva) {

  bool in_text = false;
  for (const auto &sec : pe.get_sections()) {
    const auto &h = sec.header;
    if (in_text)
      break;
    in_text = !std::strncmp(reinterpret_cast<const char *>(h->Name), ".text",
                            IMAGE_SIZEOF_SHORT_NAME) &&
              (rva >= h->VirtualAddress &&
               rva < (h->VirtualAddress + h->Misc.VirtualSize));
  }

  if (!in_text)
    return false;

  ZydisDecoder dec;
  ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  if (in_text) {
    for (std::int8_t idx = 0; idx < 8; ++idx) {
      auto b = pe.get_rva_bytes(rva, ZYDIS_MAX_INSTRUCTION_LENGTH);
      if (!b.has_value())
        return false;

      ZydisDecodedInstruction ins;
      std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops;
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, b->data(), b->size(), &ins,
                                               ops.data())))
        return false;

      if (ins.mnemonic == ZYDIS_MNEMONIC_PUSHFQ)
        return false;
      else if (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
               ins.meta.category == ZYDIS_CATEGORY_RET)
        break;

      rva += ins.length;
    }
  }

  return true;
}

std::size_t vtil::passes::chain_sections(vtil::routine *rtn, cfg_fn &cfg,
                                         const Pe &pe, pe_aware_tracer &tr,
                                         vtil::forward::states &fs) {
  std::size_t result = 0;

  // handle any hand off, that goes for any native calls or vm handoffs, they
  // are now handled hjere.
  auto take = [&](vtil::basic_block *block, std::uint64_t cand) {
    const std::uint64_t img_base = pe.get_image_base();
    auto ret = return_on_stack(block, cfg, fs, pe);
    spdlog::info("[passes] exit at {:x} to {:x}, [sp] = {}", block->entry_vip,
                 cand, ret ? std::format("{:x}", *ret) : "none");

    bool callable = ret && cand >= img_base && cfg.is_exec(cand - img_base);

    // first we check if it's a compiled function within .text that appears
    // callable
    if (callable && compiled_function(pe, cand - img_base) &&
        native_call(rtn, block, cfg, tr, fs, cand, *ret))
      return true;

    // next we see if it's just a vm hand off so we can handle business as
    // usual, this is what we previously had on its own essentially.
    else if (add_edge(rtn, block, cfg, tr, cand, img_base))
      return true;

    // if both checks fail, we check if it's at least callable and send it off
    // as one.
    return callable && native_call(rtn, block, cfg, tr, fs, cand, *ret);
  };

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
          if (take(b, dst.imm().u64))
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
          if (take(b, *parsed_expr->get<std::uint64_t>()))
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
