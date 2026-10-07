#include "indirect_jmp.hpp"

// keep a map of what each resolved handler uses for its vip
static std::unordered_map<std::uint32_t, ZydisRegister> vip_regs;
static std::unordered_map<std::uint32_t, ZydisRegister> key_regs;

// what detect_vip actually found, NONE if it never managed to work it out.
static ZydisRegister vip_detected(std::uint32_t bytecode_vip) {
  auto it = vip_regs.find(bytecode_vip);
  return it != vip_regs.end() ? it->second : ZYDIS_REGISTER_NONE;
}
static ZydisRegister vip_reg(std::uint32_t bytecode_vip) {
  auto r = vip_detected(bytecode_vip);
  return r != ZYDIS_REGISTER_NONE ? r : ZYDIS_REGISTER_R11;
}
static ZydisRegister key_reg(std::uint32_t bytecode_vip) {
  auto it = key_regs.find(bytecode_vip);
  return it != key_regs.end() ? it->second : ZYDIS_REGISTER_NONE;
}

struct split {
  std::uint64_t when0;
  std::uint64_t when1;
  vtil::symbolic::expression::reference bit;
};

// over here we'll try and resolve any vm jmps, what this does is it finds both
// outcomes depending on whether the unknown bit is etiher 1 or 0
static std::optional<split>
split_on_bit(const vtil::symbolic::expression::reference &e) {
  vtil::symbolic::expression::reference cc = {};
  e->enumerate([&](const vtil::symbolic::expression &x) {
    if (!cc && !x.is_constant() &&
        ((x.value.unknown_mask() | x.value.known_one()) == 1))
      cc = x;
  });

  if (!cc)
    return std::nullopt;

  auto when0 = e;
  auto when1 = e;

  when0
      .transform([cc](vtil::symbolic::expression::delegate &n) {
        if (n->is_identical(*cc))
          *+n = vtil::symbolic::expression{0, n->size()};
      })
      .simplify();

  when1
      .transform([cc](vtil::symbolic::expression::delegate &n) {
        if (n->is_identical(*cc))
          *+n = vtil::symbolic::expression{1, n->size()};
      })
      .simplify();

  if (when0->is_constant() && when1->is_constant())
    return split{*when0->get<std::uint64_t>(), *when1->get<std::uint64_t>(),
                 cc};

  return std::nullopt;
}

static vtil::basic_block *find_fork_point(vtil::basic_block *block,
                                          const vtil::forward::states &fs) {
  auto r11 = vtil::zydis_to_vtil_reg(
      vip_reg(vtil::from_vip(block->entry_vip).bytecode_vip));
  auto vm_vip = vtil::from_vip(block->entry_vip).bytecode_vip;

  auto is_r11_const = [&](vtil::basic_block *b) {
    auto *s = fs.get(b);
    return s && s->read_register(r11.reg()).simplify()->is_constant();
  };

  vtil::basic_block *curr = block;
  for (;;) {
    if (curr->prev.size() != 1)
      break;
    else if (auto prev = curr->prev[0];
             vtil::from_vip(prev->entry_vip).bytecode_vip != vm_vip ||
             is_r11_const(prev))
      break;

    curr = curr->prev[0];
  }

  auto *s = fs.get(curr);
  return (s && !s->read_register(r11.reg()).simplify()->is_constant())
             ? curr
             : nullptr;
}

static std::optional<std::pair<bool, std::uint64_t>>
resolve_target(vtil::basic_block *blk, pe_aware_tracer &tr,
               const vtil::forward::states &fs) {
  // return a target from operand passed, we'll need to check if it's already a
  // constant - if so we can say it's already folded and if not we'll need to
  // trace it.
  auto &last = blk->back();
  auto op = last.operands[0];
  bool folded = op.is_immediate();
  if (folded)
    return std::make_pair(folded, op.imm().u64);

  // thread this target to our state manager and see if we can resolve any vm
  // forks like embedded vm if statements.
  if (auto *s = fs.get(blk)) {
    auto v = s->read_register(op.reg()).simplify();
    if (v->is_constant()) {
      std::uint64_t raw_val = *v->get<std::uint64_t>();
      spdlog::info("[passes] resolved jmp target to {:x}", raw_val);
      return std::make_pair(false, raw_val);
    }
  }

  // legacy code
  /*

  auto raw = bounded_tracer{tr.pe, 512}.rtrace(
      vtil::symbolic::variable{std::prev(blk->end()), op.reg()});
  auto expr = raw.simplify();

  if (expr->is_constant()) {
    auto val = expr->get<std::uint64_t>();
    spdlog::info("[passes] resolved jmp target to {:x}", *val);
    return std::make_pair(folded, *val);
  } else {
    spdlog::warn("[passes] failed to resolve jmp target, got expr {}",
                 expr->to_string());
  }*/

  return std::nullopt;
}

static std::optional<std::uint64_t>
resolve_vip(vtil::basic_block *blk, pe_aware_tracer &tr, const Pe &pe,
            const vtil::forward::states &fs) {
  // from what we've seen so far, the vip is always stored in r11 regardless of
  // which vm section the handler comes from, what we need to do is just trace
  // whatever value is held in r11 and store that as this current jmp targets
  // vip. each handler can be re-called to produce a different vip. so
  // essentially, when we parse a jmp target we need to figure out what the next
  // target is which revolves around r11. the only time this changes is when
  // we've had to deal with multiple predecessor blocks (forks/merge)
  auto r11 = vtil::zydis_to_vtil_reg(
      vip_reg(vtil::from_vip(blk->entry_vip).bytecode_vip));
  vtil::symbolic::variable var{std::prev(blk->end()), r11.reg()};

  if (auto *s = fs.get(blk)) {
    auto v = s->read_register(r11.reg()).simplify();
    if (v->is_constant()) {
      std::uint64_t raw_val = *v->get<std::uint64_t>();
      std::uint64_t image_base = pe.get_image_base();
      if (raw_val >= image_base && raw_val - image_base < UINT32_MAX)
        return raw_val;
    }
  }

  // legacy code
  /*

  // bounded: when r11 was popped off the vm stack its history is long, and a
  // value that isn't a short trace away isn't a usable vip anyway.
  auto expr = bounded_tracer{pe, 512}.rtrace(var).simplify();
  if (expr->is_constant()) {
    std::uint64_t image_base = pe.get_image_base();
    auto r11_val = expr->get<std::uint64_t>();
    return (*r11_val >= image_base && *r11_val - image_base < UINT32_MAX)
               ? r11_val
               : std::nullopt;
  }*/

  return std::nullopt;
}

static bool is_vmexit(std::uint32_t rva, const Pe &pe) {
  auto rb = pe.get_rva_bytes(rva, 16);
  if (!rb.has_value()) {
    spdlog::error("[passes] failed to read bytes from {:x}", rva);
    return false;
  }

  // when we encounter a vmexit, we're expecting them to restore the stack
  // pointer to whatever it was pre-vmentry
  const auto &b = *rb;
  return rb->size() >= 3 && (b[0] == 0x48 || b[0] == 0x49) && b[1] == 0x8b &&
         (b[2] & 0xf8) == 0xe0;
}

static const vm::profile *resolve_vm_profile(const cfg_fn &cfg,
                                             std::uint32_t rva) {
  // in order to make rtrace not take many years to run on a large set of
  // blocks, we'll need to pin specific registers that we regularly trace upon,
  // the best way to do this right now is to pin these values and to figure out
  // what registers we need to pin, we detect it from the exit type of each
  // block. we split them into "sections" of handlers and they all follow those
  // patterns respective to their section. it appears to go section ->vmexit ->
  // section.
  const auto &blocks = cfg.get_blocks();

  // keep track of what we've seen and work through it in a DFS manner.
  std::unordered_set<std::uint32_t> visited;
  std::vector<std::uint32_t> work{rva};

  while (!work.empty() && visited.size() < 128) {
    std::uint32_t at = work.back();
    work.pop_back();

    if (!visited.insert(at).second)
      continue;

    auto blk = blocks.find(at);
    if (blk == blocks.end())
      continue;

    const auto &instrs = blk->second.instrs;
    if (instrs.empty())
      continue;

    const auto &dispatch = instrs.back();

    for (const auto &prof : vm::profiles()) {
      switch (prof.tail) {
      case vm::dispatch_type::jmp_reg:
        if (dispatch.instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
            dispatch.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            dispatch.operands[0].reg.value == prof.chain) {
          spdlog::info("[passes] dispatched {:x} as vm type {}", rva,
                       prof.name.c_str());
          return &prof;
        }
        break;

      case vm::dispatch_type::push_ret: {
        if (instrs.size() < 2)
          break;

        const auto &prev_instr = instrs[instrs.size() - 2];
        if (prev_instr.instr.mnemonic == ZYDIS_MNEMONIC_PUSH &&
            prev_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            prev_instr.operands[0].reg.value == prof.chain &&
            dispatch.instr.mnemonic == ZYDIS_MNEMONIC_RET) {
          spdlog::info("[passes] dispatched {:x} as vm type {}", rva,
                       prof.name.c_str());
          return &prof;
        }

        break;
      }
      }
    }

    for (auto s : blk->second.successors)
      work.push_back(s);
    if (!instrs.empty() && instrs.back().instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
        instrs.back().operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      ZyanU64 dst = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instrs.back().instr,
                                                &instrs.back().operands[0],
                                                instrs.back().rva, &dst)))
        work.push_back(static_cast<std::uint32_t>(dst));
    }
  }
  spdlog::warn("[passes] could not dispatch {:x} to any known vm type", rva);
  return nullptr;
}

// a handler's pattern can be split across an unconditional jmp (the advance at
// the end of one block, the read at the start of the next), so the detectors
// scan a block's own instructions plus whatever follows it through jmp imm.
// returns the block's instructions followed by up to `extra` more.
static std::vector<const instr_data *>
extended_instrs(const cfg_fn &cfg, std::uint32_t at, std::size_t extra) {
  const auto &blocks = cfg.get_blocks();
  std::vector<const instr_data *> out;

  auto blk = blocks.find(at);
  if (blk == blocks.end())
    return out;
  for (const auto &ins : blk->second.instrs)
    out.push_back(&ins);

  std::size_t added = 0;
  std::unordered_set<std::uint32_t> seen{at};
  while (added < extra && !out.empty()) {
    const auto &last = *out.back();
    if (last.instr.mnemonic != ZYDIS_MNEMONIC_JMP ||
        last.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
      break;

    ZyanU64 dst = 0;
    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&last.instr, &last.operands[0],
                                               last.rva, &dst)))
      break;

    auto next = blocks.find(static_cast<std::uint32_t>(dst));
    if (next == blocks.end() || !seen.insert(next->first).second)
      break;

    for (const auto &ins : next->second.instrs) {
      out.push_back(&ins);
      if (++added >= extra)
        break;
    }
  }

  return out;
}

static ZydisRegister detect_vip(const cfg_fn &cfg, std::uint32_t rva) {
  // so it turns out that not every vm keeps its vip in r11 - two vm instances
  // can dispatch the exact same way but read their bytecode through different
  // registers. every handler advances the vip and then reads the next bytecode
  // through it, so we look for that pattern: add/sub reg, small imm followed
  // shortly by a read of [reg]. whatever reg that is, is this handler's vip. we
  // walk the handler the same way resolve_vm_profile does.
  const auto &blocks = cfg.get_blocks();

  std::unordered_set<std::uint32_t> visited;
  std::vector<std::uint32_t> work{rva};

  // some vm instances read the bytecode first and advance after, so the
  // pattern below never fires for them. remember a reversed-order match and
  // only fall back to it if the normal one never hits.
  ZydisRegister reversed = ZYDIS_REGISTER_NONE;

  while (!work.empty() && visited.size() < 128) {
    std::uint32_t at = work.back();
    work.pop_back();

    if (!visited.insert(at).second)
      continue;

    auto blk = blocks.find(at);
    if (blk == blocks.end())
      continue;

    const auto &instrs = blk->second.instrs;
    const auto ext = extended_instrs(cfg, at, 6);
    for (std::size_t idx = 0; idx < ext.size(); ++idx) {
      const auto &adv = *ext[idx];

      // the advance: add/sub reg64, 1..8
      if (adv.instr.mnemonic != ZYDIS_MNEMONIC_ADD &&
          adv.instr.mnemonic != ZYDIS_MNEMONIC_SUB)
        continue;
      if (adv.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
          adv.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        continue;

      const auto reg = adv.operands[0].reg.value;
      const auto step = adv.operands[1].imm.value.u;
      if (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) != 64 ||
          reg == ZYDIS_REGISTER_RSP || step < 1 || step > 8)
        continue;

      // the read: mov/movzx anything, [reg] within the next few instructions
      for (std::size_t look = idx + 1; look < ext.size() && look <= idx + 6;
           ++look) {
        const auto &rd = *ext[look];
        if (rd.instr.mnemonic != ZYDIS_MNEMONIC_MOV &&
            rd.instr.mnemonic != ZYDIS_MNEMONIC_MOVZX)
          continue;

        const auto &src = rd.operands[1];
        if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.base == reg &&
            src.mem.index == ZYDIS_REGISTER_NONE && src.mem.disp.value == 0) {
          spdlog::info("[passes] vip register for {:x} is {}", rva,
                       ZydisRegisterGetString(reg));
          return reg;
        }
      }

      // the same advance, but with the read before it. a stack pop looks
      // identical except it moves a whole slot, so only count reads narrower
      // than 64 bits - bytecode operands are 1, 2 or 4 bytes.
      if (reversed != ZYDIS_REGISTER_NONE)
        continue;
      for (std::size_t look = 0; look < idx; ++look) {
        const auto &rd = *ext[look];
        if (rd.instr.mnemonic != ZYDIS_MNEMONIC_MOV &&
            rd.instr.mnemonic != ZYDIS_MNEMONIC_MOVZX)
          continue;
        if (rd.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            rd.operands[0].size >= 64)
          continue;

        const auto &rsrc = rd.operands[1];
        if (rsrc.type != ZYDIS_OPERAND_TYPE_MEMORY || rsrc.mem.base != reg ||
            rsrc.mem.index != ZYDIS_REGISTER_NONE || rsrc.mem.disp.value != 0)
          continue;

        // the rolling key also gets advanced and read through, so only accept
        // this if what was read is then decrypted with some other register.
        const auto word = ZydisRegisterGetLargestEnclosing(
            ZYDIS_MACHINE_MODE_LONG_64, rd.operands[0].reg.value);
        for (std::size_t dec_at = look + 1;
             dec_at < ext.size() && dec_at <= look + 12; ++dec_at) {
          const auto &dec = *ext[dec_at];
          if (dec.instr.mnemonic != ZYDIS_MNEMONIC_XOR)
            continue;
          if (dec.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
              dec.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;

          const auto lhs = ZydisRegisterGetLargestEnclosing(
              ZYDIS_MACHINE_MODE_LONG_64, dec.operands[0].reg.value);
          const auto rhs = ZydisRegisterGetLargestEnclosing(
              ZYDIS_MACHINE_MODE_LONG_64, dec.operands[1].reg.value);
          if (lhs != word && rhs != word)
            continue;

          const auto key = lhs == word ? rhs : lhs;
          if (key == word || key == reg || key == ZYDIS_REGISTER_RSP)
            continue;

          reversed = reg;
          break;
        }
        if (reversed != ZYDIS_REGISTER_NONE)
          break;
      }
    }

    for (auto s : blk->second.successors)
      work.push_back(s);
    if (!instrs.empty() && instrs.back().instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
        instrs.back().operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      ZyanU64 dst = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instrs.back().instr,
                                                &instrs.back().operands[0],
                                                instrs.back().rva, &dst)))
        work.push_back(static_cast<std::uint32_t>(dst));
    }
  }

  if (reversed != ZYDIS_REGISTER_NONE) {
    spdlog::info("[passes] vip register for {:x} is {} (read before advance)",
                 rva, ZydisRegisterGetString(reversed));
    return reversed;
  }

  // nothing matched. say so rather than guessing - a wrong guess gets pinned
  // into a register that might be this instance's vm stack.
  return ZYDIS_REGISTER_NONE;
}

// the key register isn't fixed either, and in some vm instances the profile's
// key is actually the vip - pinning both would fight over the same register.
// every handler reads its next bytecode word through the vip and then xors it
// with the rolling key, so we find that read and look for the xor that uses it.
// whatever register it is xored against is this handler's key.
static ZydisRegister detect_key(const cfg_fn &cfg, std::uint32_t rva,
                                ZydisRegister vip) {
  const auto &blocks = cfg.get_blocks();

  // the 64 bit name of a register, so a read into ebx matches an xor on ebx.
  auto widen = [](ZydisRegister reg) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
  };

  std::unordered_set<std::uint32_t> visited;
  std::vector<std::uint32_t> work{rva};

  while (!work.empty() && visited.size() < 128) {
    std::uint32_t at = work.back();
    work.pop_back();

    if (!visited.insert(at).second)
      continue;

    auto blk = blocks.find(at);
    if (blk == blocks.end())
      continue;

    const auto &instrs = blk->second.instrs;
    const auto ext = extended_instrs(cfg, at, 12);
    for (std::size_t idx = 0; idx < instrs.size(); ++idx) {
      const auto &rd = *ext[idx];

      // the bytecode read: mov/movzx reg, [vip]
      if (rd.instr.mnemonic != ZYDIS_MNEMONIC_MOV &&
          rd.instr.mnemonic != ZYDIS_MNEMONIC_MOVZX)
        continue;
      if (rd.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
        continue;

      const auto &src = rd.operands[1];
      if (src.type != ZYDIS_OPERAND_TYPE_MEMORY || src.mem.base != vip ||
          src.mem.index != ZYDIS_REGISTER_NONE || src.mem.disp.value != 0)
        continue;

      const auto word = widen(rd.operands[0].reg.value);

      // the decrypt: xor word, key somewhere after it
      for (std::size_t look = idx + 1; look < ext.size() && look <= idx + 12;
           ++look) {
        const auto &dec = *ext[look];
        if (dec.instr.mnemonic != ZYDIS_MNEMONIC_XOR)
          continue;
        if (dec.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            dec.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
          continue;

        const auto lhs = widen(dec.operands[0].reg.value);
        const auto rhs = widen(dec.operands[1].reg.value);
        if (lhs != word && rhs != word)
          continue;

        const auto key = lhs == word ? rhs : lhs;
        if (key == word || key == widen(vip) || key == ZYDIS_REGISTER_RSP)
          continue;

        spdlog::info("[passes] key register for {:x} is {}", rva,
                     ZydisRegisterGetString(key));
        return key;
      }
    }

    for (auto s : blk->second.successors)
      work.push_back(s);
    if (!instrs.empty() && instrs.back().instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
        instrs.back().operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      ZyanU64 dst = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instrs.back().instr,
                                                &instrs.back().operands[0],
                                                instrs.back().rva, &dst)))
        work.push_back(static_cast<std::uint32_t>(dst));
    }
  }

  // nothing matched, let the caller fall back to the profile's key.
  return ZYDIS_REGISTER_NONE;
}

static void pin_vm_state(vtil::basic_block *new_block, vtil::basic_block *src,
                         pe_aware_tracer &tr, const Pe &pe,
                         const vtil::block_key &bk, const vm::profile *vm,
                         const vtil::forward::states &fs) {
  // as mentioned previously, we'll need to pin important values so our tracer
  // doesn't explode rtracing for it.
  auto it = std::prev(src->end());

  // the current issue with our pinning is that we insert it at the start of the
  // block, there are some very niche times where the handler will hand off to a
  // new vm type MID block so when we insert our pins, we're actually clobbering
  // previous registers before they were assigned. to fix this, we'll just avoid
  // pinning those values if the values conflict, this should be okay because we
  // know that it should hold the value we're going to pin anyway
  bool vip_conflicts = false;
  auto *s = fs.get(src);
  if (s && vip_detected(bk.bytecode_vip) != ZYDIS_REGISTER_NONE) {
    auto vr = vtil::zydis_to_vtil_reg(vip_detected(bk.bytecode_vip));
    auto have = s->read_register(vr.reg()).simplify();
    if (have->is_constant())
      vip_conflicts =
          *have->get<std::uint64_t>() != bk.bytecode_vip + pe.get_image_base();
    else {
      // value isn't concrete, check if it's sp relative
      auto e =
          (have - (s->read_register(vtil::REG_SP) + it->sp_offset)).simplify();
      vip_conflicts = e.is_constant();
    }
  }

  // start by pinning the vip, we used to only see it in r11 but some blocks can
  // resolve differently so we need to figure it out if we've resolved it
  // already
  if (bk.bytecode_vip && !vip_conflicts &&
      vip_detected(bk.bytecode_vip) != ZYDIS_REGISTER_NONE)
    new_block->insert(
        new_block->begin(),
        vtil::instruction{
            &vtil::ins::mov,
            {vtil::zydis_to_vtil_reg(vip_detected(bk.bytecode_vip)),
             vtil::operand{bk.bytecode_vip + pe.get_image_base(), 64}}});

  // now we'll iterate over all the pins from our deduced vm profile and do the
  // same.
  auto pins = vm ? vm->pins() : std::vector{ZYDIS_REGISTER_R8};
  if (auto r = key_reg(bk.bytecode_vip);
      r != ZYDIS_REGISTER_NONE && pins.size() > 1)
    pins[1] = r;

  for (const auto &pin : pins) {
    auto reg = vtil::zydis_to_vtil_reg(pin);
    if (pin == vip_detected(bk.bytecode_vip))
      continue; // already pinned above with the right value
    // use our vm state at any possible chance we can.
    if (s) {

      auto expr = s->read_register(reg.reg()).simplify();
      if (expr->is_constant()) {
        auto val = expr->get<std::uint64_t>();
        new_block->insert(
            new_block->begin(),
            vtil::instruction{&vtil::ins::mov, {reg, vtil::operand(*val, 64)}});
      } else {
        auto sp = (s->read_register(vtil::REG_SP) + it->sp_offset).simplify();
        auto new_expr = (expr - sp).simplify();

        if (new_expr.is_constant()) {
          auto stack_val = new_expr.get<std::int64_t>();
          new_block->insert(
              new_block->begin(),
              vtil::instruction{&vtil::ins::add,
                                {reg, vtil::operand{*stack_val, 64}}});
          new_block->insert(
              new_block->begin(),
              vtil::instruction{&vtil::ins::mov, {reg, vtil::REG_SP}});
        }
      }
    }
    // legacy code
    /*
    // resort back to tracing.
    else {
      // start by tracing the value so we can pin it, these aren't concrete like
      // bytecode_vip, this we'll actually need to find first. this is why it
      // was important to deduce what type of vm it is.

      auto expr = tr.rtrace({it, reg.reg()}).simplify();

      // we need to make sure we've traced it to a constant, if not we'll have
      // to store it a different way.
      if (expr->is_constant()) {
        auto val = expr->get<std::uint64_t>();
        new_block->insert(
            new_block->begin(),
            vtil::instruction{&vtil::ins::mov, {reg, vtil::operand(*val, 64)}});
      } else {
        // this is the part it gets a bit retarded but we'll need to try and see
        // if the value itself might be a sp relative value instead of a
        // constant.
        auto sp = (tr.rtrace({it, vtil::REG_SP}) + it->sp_offset).simplify();
        auto new_expr = (expr - sp).simplify();

        if (new_expr.is_constant()) {
          auto stack_val = new_expr.get<std::int64_t>();
          new_block->insert(
              new_block->begin(),
              vtil::instruction{&vtil::ins::add,
                                {reg, vtil::operand{*stack_val, 64}}});
          new_block->insert(
              new_block->begin(),
              vtil::instruction{&vtil::ins::mov, {reg, vtil::REG_SP}});
        }
      }
    }*/
  }

  tr.flush(new_block);
}

static void unlink(vtil::basic_block *a, vtil::basic_block *b) {
  std::erase(a->next, b);
  std::erase(b->prev, a);
}

std::size_t vtil::passes::resolve_indirects(
    vtil::routine *rtn, cfg_fn &cfg, const Pe &pe, pe_aware_tracer &tr,
    std::unordered_set<std::uint32_t> &exit_vips, vtil::forward::states &fs) {
  std::size_t resolved = 0;
  std::vector<vtil::vip_t> vips;
  for (auto &[vip, _] : rtn->explored_blocks)
    vips.push_back(vip);

  for (auto vip : vips) {
    auto bit = rtn->explored_blocks.find(vip);
    if (bit == rtn->explored_blocks.end())
      continue;
    auto *blk = bit->second.get();
    if (blk->empty())
      continue;

    if (exit_vips.count(vtil::from_vip(vip).bytecode_vip))
      continue;

    auto &last = blk->back();
    if (last.base != &vtil::ins::jmp)
      continue;
    auto it = std::prev(blk->end());

    auto resolve_ret = resolve_target(blk, tr, fs);
    if (!resolve_ret) {
      // typically we cannot resolve this because the expression contains an
      // unknown bit which causes this to fail being resolved.
      auto *b = find_fork_point(blk, fs);
      if (!b)
        continue;

      auto r11 = vtil::zydis_to_vtil_reg(
          vip_reg(vtil::from_vip(blk->entry_vip).bytecode_vip));
      auto vals = split_on_bit(fs.get(b)->read_register(r11.reg()).simplify());
      if (!vals)
        continue;

      spdlog::info("[passes] forked {:x}: vip {:x} / {:x}", b->entry_vip,
                   vals->when0, vals->when1);

      auto *s = b->next[0];
      std::vector<vtil::basic_block *> tail;
      for (auto *x = s;; x = x->next[0]) {
        tail.push_back(x);
        if (x == blk || x->next.size() != 1)
          break;
      }

      auto s_rva = vtil::from_vip(s->entry_vip).rva;
      std::uint64_t sides[2] = {vals->when0, vals->when1};
      vtil::vip_t keys[2] = {};
      std::uint32_t b_vips[2] = {};

      // at first just store all keys and block vips
      for (std::int32_t idx = 0; idx < 2; ++idx) {
        b_vips[idx] =
            static_cast<std::uint32_t>(sides[idx] - pe.get_image_base());
        keys[idx] = vtil::to_vip({.rva = s_rva, .bytecode_vip = b_vips[idx]});
      }

      // check if one of the sides are the existing tail
      int same = keys[0] == s->entry_vip ? 0 : keys[1] == s->entry_vip ? 1 : -1;

      // lift only the blocks who aren't the tail
      bool ok = true;
      for (std::int32_t idx = 0; idx < 2; ++idx) {
        // if it's the index of the key who is the same as the tail or we've
        // already lifted this block then we skip it
        if (idx == same || rtn->explored_blocks.count(keys[idx]))
          continue;

        auto bk = vtil::block_key{.rva = s_rva, .bytecode_vip = b_vips[idx]};
        vtil::lift_pending(rtn, cfg, bk.rva, bk.bytecode_vip);
        if (!rtn->explored_blocks.count(keys[idx])) {
          ok = false;
          break;
        }
        auto vip = detect_vip(cfg, s_rva);
        vip_regs[bk.bytecode_vip] = vip;
        key_regs[bk.bytecode_vip] = detect_key(cfg, s_rva, vip);
        pin_vm_state(rtn->explored_blocks[keys[idx]].get(), b, tr, pe, bk,
                     resolve_vm_profile(cfg, bk.rva), fs);
      }
      if (!ok)
        continue;

      if (same < 0) {
        fs.invalidate(s);
        for (auto *x : tail) {
          fs.dirty.erase(x);
          tr.flush(x);
        }

        unlink(b, s);
        for (std::int32_t idx = 0; idx + 1 < tail.size(); ++idx)
          unlink(tail[idx], tail[idx + 1]);

        for (auto *x : tail)
          rtn->delete_block(x);
      } else {
        s->insert(s->begin(), vtil::instruction{
                                  &vtil::ins::mov,
                                  {r11.reg(), vtil::operand{sides[same], 64}}});
        tr.flush(s);
        fs.invalidate(s);
        unlink(b, s);
      }
      // make it a conditional jmp now
      b->pop_back();
      auto cc = b->tmp(1);
      b->te(cc, r11, vtil::make_imm<std::uint64_t>(vals->when0));
      b->js(cc, keys[0], keys[1]);
      b->fork(keys[0]);
      b->fork(keys[1]);
      tr.flush(b);
      fs.fork_cond[b] = vals->bit;

      for (const auto &k : keys)
        if (auto t = rtn->explored_blocks[k].get();
            t->prev.size() >= 2 && fs.get(t))
          fs.invalidate(t);
      ++resolved;
      continue;
    }

    std::uint64_t target = resolve_ret->second;
    bool folded = resolve_ret->first;
    if (!target)
      continue;

    if (folded && rtn->explored_blocks.count(target))
      continue;

    const auto rva = vtil::from_vip(target).rva;
    auto vip_return = resolve_vip(blk, tr, pe, fs);
    std::uint32_t bytecode_vip =
        vip_return ? *vip_return - pe.get_image_base() : 0;

    if (bytecode_vip)
      spdlog::info("[resolve] parsed vip to be 0x{:x} from rva 0x{:x}",
                   bytecode_vip, rva);

    vtil::block_key bk = {.rva = rva, .bytecode_vip = bytecode_vip};
    const auto key = vtil::to_vip(bk);

    if (!rtn->explored_blocks.count(key)) {
      spdlog::info("[resolve] target 0x{:x}: in_cfg={} lifted={}", rva,
                   cfg.get_blocks().count(rva), cfg.is_lifted(key));

      if (is_vmexit(rva, pe)) {
        spdlog::info("[resolve] vm exit at {:x} (bytecode 0x{:x})", rva,
                     bytecode_vip);
        exit_vips.insert(bytecode_vip);
      }

      if (auto r = cfg.add_root(pdb::pdb_fn{
              .fn_name = "vm_handler", .fn_rva = bk.rva, .fn_size = 0x200});
          !r.has_value())
        spdlog::warn("[resolve] add_root {:x} failed: {}", bk.rva, r.error());

      vtil::lift_pending(rtn, cfg, bk.rva, bk.bytecode_vip);
      if (!rtn->explored_blocks.count(key)) {
        spdlog::warn("[resolve] target {:x} lifted nothing, skipping", rva);
        continue;
      }
      auto vip = detect_vip(cfg, rva);
      vip_regs[bk.bytecode_vip] = vip;
      key_regs[bk.bytecode_vip] = detect_key(cfg, rva, vip);

      auto &new_block = rtn->explored_blocks[key];

      const vm::profile *vmp = resolve_vm_profile(cfg, rva);

      pin_vm_state(new_block.get(), blk, tr, pe, bk, vmp, fs);
    }

    blk->pop_back();
    blk->jmp(key);
    blk->fork(key);
    tr.flush(blk);

    if (auto *t = rtn->explored_blocks[key].get();
        t->prev.size() >= 2 && fs.get(t))
      fs.invalidate(t);

    resolved++;
  }
  return resolved;
}
