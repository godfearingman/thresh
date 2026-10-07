#include "cfg.hpp"

cfg_fn::cfg_fn(pdb::pdb_fn fn_info, const Pe &pe, ZydisDecoder decoder)
    : fn_info(fn_info), pe(pe), decoder(decoder) {};

const pdb::pdb_fn &cfg_fn::get_fn_info() const { return fn_info; }

const std::unordered_map<std::uint32_t, basic_block> &
cfg_fn::get_blocks() const {
  return blocks;
}
std::expected<std::monostate, std::string> cfg_fn::build_blocks() {
  auto in_fn = [&](std::uint64_t t) {
    return t >= fn_info.fn_rva && t < fn_info.fn_rva + fn_info.fn_size;
  };

  std::deque<std::uint32_t> work{fn_info.fn_rva};

  while (!work.empty()) {
    std::uint32_t leader = work.front();
    work.pop_front();
    if (blocks.contains(leader))
      continue;
    if (split_at(leader))
      continue;

    basic_block b{.block_rva = leader, .term = block_terminator::unk};
    std::uint32_t cur = leader;
    spdlog::info("[walk] start 0x{:x} is_exec={}", cur, is_exec(cur));

    while (is_exec(cur)) {
      auto bytes = pe.get_rva_bytes(cur, ZYDIS_MAX_INSTRUCTION_LENGTH);
      for (std::uint32_t n = ZYDIS_MAX_INSTRUCTION_LENGTH - 1; !bytes && n > 0;
           --n)
        bytes = pe.get_rva_bytes(cur, n);
      if (!bytes) {
        spdlog::warn("[walk] 0x{:x}: get_rva_bytes failed", cur);
        break;
      }
      ZydisDecodedInstruction instr;
      std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops;
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
              &decoder, bytes->data(), bytes->size(), &instr, ops.data()))) {
        break;
        spdlog::warn("[walk] 0x{:x}: decode failed ({} bytes: {:02x} {:02x} "
                     "{:02x} {:02x})",
                     cur, bytes->size(), (*bytes)[0], (*bytes)[1], (*bytes)[2],
                     (*bytes)[3]);
        break;
      }
      instr_data id{.rva = cur, .instr = instr, .operands = ops};
      std::memcpy(id.bytes.data(), bytes->data(), instr.length);
      b.instrs.push_back(id);

      std::uint32_t next = cur + instr.length;

      switch (instr.meta.category) {
      case ZYDIS_CATEGORY_UNCOND_BR:
        if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
          std::uint64_t t = 0;
          ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);
          b.term =
              in_fn(t) ? block_terminator::jmp : block_terminator::tail_call;
          if (is_exec(t))
            b.successors.push_back((std::uint32_t)t); // follow it either way
        } else {
          b.term = block_terminator::indirect_jmp;
        }
        goto done;

      case ZYDIS_CATEGORY_COND_BR: {
        std::uint64_t t = 0;
        ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);
        b.term = block_terminator::jcc;
        if (is_exec(t))
          b.successors.push_back((std::uint32_t)t);
        if (is_exec(next))
          b.successors.push_back(next);
        goto done;
      }

      case ZYDIS_CATEGORY_CALL:
        if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
          std::uint64_t t = 0;
          ZydisCalcAbsoluteAddress(&instr, &ops[0], cur, &t);
          if (is_exec(t)) {
            b.term = block_terminator::call;
            b.successors.push_back((std::uint32_t)t);
            goto done;
          }
        }
        break;

      case ZYDIS_CATEGORY_RET:
        b.term = block_terminator::ret;
        goto done;

      default:
        break;
      }

      if (blocks.contains(next)) {
        b.term = block_terminator::fall_through;
        b.successors.push_back(next);
        goto done;
      }
      cur = next;
    }
  done:
    if (b.instrs.empty())
      continue;
    for (auto s : b.successors)
      work.push_back(s);
    blocks[leader] = std::move(b);
  }
  return std::monostate{};
}
bool cfg_fn::split_at(std::uint32_t rva) {
  for (auto &[brva, b] : blocks) {
    for (std::size_t i = 1; i < b.instrs.size(); ++i) {
      if (b.instrs[i].rva != rva)
        continue;
      basic_block tail{.block_rva = rva,
                       .instrs = {b.instrs.begin() + i, b.instrs.end()},
                       .successors = std::move(b.successors),
                       .term = b.term};
      b.instrs.resize(i);
      b.successors = {rva};
      b.term = block_terminator::fall_through;
      blocks[rva] = std::move(tail);
      return true;
    }
  }
  return false;
}
bool cfg_fn::is_exec(std::uint64_t rva) const {
  for (const auto &sec : pe.get_sections()) {
    const auto *h = sec.header;
    if (!(h->Characteristics & IMAGE_SCN_MEM_EXECUTE))
      continue;
    if (rva >= h->VirtualAddress &&
        rva < h->VirtualAddress + h->Misc.VirtualSize)
      return true;
  }
  return false;
}

void cfg_fn::set_terminator(std::uint32_t rva, block_terminator term,
                            std::vector<std::uint32_t> successors) {
  auto it = blocks.find(rva);
  if (it == blocks.end())
    return;
  it->second.term = term;
  it->second.successors = std::move(successors);
}

std::expected<std::monostate, std::string>
cfg_fn::add_root(const pdb::pdb_fn &new_fn) {
  if (blocks.count(new_fn.fn_rva))
    return std::monostate{};

  auto saved = fn_info;
  fn_info = new_fn;
  auto r = build_blocks();
  fn_info = saved;
  return r;
}

bool cfg_fn::is_lifted(vtil::vip_t vip) const { return lifted.count(vip) != 0; }
void cfg_fn::mark_lifted(vtil::vip_t vip) { lifted.insert(vip); }
