#include "report.hpp"

static void print_inputs(const vtil::symbolic::expression::reference &e,
                         std::set<std::string> &seen, std::int32_t depth) {
  std::vector<vtil::symbolic::variable> vars = {};
  e->enumerate([&vars, &seen](const vtil::symbolic::expression &x) {
    if (!x.is_variable())
      return;
    const auto &var = x.uid.get<vtil::symbolic::variable>();

    if (seen.insert(var.to_string()).second)
      vars.push_back(var);
  });

  for (const auto &var : vars) {
    spdlog::info("{:{}}{} = {}", "", depth * 4, var.to_string(),
                 vtil::forward::describe_var(var));

    if (!var.is_register())
      continue;
    const auto &reg = var.reg();

    if (!reg.is_virtual())
      continue;
    std::uint64_t id = reg.local_id;

    if (id < 0x100000 || depth >= 6)
      continue;

    auto *p = vtil::forward::expr_unk(id);
    if (!p)
      continue;

    print_inputs(*p, seen, depth + 1);
  }
}

void vtil::forward::report(const vtil::routine *rtn, const states &fs,
                           const Pe &pe) {
  for (const auto &[vip, block] : rtn->explored_blocks) {
    if (!block->empty() && block->back().base == &vtil::ins::js) {
      std::set<std::string> seen = {};
      auto *s = fs.get(block.get());
      if (!s) {
        spdlog::warn("[fork] missing state for {:x}", vip);
        continue;
      }

      const auto &js = block->back();
      const auto &targ_1 = js.operands[1];
      const auto &targ_2 = js.operands[2];

      auto cit = fs.fork_cond.find(block.get());
      if (cit == fs.fork_cond.end()) {
        spdlog::info("[fork] {:x}: if <unknown condition> -> {:x} else -> {:x}",
                     vip, targ_1.imm().u64, targ_2.imm().u64);
        continue;
      }

      const auto &c = cit->second;
      spdlog::info("[fork] {:x}: if {} == 0 -> {:x} else -> {:x}", vip,
                   c->to_string(), targ_1.imm().u64, targ_2.imm().u64);
      print_inputs(c, seen, 1);
    }

    if (block->next.empty() && !block->empty() &&
        block->back().base == &vtil::ins::jmp) {
      auto *s = fs.get(block.get());
      if (!s) {
        spdlog::warn("[exit] missing state for {:x}", vip);
        continue;
      }

      const auto &jmp = block->back();
      const auto &op = jmp.operands[0];

      if (op.is_register()) {
        auto targ = s->read_register(op.reg()).simplify();
        auto rax =
            s->read_register(vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_RAX).reg())
                .simplify();
        if (!targ->is_constant()) {

          std::set<std::string> seen;

          if (vtil::forward::is_return(targ))
            spdlog::info("[exit] {:x}: return, rax = {}", vip,
                         rax->to_string());
          else if (never_in_image(targ, pe)) {
            spdlog::info("[exit] {:x} never resolvable in target - tamper "
                         "trap?, rax = {}",
                         vip, rax->to_string());
            continue;
          } else
            spdlog::info("[exit] {:x}: unresolved, target = {}, rax = {}", vip,
                         targ->to_string(), rax->to_string());

          print_inputs(targ, seen, 1);
          print_inputs(rax, seen, 1);
        } else {
          spdlog::warn("[exit] {:x} jmps to {:x} with no succ", vip,
                       *targ->get<std::uint64_t>());
          continue;
        }

      } else if (op.is_immediate()) {
        spdlog::warn("[exit] {:x} jmps to {:x} with no succ", vip,
                     op.imm().u64);
        continue;
      }
    }
  }
}
