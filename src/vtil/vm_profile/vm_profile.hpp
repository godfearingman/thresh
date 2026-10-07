#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "Zydis/Zydis.h"

namespace vm {
enum class dispatch_type { push_ret, jmp_reg };

struct profile {
  std::string name;
  dispatch_type tail;
  ZydisRegister chain;
  ZydisRegister key;
  ZydisRegister vm_stack;
  ZydisRegister vip = ZYDIS_REGISTER_NONE;
  std::vector<ZydisRegister> pins() const { return {vm_stack, key, chain}; }
};
inline const std::vector<profile> &profiles() {
  static const std::vector<profile> v = {
      {"vm1", dispatch_type::push_ret, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R9,
       ZYDIS_REGISTER_R8},
      {"vm2", dispatch_type::push_ret, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RBP,
       ZYDIS_REGISTER_R8},
      {"vm3", dispatch_type::push_ret, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R10,
       ZYDIS_REGISTER_RBX},
      {"vm4", dispatch_type::push_ret, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8,
       ZYDIS_REGISTER_RSI},
      {"vm5", dispatch_type::push_ret, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_RSI,
       ZYDIS_REGISTER_R11},

      {"vm1_jmp", dispatch_type::jmp_reg, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R9,
       ZYDIS_REGISTER_R8},
      {"vm2_jmp", dispatch_type::jmp_reg, ZYDIS_REGISTER_RBX,
       ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8},
      {"vm3_jmp", dispatch_type::jmp_reg, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R10,
       ZYDIS_REGISTER_RBX},
      {"vm4_jmp", dispatch_type::jmp_reg, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_R8,
       ZYDIS_REGISTER_RSI},
      {"vm5_jmp", dispatch_type::jmp_reg, ZYDIS_REGISTER_RDI,
       ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_R11},
  };
  return v;
}
} // namespace vm
