#pragma once
#include "vtil/vtil"

namespace vtil {
struct block_key {
  std::uint32_t rva;
  std::uint32_t bytecode_vip;
};

inline vtil::vip_t to_vip(block_key k) {
  return static_cast<vtil::vip_t>(k.bytecode_vip) << 32 | k.rva;
}
inline block_key from_vip(vtil::vip_t v) {
  return {.rva = static_cast<std::uint32_t>(v),
          .bytecode_vip = static_cast<std::uint32_t>(v >> 32) & 0xFFFFFF};
}
} // namespace vtil
