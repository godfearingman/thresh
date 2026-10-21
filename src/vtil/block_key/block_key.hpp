#pragma once
#include "vtil/vtil"

namespace vtil {
struct block_key {
  std::uint32_t rva;
  std::uint32_t bytecode_vip;
  // virtualised code in vmprotect can re-enter the same vm entry so we need to
  // see what entry it belongs to otherwise it will re-use the already lifted
  // entry when it re-enters the said vm entry. by storing what rva of the stub
  // where the vmentry was detected we can then lift it fresh which only becomes
  // relevant to wherever it entered. by default it's 0 which just indicates
  // that it's not entry code
  std::uint32_t entry = 0;
};

inline vtil::vip_t to_vip(block_key k) {
  // we need to see if entry rva exists, if so then we'll replace bytecode_vip
  // with entry as on entry bytecode_vip is 0 anyway. we'll set the msb if
  // needed so these helper functions can determine if we're using vip or entry
  // rva.
  if (k.entry)
    return (1ull << 63) | static_cast<vtil::vip_t>(k.entry) << 32 | k.rva;
  return static_cast<vtil::vip_t>(k.bytecode_vip) << 32 | k.rva;
}
inline block_key from_vip(vtil::vip_t v) {
  if (v >> 63)
    return {.rva = static_cast<std::uint32_t>(v),
            .bytecode_vip = 0, // ensure that we're sending back bytecode vip =
                               // 0 so that other functions know this is entry
            .entry = static_cast<std::uint32_t>(v >> 32) & 0x7FFFFFFF};

  return {.rva = static_cast<std::uint32_t>(v),
          .bytecode_vip = static_cast<std::uint32_t>(v >> 32) & 0xFFFFFF};
}
inline std::uint32_t context_of(vtil::vip_t v) {
  // this will either return the bytecode vip or the entry it came from.
  return static_cast<std::uint32_t>(v >> 32);
}
} // namespace vtil
