#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace fake_env {
inline constexpr std::uint64_t TEB = 0x7FF000000000;
inline constexpr std::uint64_t PEB = 0x7FF000010000;
inline constexpr std::uint64_t HEAP = 0x7FF000020000;
inline constexpr std::uint64_t RT = 0x7FF000030000; // VMProtect runtime data
inline constexpr std::uint64_t SIZE = 0x10000;
inline constexpr std::uint64_t RT_PTR = 0x1800A1910; // .be0 global -> RT

struct region {
  std::uint64_t base;
  const char *name;
  bool strict;
  std::vector<std::uint8_t> bytes = std::vector<std::uint8_t>(SIZE, 0);
  std::vector<bool> known = std::vector<bool>(SIZE, false);

  template <class T> void put(std::size_t off, T v) {
    std::memcpy(bytes.data() + off, &v, sizeof v);
    std::fill_n(known.begin() + off, sizeof v, true);
  }

  bool has(std::uint64_t addr, std::size_t n) const {
    return addr >= base && addr - base + n <= SIZE;
  }

  bool is_known(std::uint64_t addr, std::size_t n) const {
    auto first = known.begin() + static_cast<std::ptrdiff_t>(addr - base);
    return std::all_of(first, first + static_cast<std::ptrdiff_t>(n),
                       [](bool k) { return k; });
  }
};

inline const std::vector<region> &regions() {
  static const std::vector<region> r = [] {
    region teb{TEB, "TEB", false}, peb{PEB, "PEB", false},
        heap{HEAP, "HEAP", false}, rt{RT, "RT", true};

    teb.put(0x30, TEB); // NtTib.Self
    teb.put(0x60, PEB); // ProcessEnvironmentBlock

    peb.put(0x02, std::uint8_t{0});       // BeingDebugged
    peb.put(0x30, HEAP);                  // ProcessHeap
    peb.put(0xBC, std::uint32_t{0});      // NtGlobalFlag
    peb.put(0x118, std::uint32_t{10});    // OSMajorVersion
    peb.put(0x11C, std::uint32_t{0});     // OSMinorVersion
    peb.put(0x120, std::uint16_t{22631}); // OSBuildNumber (Windows 11 23H2)
    peb.put(0x124, std::uint32_t{2}); // OSPlatformId = VER_PLATFORM_WIN32_NT

    heap.put(0x70, std::uint32_t{2}); // Flags = HEAP_GROWABLE
    heap.put(0x74, std::uint32_t{0}); // ForceFlags

    rt.put(0x20, std::uint32_t{0x354440d7}); // loader-finished marker
    rt.put(0x58, std::uint64_t{0x63CF253C459A33C0});
    rt.put(0x80, std::uint32_t{0x9173573}); // encoded OSBuildNumber 22631

    return std::vector<region>{teb, peb, heap, rt};
  }();
  return r;
}

inline bool contains(std::uint64_t addr) {
  return std::ranges::any_of(regions(),
                             [&](const region &r) { return r.has(addr, 1); });
}

inline std::optional<std::string> name(std::uint64_t addr) {
  if (addr == RT_PTR)
    return "RT_PTR";
  for (const auto &r : regions())
    if (r.has(addr, 1))
      return std::format("{}+{:#x}", r.name, addr - r.base);
  return std::nullopt;
}

inline std::optional<std::uint64_t> read(std::uint64_t addr, unsigned bits) {
  if (addr == RT_PTR && bits == 64)
    return RT;

  const std::size_t n = bits / 8;
  if (n == 0 || n > sizeof(std::uint64_t))
    return std::nullopt;

  for (const auto &r : regions()) {
    if (!r.has(addr, n))
      continue;
    if (r.strict && !r.is_known(addr, n))
      return std::nullopt;

    std::uint64_t v = 0;
    std::memcpy(&v, r.bytes.data() + (addr - r.base), n);
    return v;
  }
  return std::nullopt;
}
} // namespace fake_env
