#pragma once

#include "../../vtil/regs/regs.hpp"
#include "../pe.hpp"

#include "Zydis/Zydis.h"
#include "spdlog/spdlog.h"
#include "vtil/vtil"

struct pe_aware_tracer : vtil::cached_tracer {
  const Pe &pe;
  pe_aware_tracer(const Pe &pe) : pe(pe) {};

  static bool mentions_r11(const vtil::symbolic::expression::reference &e) {
    bool found = false;
    e->enumerate([&](const vtil::symbolic::expression &x) {
      if (x.is_variable()) {
        auto &v = x.uid.get<vtil::symbolic::variable>();
        if (v.is_register() &&
            v.reg() == vtil::zydis_to_vtil_reg(ZYDIS_REGISTER_R11).reg())
          found = true;
      }
    });
    return found;
  }

  static bool
  mentions_fake_env(const vtil::symbolic::expression::reference &e) {
    bool found = false;
    e->enumerate([&](const vtil::symbolic::expression &x) {
      if (auto c = x.get<std::uint64_t>())
        if (*c >= fake_env::TEB && *c < fake_env::RT + fake_env::SIZE)
          found = true;
    });
    return found;
  }

  // If `var` reads image memory at a resolvable address, return the value
  // there.
  std::optional<vtil::symbolic::expression::reference>
  read_image(const vtil::symbolic::variable &var) {
    auto local =
        trace_exp(var.mem().base.base).simplify(); // block-local, cheap
    if (!local->is_constant() && !mentions_r11(local) &&
        !mentions_fake_env(local))
      return std::nullopt; // e.g. VM stack via r8: don't chase it
    auto addr = local->is_constant()
                    ? local
                    : rtrace_exp(var.mem().base.base).simplify();
    if (!addr->is_constant())
      return std::nullopt;

    const auto a = *addr->get<std::uint64_t>();
    const auto bits = var.mem().bit_count;

    // gs:-relative reads land in our fake TEB/PEB (see fake_env.hpp)
    if (auto v = fake_env::read(a, bits)) {
      spdlog::info("[env] read {:#x} ({} bits) = {:#x}", a, bits, *v);
      return vtil::symbolic::expression::reference{
          vtil::symbolic::expression{*v, bits}};
    }

    std::uint64_t rva = a;
    std::uint64_t image_base = pe.get_image_base();
    if (rva >= image_base)
      rva -= image_base;
    if (rva > UINT32_MAX)
      return std::nullopt;

    spdlog::info("[trace] mem @ 0x{:x} -> rva 0x{:x}, {} bits",
                 *addr->get<std::uint64_t>(), rva, var.mem().bit_count);

    auto bytes = pe.get_rva_bytes(static_cast<std::uint32_t>(rva),
                                  var.mem().bit_count / 8);
    if (!bytes.has_value()) {
      spdlog::warn("[trace]   get_rva_bytes(0x{:x}) failed", rva);
      return std::nullopt;
    }
    std::uint64_t stored_val = 0;
    std::memcpy(&stored_val, bytes->data(),
                std::min<std::size_t>(bytes->size(), sizeof(stored_val)));
    return vtil::symbolic::expression::reference{
        vtil::symbolic::expression{stored_val, var.mem().bit_count}};
  }

  vtil::symbolic::expression::reference
  trace(const vtil::symbolic::variable &lookup) override {
    // Bytecode read: answer from the image *before* VTIL searches for stores,
    // which would rtrace every VM-stack pointer through the whole history.
    // Sound because the VM never writes its own bytecode.
    if (lookup.is_memory() && mentions_r11(lookup.mem().base.base))
      if (auto v = read_image(lookup))
        return *v;

    auto result = vtil::cached_tracer::trace(lookup);
    if (!result->is_variable())
      return result;
    auto &var = result->uid.get<vtil::symbolic::variable>();
    if (!var.is_memory())
      return result;
    if (auto v = read_image(var))
      return *v;
    return result;
  }
};

// in order to not waste time on expensive rtraces, we can create a bounded
// tracer which will help when we want to find a constant within a short
// history, if it isn't close - we'll bail out.
struct bounded_tracer : pe_aware_tracer {
  std::size_t budget;

  bounded_tracer(const Pe &pe, std::size_t budget)
      :  pe_aware_tracer{pe}, budget(budget) {}

  vtil::symbolic::expression::reference
  trace(const vtil::symbolic::variable &lookup) override {
    if (budget == 0)
      return lookup.to_expression();
    --budget;
    return pe_aware_tracer::trace(lookup);
  }
};
