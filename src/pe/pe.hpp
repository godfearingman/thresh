#pragma once

#include <Windows.h>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>
#include <winnt.h>

// #include "section.h"

struct Section {
  IMAGE_SECTION_HEADER *header{};
  // WARNING: this must always point to an allocated PE section.
  std::span<const std::uint8_t> data{};
};

class Pe {
  IMAGE_NT_HEADERS64 *nt_header{};

  /// These are the raw bytes of the PE file on disk.
  std::vector<std::uint8_t> bytes;

  /// The name of the binary, used for differentiation.
  const std::string name{};

  /// The base address of the PE (its assigned allocation).
  std::uint64_t base_address{};

public:
  /// This represents a 'virtual' mapped PE file.
  ///
  /// What this is, is a temporary buffer where we'll map in the
  /// PE image, then this buffer gets copied verbatim into our target
  /// allocation. Every "mapped image" gets mapped into this buffer and then
  /// copied into the remote buffer.
  std::vector<std::uint8_t> mapped_buffer{};

public:
  // Returns the local image name
  std::string get_image_name();
  /// Returns the address of the raw image data on 'disk'.
  std::uint64_t get_raw_data() const;
  const std::vector<std::uint8_t> &get_data() const;
  /// Gets the address of the local image, a.k.a our mapped buffer.
  std::uint64_t get_raw_virtual_image() const;
  /// Sets the allocated base address for the pe file.
  void set_base_address(std::uint64_t address);
  /// Gets the allocated base address for the pe file.
  /// NOTE: this must be set before it can be called.
  std::expected<std::uint64_t, std::string> get_base_address() const;
  std::uint64_t get_size() const;
  IMAGE_NT_HEADERS64 *get_nt_header() const;
  std::vector<Section> get_sections() const;

  std::expected<std::uint32_t, std::string>
  rva_to_file_offset(std::uint32_t rva) const;

  std::expected<std::span<const std::uint8_t>, std::string>
  get_rva_bytes(std::uint32_t rva, std::uint32_t size) const;

  std::uint64_t get_image_base() const;

  Pe(std::vector<std::uint8_t> &bytes, const std::string &name);

private:
  // std::expected<std::monostate, std::string> store_sections(bool with_data);
};
