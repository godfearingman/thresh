#include "pe.hpp"
#include <processthreadsapi.h>
#include <winuser.h>

// NOTE: Turn this into a factory method, it could fail.
Pe::Pe(std::vector<std::uint8_t> &bytes, const std::string &name)
    : bytes{bytes}, name{name} {
  // parse the dos header from the provided bytes.
  auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(bytes.data());
  // parse the nt header from the provided bytes.
  auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS64 *>(bytes.data() +
                                                          dos_header->e_lfanew);

  this->nt_header = nt_header;

  // WARNING: this could fail, if our pe file is not an actual pe file.
  this->mapped_buffer.resize(nt_header->OptionalHeader.SizeOfImage);
}

IMAGE_NT_HEADERS64 *Pe::get_nt_header() const { return this->nt_header; }

std::uint64_t Pe::get_raw_data() const {
  return reinterpret_cast<std::uintptr_t>(this->bytes.data());
}

const std::vector<std::uint8_t> &Pe::get_data() const { return this->bytes; }

std::uint64_t Pe::get_raw_virtual_image() const {
  return reinterpret_cast<std::uint64_t>(this->mapped_buffer.data());
}

void Pe::set_base_address(std::uint64_t address) {
  this->base_address = address;
}

std::expected<std::uint64_t, std::string> Pe::get_base_address() const {
  // NOTE: should properly handle error this case.
  if (!this->base_address)
    return std::unexpected("base address not set.");

  return this->base_address;
}

std::uint64_t Pe::get_size() const {
  return this->nt_header->OptionalHeader.SizeOfImage;
}

std::vector<Section> Pe::get_sections() const {
  // this is where we'll hold all the sections.
  std::vector<Section> sections{};

  // get a pointer to the optional header, specifically byte sized for pointer
  // offsetting.
  std::uint8_t *optional_header =
      reinterpret_cast<std::uint8_t *>(&this->get_nt_header()->OptionalHeader);

  // get the section header by adding the size of the optional header to the
  // file location of the optional header.
  auto section_header = reinterpret_cast<IMAGE_SECTION_HEADER *>(
      optional_header + get_nt_header()->FileHeader.SizeOfOptionalHeader);

  // iterate through every section in the pe file.
  for (auto section = 0; section < get_nt_header()->FileHeader.NumberOfSections;
       section++) {
    // get a pointer to the section data.
    auto section_data =
        this->bytes.data() + section_header[section].PointerToRawData;
    // create a span of the target section data.
    std::span<const std::uint8_t> data(section_data,
                                       section_header[section].SizeOfRawData);

    sections.emplace_back(&section_header[section], data);
  }

  return sections;
}

std::expected<std::uint32_t, std::string>
Pe::rva_to_file_offset(std::uint32_t rva) const {
  for (const auto &sec : get_sections()) {
    const auto &header = sec.header;
    if (rva >= header->VirtualAddress &&
        rva < header->VirtualAddress + header->Misc.VirtualSize)
      return header->PointerToRawData + (rva - header->VirtualAddress);
  }

  return std::unexpected("failed to find rva within any binary section.");
}

std::expected<std::span<const std::uint8_t>, std::string>
Pe::get_rva_bytes(std::uint32_t rva, std::uint32_t size) const {
  auto file_offset = rva_to_file_offset(rva);
  if (!file_offset.has_value())
    return std::unexpected(file_offset.error());
  else if (*file_offset + size > bytes.size())
    return std::unexpected("invalid rva.");

  return std::span<const std::uint8_t>(bytes.data() + *file_offset, size);
}

std::uint64_t Pe::get_image_base() const {
  return this->nt_header->OptionalHeader.ImageBase;
}

std::string Pe::get_image_name() { return this->name; }
