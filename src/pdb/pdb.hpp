#pragma once

#include <Windows.h>
#include <algorithm>
#include <expected>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <unordered_set>
#include <vector>

#include "PDB.h"
#include "PDB_DBIStream.h"
#include "PDB_DBITypes.h"
#include "PDB_ErrorCodes.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleSymbolStream.h"
#include "PDB_RawFile.h"

#define PUSH_PROC(KIND)                                                        \
  do {                                                                         \
    const uint32_t rva = pdb_iss.ConvertSectionOffsetToRVA(                    \
        record->data.KIND.section, record->data.KIND.offset);                  \
    if (rva != 0u) {                                                           \
      functions.push_back({.fn_name = record->data.KIND.name,                  \
                           .fn_rva = rva,                                      \
                           .fn_size = record->data.KIND.codeSize});            \
      seen_fn.emplace(rva);                                                    \
    }                                                                          \
  } while (0)

namespace pdb {

// create our structure for storing function information
struct pdb_fn {
  std::string fn_name;
  std::uint32_t fn_rva;
  std::uint32_t fn_size;
};

class pdb_parser {
private:
  std::string file_str;
  std::vector<std::uint8_t> buffer;
  std::optional<PDB::RawFile> pdb_file;

public:
  explicit pdb_parser(const std::string &file) : file_str(file) {};

  std::expected<std::vector<std::uint8_t>, std::string>
  get_file_info(std::string file_path) const {
    // read the raw file into a byte array which we'll later send off to
    // open_pdb_file, example creates a file mapping because it's assuming we're
    // going to be dealing with large files which is fine but for now we'll do
    // as so until we test on larger binaries..
    std::ifstream raw_file(file_path, std::ios::binary | std::ios::ate);

    std::streamsize raw_size = raw_file.tellg();

    raw_file.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> raw_bytes(raw_size);
    if (!raw_file.read(reinterpret_cast<char *>(raw_bytes.data()), raw_size))
      return std::unexpected(
          "Failed to read file data to memory, invalid file?");

    return raw_bytes;
  }

private:
  std::expected<std::monostate, std::string> open_pdb_file() {
    // we're gonna need to get the file info (bytes & sizee), from there we'll
    // call validatefile to ensure it passes and is ready to be sent of to
    // createrawfile. from there, any need of creating different sub-structures
    // of the pdb file, the user can directly use this->pdb_file (through some
    // getter) in order to access those sub-structures, raw_pdb just has a bunch
    // that doesn't need us to create useless wrappers for accessing.
    const auto &file_info = this->get_file_info(file_str);

    if (!file_info.has_value())
      return std::unexpected(file_info.error());

    this->buffer = std::move(*file_info);

    if (auto err_code =
            PDB::ValidateFile((*file_info).data(), (*file_info).size());
        err_code != PDB::ErrorCode::Success)
      return std::unexpected(
          std::format("Errored on ValidateFile with error code {}",
                      static_cast<std::uint32_t>(err_code)));

    // pdb file validated, we can now store the raw file and be done here.
    this->pdb_file = PDB::CreateRawFile(buffer.data());

    return std::monostate{};
  }

public:
  std::expected<std::vector<pdb_fn>, std::string> get_fns() {
    if (!pdb_file.has_value()) {
      if (auto _ = open_pdb_file(); !_.has_value())
        return std::unexpected(_.error());
    }

    // start of by creating a dbi stream so we can iterate over functions, we'll
    // then sort by kind by each symbol encountered. initially will be minimal
    // but later updated as needed...
    std::vector<pdb_fn> functions{};
    std::unordered_set<std::uint32_t> seen_fn;

    PDB::DBIStream pdb_dbi = PDB::CreateDBIStream(*pdb_file);
    PDB::ModuleInfoStream pdb_mis = pdb_dbi.CreateModuleInfoStream(*pdb_file);
    PDB::ImageSectionStream pdb_iss =
        pdb_dbi.CreateImageSectionStream(*pdb_file);

    for (const auto &mod : pdb_mis.GetModules()) {
      PDB::ModuleSymbolStream pdb_syms = mod.CreateSymbolStream(*pdb_file);

      pdb_syms.ForEachSymbol([&functions, &seen_fn, &pdb_iss](
                                 const PDB::CodeView::DBI::Record *record) {
        switch (record->header.kind) {
        case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32:
          PUSH_PROC(S_GPROC32);
          break;
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32:
          PUSH_PROC(S_LPROC32);
          break;
        case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID:
          PUSH_PROC(S_GPROC32_ID);
          break;
        case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID:
          PUSH_PROC(S_LPROC32_ID);
          break;

        default:
          break;
        }
      });
    }

    PDB::CoalescedMSFStream symbol_record_stream =
        pdb_dbi.CreateSymbolRecordStream(*pdb_file);
    PDB::PublicSymbolStream public_stream =
        pdb_dbi.CreatePublicSymbolStream(*pdb_file);

    for (const PDB::HashRecord &hash : public_stream.GetRecords()) {
      const PDB::CodeView::DBI::Record *record =
          public_stream.GetRecord(symbol_record_stream, hash);

      if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32)
        continue;

      if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
           PDB_AS_UNDERLYING(
               PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0)
        continue;

      uint32_t rva = pdb_iss.ConvertSectionOffsetToRVA(
          record->data.S_PUB32.section, record->data.S_PUB32.offset);
      if (rva == 0)
        continue;

      if (seen_fn.count(rva))
        continue; // module walk got it already

      // S_PUB32 has no codeSize — leave as 0, compute via distance later
      functions.push_back(
          {.fn_name = record->data.S_PUB32.name, .fn_rva = rva, .fn_size = 0});
      seen_fn.emplace(rva);
    }

    // Sort by RVA and infer sizes from distance
    std::sort(functions.begin(), functions.end(),
              [](auto &a, auto &b) { return a.fn_rva < b.fn_rva; });

    for (size_t i = 0; i + 1 < functions.size(); ++i) {
      if (functions[i].fn_size == 0)
        functions[i].fn_size = functions[i + 1].fn_rva - functions[i].fn_rva;
    }
    return functions;
  }
};
} // namespace pdb
