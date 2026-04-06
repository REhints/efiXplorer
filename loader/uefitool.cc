// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "uefitool.h"

#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

void efiloader::Uefitool::show_messages() {
  for (const auto &[text, index] : messages) {
    msg("[uefitool] %s\n", text.toLocal8Bit());
  }
}

void efiloader::Uefitool::get_image_guid(qstring &image_guid,
                                         UModelIndex index) {
  UString guid;
  UModelIndex guid_index;
  switch (model.subtype(model.parent(index))) {
  case EFI_SECTION_GUID_DEFINED:
    if (model.type(model.parent(index)) == Types::File) {
      guid_index = model.parent(index);
    } else {
      guid_index = model.parent(model.parent(index));
    }
    if (model.subtype(guid_index) == EFI_SECTION_COMPRESSION)
      guid_index = model.parent(guid_index);
    break;
  case EFI_SECTION_COMPRESSION:
    guid_index = model.parent(model.parent(index));
    break;
  default:
    guid_index = model.parent(index);
  }
  // get parent header and read GUID
  guid = guidToUString(
      readUnaligned((const EFI_GUID *)(model.header(guid_index).constData())));
  image_guid = reinterpret_cast<char *>(guid.data);
}

std::vector<std::string>
efiloader::Uefitool::parse_depex_section_body(const UModelIndex &index,
                                              UString &parsed) {
  // adopted from FfsParser::parseDepexSectionBody
  std::vector<std::string> res;

  if (!index.isValid())
    return res;

  UByteArray body = model.body(index);

  // check data to be present
  if (body.size() < 2) { // 2 is a minimal sane value, i.e TRUE + END
    return res;
  }

  const EFI_GUID *guid;
  const UINT8 *current = (const UINT8 *)body.constData();

  // special cases of first opcode
  switch (*current) {
  case EFI_DEP_BEFORE:
    if (body.size() != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
      return res;
    }
    guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
    parsed += UString("\nBEFORE ") + guidToUString(readUnaligned(guid));
    current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
    if (*current != EFI_DEP_END) {
      return res;
    }
    return res;
  case EFI_DEP_AFTER:
    if (body.size() != 2 * EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
      return res;
    }
    guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
    parsed += UString("\nAFTER ") + guidToUString(readUnaligned(guid));
    current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
    if (*current != EFI_DEP_END) {
      return res;
    }
    return res;
  case EFI_DEP_SOR:
    if (body.size() <= 2 * EFI_DEP_OPCODE_SIZE) {
      return res;
    }
    parsed += UString("\nSOR");
    current += EFI_DEP_OPCODE_SIZE;
    break;
  }

  // parse the rest of depex
  while (current - (const UINT8 *)body.constData() < body.size()) {
    switch (*current) {
    case EFI_DEP_BEFORE: {
      return res;
    }
    case EFI_DEP_AFTER: {
      return res;
    }
    case EFI_DEP_SOR: {
      return res;
    }
    case EFI_DEP_PUSH:
      // check that the rest of depex has correct size
      if ((UINT32)body.size() -
              (UINT32)(current - (const UINT8 *)body.constData()) <=
          EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID)) {
        parsed.clear();
        return res;
      }
      guid = (const EFI_GUID *)(current + EFI_DEP_OPCODE_SIZE);
      parsed += UString("\nPUSH ") + guidToUString(readUnaligned(guid));
      // add protocol GUID to result vector
      res.push_back(
          reinterpret_cast<char *>(guidToUString(readUnaligned(guid)).data));
      current += EFI_DEP_OPCODE_SIZE + sizeof(EFI_GUID);
      break;
    case EFI_DEP_AND:
      parsed += UString("\nAND");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_OR:
      parsed += UString("\nOR");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_NOT:
      parsed += UString("\nNOT");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_TRUE:
      parsed += UString("\nTRUE");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_FALSE:
      parsed += UString("\nFALSE");
      current += EFI_DEP_OPCODE_SIZE;
      break;
    case EFI_DEP_END:
      parsed += UString("\nEND");
      current += EFI_DEP_OPCODE_SIZE;
      // check that END is the last opcode
      if (current - (const UINT8 *)body.constData() < body.size()) {
        parsed.clear();
      }
      break;
    default:
      return res;
    }
  }

  return res;
}

std::vector<std::string>
efiloader::Uefitool::parse_apriori_raw_section(const UModelIndex &index) {
  // adopted from FfsParser::parseDepexSectionBody
  std::vector<std::string> res;

  if (!index.isValid())
    return res;

  UByteArray body = model.body(index);

  // sanity check
  if (body.size() % sizeof(EFI_GUID)) {
    return res;
  }

  auto count = static_cast<UINT32>(body.size() / sizeof(EFI_GUID));
  for (UINT32 i = 0; i < count; i++) {
    const auto *guid = reinterpret_cast<const EFI_GUID *>(body.constData()) + i;
    res.push_back(
        reinterpret_cast<char *>(guidToUString(readUnaligned(guid)).data));
  }

  return res;
}

void efiloader::Uefitool::set_machine_type(const UByteArray &pe_body) {
  const char *data = pe_body.constData();
  if (pe_body.size() < 64) {
    return;
  }
  uint32_t pe_hdr_off = 0;
  memcpy(&pe_hdr_off, data + 0x3c, sizeof(pe_hdr_off));
  if (pe_hdr_off > static_cast<uint32_t>(pe_body.size()) ||
      pe_body.size() - pe_hdr_off < 6) {
    return;
  }
  uint32_t sig = 0;
  memcpy(&sig, data + pe_hdr_off, sizeof(sig));
  if (sig == 0x4550) {
    memcpy(&machine_type, data + pe_hdr_off + 4, sizeof(machine_type));
    machine_type_initialised = true;
  }
}

void efiloader::Uefitool::handle_raw_section(const UModelIndex &index) {
  UModelIndex parent_file = model.findParentOfType(index, Types::File);
  if (!parent_file.isValid()) {
    return;
  }
  UByteArray parent_file_guid(model.header(parent_file).constData(),
                              sizeof(EFI_GUID));
  if (parent_file_guid == EFI_PEI_APRIORI_FILE_GUID) {
    msg("[efiXloader] PEI Apriori file found\n");
    get_apriori(index, "PEI_APRIORI_FILE");
  }
  if (parent_file_guid == EFI_DXE_APRIORI_FILE_GUID) {
    msg("[efiXloader] DXE Apriori file found\n");
    get_apriori(index, "DXE_APRIORI_FILE");
  }
}

namespace {
void get_module_name(qstring &module_name, efiloader::File *file) {
  utf16_utf8(&module_name,
             reinterpret_cast<const wchar16_t *>(file->uname.data()));
}
} // namespace

void efiloader::Uefitool::process_section(const UModelIndex &index,
                                          int /*section_idx*/,
                                          efiloader::File *file) {
  qstring name;
  qstring guid;

  switch (model.subtype(index)) {
  case EFI_SECTION_RAW:
    handle_raw_section(index);
    break;
  case EFI_SECTION_TE:
    file->is_te = true;
    file->ubytes = model.body(index);
    file->module_kind = get_kind(index);
    break;
  case EFI_SECTION_PE32:
    file->is_pe = true;
    file->ubytes = model.body(index);
    file->module_kind = get_kind(index);
    if (!machine_type_initialised) {
      set_machine_type(model.body(index));
    }
    break;
  case EFI_SECTION_USER_INTERFACE:
    file->has_ui = true;
    file->uname = model.body(index);
    break;
  case EFI_SECTION_COMPRESSION:
  case EFI_SECTION_GUID_DEFINED:
    for (int i = 0; i < model.rowCount(index); i++) {
      process_section(index.child(i, 0), i, file);
    }
    break;
  case EFI_SECTION_DXE_DEPEX:
    get_deps(index, "EFI_SECTION_DXE_DEPEX");
    break;
  case EFI_SECTION_MM_DEPEX:
    get_deps(index, "EFI_SECTION_MM_DEPEX");
    break;
  case EFI_SECTION_PEI_DEPEX:
    get_deps(index, "EFI_SECTION_PEI_DEPEX");
    break;
  case EFI_SECTION_VERSION:
    break;
  default:
    break;
  }

  // update file
  if (file->is_pe || file->is_te) {
    get_image_guid(guid, index);
    if (file->has_ui) {
      // get module name from UI section
      get_module_name(name, file);
    } else {
      // use module GUID as module name
      name = guid;
    }
    file->module_name.swap(name);
    file->module_guid.swap(guid);
  }
}

void efiloader::Uefitool::extract_files(const UModelIndex &index) {
  if (is_file_index(index)) {
    auto file = std::make_unique<File>();
    for (int i = 0; i < model.rowCount(index); i++) {
      process_section(index.child(i, 0), i, file.get());
    }

    // skip duplicate GUIDs and consider them to be the same module
    if (file->is_ok() && seen_guids.insert(file->module_guid.c_str()).second) {
      all_modules[file->module_guid.c_str()] = {
          {"name", file->module_name.c_str()},
          {"kind", file->module_kind.c_str()}};
      file->write(output_dir);
      files.push_back(std::move(file));
    }
  }

  // recurse into children to find nested files (e.g. inner firmware volumes)
  for (int i = 0; i < model.rowCount(index); i++) {
    extract_files(index.child(i, 0));
  }
}

void efiloader::Uefitool::dump() {
  // use the original input file path so both 32-bit and 64-bit
  // sessions share the same dump directory (e.g., fw.bin.efiloader)
  qstring input_path(get_path(PATH_TYPE_CMD));
  output_dir = input_path + qstring(".efiloader");
  std::filesystem::create_directory(output_dir.c_str());
  extract_files(model.index(0, 0));
}

void efiloader::Uefitool::get_deps(const UModelIndex &index,
                                   const std::string &key) {
  UString parsed;
  qstring image_guid;

  get_image_guid(image_guid, index);
  auto deps = parse_depex_section_body(index, parsed);
  if (!deps.empty()) {
    msg("[efiXloader] dependency section for image with GUID %s: %s\n",
        image_guid.c_str(), parsed.data);
    all_deps[key][image_guid.c_str()] = deps;
  }
}

void efiloader::Uefitool::get_apriori(const UModelIndex &index,
                                      const std::string &key) {
  if (all_deps.contains(key)) {
    return;
  }
  auto deps = parse_apriori_raw_section(index);
  if (deps.empty()) {
    return;
  }
  all_deps[key] = deps;
}

void efiloader::Uefitool::dump_jsons() {
  // dump JSON with DEPEX and GUIDs information for each image
  // use the original input file path (not the bitness-specific IDB path)
  // so both 32-bit and 64-bit sessions share the same JSON files
  qstring input_path(get_path(PATH_TYPE_CMD));

  std::ofstream out_deps((input_path + ".deps.json").c_str());
  out_deps << std::setw(2) << all_deps << std::endl;

  std::ofstream out_guids((input_path + ".images.json").c_str());
  out_guids << std::setw(2) << all_modules << std::endl;
}
