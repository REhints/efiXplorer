// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_utils.h"
#include "efi_defs.h"

#include "../ldr/pe/pe.h"

#include <algorithm>
#include <cstdio>
#include <string>

// can be used after Hex-Rays based analysis
ea_set_t g_get_smst_location_calls;
ea_set_t g_smm_get_variable_calls;
ea_set_t g_smm_set_variable_calls;

//--------------------------------------------------------------------------
// get file format name
std::string file_format_name() {
  std::array<char, 256> file_format{};
  get_file_type_name(file_format.data(), file_format.size());
  return std::string(file_format.data());
}

//--------------------------------------------------------------------------
// get input file type (PEI or DXE-like). No reliable way to determine FFS
// file type given only its PE/TE image section, so hello heuristics
ffs_file_type_t guess_file_type(analysis_kind_t analysis_kind,
                                json_list_t *all_guids) {
  if (analysis_kind == analysis_kind_t::uefi) {
    return ffs_file_type_t::driver;
  }

  segment_t *hdr_seg = get_segm_by_name("HEADER");
  if (hdr_seg == nullptr) {
    return ffs_file_type_t::driver;
  }

  uint64_t signature = get_wide_word(hdr_seg->start_ea);
  bool has_pei_guids = std::any_of(
      all_guids->begin(), all_guids->end(), [](const json &guid_value) {
        return static_cast<std::string>(guid_value["name"]).find("PEI") !=
               std::string::npos;
      });

  std::array<char, 256> file_name_buf{};
  get_input_file_path(file_name_buf.data(), file_name_buf.size());
  std::string file_name = file_name_buf.data();

  bool has_pei_in_path =
      ((file_name.find("Pei") != std::string::npos ||
        file_name.find("pei") != std::string::npos || signature == VZ) &&
       analysis_kind == analysis_kind_t::x86_64);

  if (signature == VZ || has_pei_guids || has_pei_in_path) {
    efi_utils::log("analysing binary file as PEI, signature: %llx\n",
                   signature);
    return ffs_file_type_t::peim;
  }

  efi_utils::log("analysing binary file as DXE/SMM\n");
  return ffs_file_type_t::driver;
}

int parse_efi_standalone_smm_entry_point() {
  return parse_decls(
      nullptr,
      "typedef EFI_STATUS (*EFI_SMM_STANDALONE_ENTRY_POINT)(EFI_HANDLE "
      "ImageHandle, EFI_SMM_SYSTEM_TABLE2 *Smst);",
      msg, HTI_DCL);
}

//--------------------------------------------------------------------------
// add EFI_SMM_STANDALONE_ENTRY_POINT
bool efi_utils::add_efi_standalone_smm_entry_point() {
#if IDA_SDK_VERSION < 850
  return false;
#else
  // return true if there are no errors from parse_decls()
  return !parse_efi_standalone_smm_entry_point();
#endif
}

int parse_efi_pei_svc4() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SERVICES_4 {\n"
                     "  EFI_PEI_SERVICES **PeiServices;\n"
                     "  UINT32 BaseAddress;\n"
                     "};",
                     msg, HTI_DCL);
}

int parse_efi_pei_sidt() {
  return parse_decls(nullptr,
                     "struct EFI_PEI_SIDT {\n"
                     "  UINT16 Limit;\n"
                     "  int *__shifted(EFI_PEI_SERVICES_4, 4) BaseAddress;\n"
                     "};",
                     msg, HTI_DCL | HTI_PAK1);
}

bool mark_copy(ea_t code_addr, ea_t var_addr, std::string type) {
  int reg = -1;
  ea_t ea = code_addr;
  ea_t var_copy = BADADDR;

  insn_t insn;
  decode_insn(&insn, ea);

  if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
      insn.ops[1].type == o_mem && insn.ops[1].addr == var_addr) {
    reg = insn.ops[0].reg;
  }

  if (reg == -1) {
    return false;
  }

  for (auto i = 0; i < 8; ++i) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);

    if (is_basic_block_end(insn, false)) {
      break;
    }

    if ((insn.itype == NN_callni || insn.itype == NN_call) ||
        (insn.ops[0].type == o_reg && insn.ops[0].reg == reg)) {
      break;
    }

    if (insn.itype == NN_mov && insn.ops[0].type == o_mem &&
        insn.ops[1].type == o_reg && insn.ops[1].reg == reg) {
      var_copy = insn.ops[0].addr;
      efi_utils::log("found copy for global variable: 0x%" PRIx64 "\n",
                     u64_addr(ea));
      break;
    }
  }

  if (var_copy == BADADDR) {
    return false;
  }

  if (type == "gSmst") {
    efi_utils::set_ptr_type_and_name(var_copy, "gSmst",
                                     "_EFI_SMM_SYSTEM_TABLE2");
  }

  if (type == "gBS") {
    efi_utils::set_ptr_type_and_name(var_copy, "gBS", "EFI_BOOT_SERVICES");
  }

  if (type == "gRT") {
    efi_utils::set_ptr_type_and_name(var_copy, "gRT", "EFI_RUNTIME_SERVICES");
  }

  return true;
}

//--------------------------------------------------------------------------
// msg wrapper
int efi_utils::log(const char *fmt, ...) {
  auto nbytes = msg("[%s] ", g_plugin_name);

  va_list va;
  va_start(va, fmt);

  nbytes += vmsg(fmt, va);

  va_end(va);
  return nbytes;
}

//--------------------------------------------------------------------------
// set EFI_GUID type
void efi_utils::set_guid_type(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "EFI_GUID")) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// set type and name
void efi_utils::set_type_and_name(ea_t ea, std::string name, std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), type.c_str())) {
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

//--------------------------------------------------------------------------
// set const CHAR16 type
void efi_utils::set_const_char16_type(ea_t ea) {
  tinfo_t tinfo;
  if (tinfo.get_named_type(get_idati(), "CHAR16")) {
    tinfo.set_const();
    apply_tinfo(ea, tinfo, TINFO_DEFINITE);
  }
}

inline bool read_pe_header(peheader_t &pe) {
  const netnode penode(PE_NODE);
  return penode.valobj(&pe, sizeof(pe)) > 0;
}

//--------------------------------------------------------------------------
// get input file type (64-bit, 32-bit module or UEFI firmware)
analysis_kind_t efi_utils::get_analysis_kind() {
  processor_t &ph = PH;
  auto bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32 : 16;

  // check if the input file is a UEFI firmware image
  if (file_format_name().find("UEFI") != std::string::npos) {
    return analysis_kind_t::uefi;
  }

  if (inf_get_filetype() != f_PE) {
    // only PE/TE files,
    // if file is TE, IDA will mark it with f_PE file type
    efi_utils::log("unsupported format\n");
    return analysis_kind_t::unsupported;
  }

  // check subsystem
  peheader_t pe;
  if (!read_pe_header(pe)) {
    efi_utils::log("unsupported format\n");
    return analysis_kind_t::unsupported;
  }

  if (!pe.is_te() && !pe.is_efi()) {
    efi_utils::log("unsupported subsystem\n");
    return analysis_kind_t::unsupported;
  }

  switch (ph.id) {
  case PLFM_386:
    if (bits == 64)
      return analysis_kind_t::x86_64;
    if (bits == 32)
      return analysis_kind_t::x86_32;
    break;

  case PLFM_ARM:
    if (bits == 64)
      return analysis_kind_t::aarch64;
    break;
  }

  return analysis_kind_t::unsupported;
}

ffs_file_type_t efi_utils::ask_file_type(json_list_t *all_guids) {
  const auto analysis_kind = efi_utils::get_analysis_kind();
  if (analysis_kind == analysis_kind_t::uefi ||
      analysis_kind == analysis_kind_t::x86_64) {
    // if the input is UEFI firmware or an x86-64 module,
    // it will be analysed as DXE/SMM
    return ffs_file_type_t::driver;
  }

  constexpr std::array file_types = {ffs_file_type_t::driver,
                                     ffs_file_type_t::peim,
                                     ffs_file_type_t::mm_standalone};

  static const char form[] = "Analyse file as\n\n"
                             "<DXE/SMM:R>\n"
                             "<PEI Module:R>\n"
                             "<Standalone SMM:R>>\n";

  int16_t choice = 0;
  if (!ask_form(form, &choice)) {
    return guess_file_type(analysis_kind, all_guids);
  }

  return file_types[choice];
}

//--------------------------------------------------------------------------
// find address of global gBS var for x86 64-bit module for each service
ea_t efi_utils::find_unknown_bs_var64(ea_t ea) {
  insn_t insn;

  // check 10 instructions below
  for (auto i = 0; i < 10; ++i) {
    decode_insn(&insn, ea);

    if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RAX && insn.ops[1].type == o_mem) {
      return insn.ops[1].addr;
    }

    ea = prev_head(ea, 0);
  }

  return BADADDR;
}

//--------------------------------------------------------------------------
// get all xrefs for given address
ea_set_t efi_utils::get_xrefs(ea_t addr) {
  ea_set_t xrefs;

  for (ea_t xref = get_first_dref_to(addr); xref != BADADDR;
       xref = get_next_dref_to(addr, xref)) {
    xrefs.insert(xref);
  }

  return xrefs;
}

//--------------------------------------------------------------------------
// get all xrefs for given array element
ea_set_t efi_utils::get_xrefs_to_array(ea_t addr) {
  ea_t first_ea;
  ea_t ea = addr;

  while (true) {
    const auto ptr = get_qword(ea);
    const auto xrefs = efi_utils::get_xrefs(ptr);

    if (!xrefs.contains(ea)) {
      break;
    }

    first_ea = ea;
    ea -= 8;
  }

  return efi_utils::get_xrefs(first_ea);
}

//--------------------------------------------------------------------------
// wrapper for op_stroff function
bool efi_utils::op_stroff(ea_t addr, std::string type) {
#if IDA_SDK_VERSION >= 840
  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), type.c_str())) {
    return false;
  }

  // use force_tid() instead of get_tid()
  // to import type if it's not imported
  tid_t tid = tinfo.force_tid();
  if (tid == BADADDR) {
    return false;
  }
#else
  tid_t tid = get_struc_id(type.c_str());
#endif

  insn_t insn;
  decode_insn(&insn, addr);
  return op_stroff(insn, 0, &tid, 1, 0);
}

//--------------------------------------------------------------------------
// get pointer to named type and apply it
bool efi_utils::set_ptr_type(ea_t addr, std::string type) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), type.c_str())) {
    return false;
  }

  tinfo_t p_tinfo;
  p_tinfo.create_ptr(tinfo);
  return apply_tinfo(addr, p_tinfo, TINFO_DEFINITE);
}

//--------------------------------------------------------------------------
// set name and apply pointer to named type
void efi_utils::set_ptr_type_and_name(ea_t ea, std::string name,
                                      std::string type) {
  set_name(ea, name.c_str(), SN_FORCE);
  efi_utils::set_ptr_type(ea, type.c_str());
}

//--------------------------------------------------------------------------
// get guids.json file name
std::filesystem::path efi_utils::get_guids_json_file() {
  const auto search_paths = {
      std::filesystem::path(get_user_idadir()) / "plugins" /
          "efiXplorer", // if installed via ida-hcli
      std::filesystem::path(get_user_idadir()) / "plugins",
      std::filesystem::path(idadir("plugins"))};

  const auto guids_paths = {std::filesystem::path("guids.json"),
                            std::filesystem::path("guids") / "guids.json"};

  for (const auto &base_path : search_paths) {
    for (const auto &guids_path : guids_paths) {
      auto guids = base_path / guids_path;
      if (std::filesystem::exists(guids)) {
        return guids;
      }
    }
  }

  return {};
}

//--------------------------------------------------------------------------
// get json summary file name
std::filesystem::path efi_utils::get_summary_file() {
  auto path = std::filesystem::path(get_path(PATH_TYPE_IDB));
  path.replace_extension(".json");
  return path;
}

//--------------------------------------------------------------------------
// check if summary json file exists
bool efi_utils::summary_json_exists() {
  return std::filesystem::exists(get_summary_file());
}

//--------------------------------------------------------------------------
// change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// at ModuleEntryPoint
void efi_utils::set_entry_arg_to_pei_svc() {
  if (get_entry_qty() == 0) {
    return;
  }

  tinfo_t pp_tinfo;
  bool initialised = false;

  for (auto idx = 0; idx < get_entry_qty(); ++idx) {
    const auto ord = get_entry_ordinal(idx);
    const auto start_ea = get_entry(ord);

    tinfo_t tif_ea;
    if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
      continue;
    }

    func_type_data_t funcdata;
    if (!tif_ea.get_func_details(&funcdata)) {
      continue;
    }

    // funcdata.size() does not work for aarch64
    if (funcdata.size() != 2) {
      continue;
    }

    if (!initialised) {
      tinfo_t tif_pei;
      if (!tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES")) {
        return; // exit if type not found
      }

      tinfo_t p_tinfo;
      p_tinfo.create_ptr(tif_pei);
      pp_tinfo.create_ptr(p_tinfo);

      initialised = true;
    }

    funcdata[1].type = pp_tinfo;
    funcdata[1].name = "PeiServices";

    tinfo_t f_tinfo;
    if (!f_tinfo.create_func(funcdata)) {
      continue;
    }

    apply_tinfo(start_ea, f_tinfo, TINFO_DEFINITE);
  }
}

bool efi_utils::set_ret_to_pei_svc(ea_t start_ea) {
  tinfo_t tif_ea;
  if (guess_tinfo(&tif_ea, start_ea) == GUESS_FUNC_FAILED) {
    return false;
  }

  func_type_data_t fi;
  if (!tif_ea.get_func_details(&fi)) {
    return false;
  }

  tinfo_t tif_pei;
  if (!tif_pei.get_named_type(get_idati(), "EFI_PEI_SERVICES")) {
    return false;
  }

  tinfo_t p_tinfo;
  tinfo_t pp_tinfo;
  p_tinfo.create_ptr(tif_pei);
  pp_tinfo.create_ptr(p_tinfo);

  fi.rettype = pp_tinfo;

  tinfo_t f_tinfo;
  if (!f_tinfo.create_func(fi)) {
    return false;
  }

  return apply_tinfo(start_ea, f_tinfo, TINFO_DEFINITE);
}

//--------------------------------------------------------------------------
// add EFI_PEI_SERVICES_4 structure
bool efi_utils::add_struct_for_shifted_ptr() {
#if IDA_SDK_VERSION < 850
  const auto sid = add_struc(BADADDR, "EFI_PEI_SERVICES_4");
  if (sid == BADADDR) {
    return false;
  }

  const auto new_struct = get_struc(sid);
  if (new_struct == nullptr) {
    return false;
  }

  add_struc_member(new_struct, nullptr, 0, dword_flag(), nullptr, 4);
  add_struc_member(new_struct, nullptr, 4, dword_flag(), nullptr, 4);
  set_member_name(new_struct, 0, "PeiServices");
  set_member_name(new_struct, 4, "BaseAddress");

  tinfo_t tinfo;
  if (!tinfo.get_named_type(get_idati(), "EFI_PEI_SERVICES")) {
    return false;
  }

  // set type "EFI_PEI_SERVICES **PeiServices"
  tinfo_t p_tinfo;
  tinfo_t pp_tinfo;
  p_tinfo.create_ptr(tinfo);
  pp_tinfo.create_ptr(p_tinfo);

  auto member = get_member_by_name(new_struct, "PeiServices");
  set_member_tinfo(new_struct, member, 0, pp_tinfo, 0);

  return true;
#else
  // return true if there are no errors from parse_decls()
  return !parse_efi_pei_svc4() && !parse_efi_pei_sidt();
#endif
}

//--------------------------------------------------------------------------
// get module name by address
qstring efi_utils::get_module_name_loader(ea_t addr) {
  segment_t *seg = getseg(addr);
  if (!seg) {
    return {};
  }

  qstring segname;
  get_segm_name(&segname, seg);

  constexpr size_t suflen = 7;
  if (segname.size() > suflen) {
    segname.remove(segname.size() - suflen, segname.size());
  }

  return segname;
}

//--------------------------------------------------------------------------
// get GUID data by address
json efi_utils::get_guid_by_address(ea_t addr) {
  return json::array({get_wide_dword(addr), get_wide_word(addr + 4),
                      get_wide_word(addr + 6), get_wide_byte(addr + 8),
                      get_wide_byte(addr + 9), get_wide_byte(addr + 10),
                      get_wide_byte(addr + 11), get_wide_byte(addr + 12),
                      get_wide_byte(addr + 13), get_wide_byte(addr + 14),
                      get_wide_byte(addr + 15)});
}

//--------------------------------------------------------------------------
// validate GUID value
bool efi_utils::valid_guid(json guid) {
  if (!guid.is_array() || guid.size() < 2) {
    return false;
  }

  const uint32_t data1 = guid[0].get<uint32_t>();
  const uint16_t data2 = guid[1].get<uint16_t>();

  return !(data1 == 0 && data2 == 0) &&
         !(data1 == 0xffffffff && data2 == 0xffff);
}

//--------------------------------------------------------------------------
// get addresses of argumets, custom mimimal implementation,
// works with num_args <= 4 and only for x86-64
bool efi_utils::get_arg_addrs_with(eavec_t *out, ea_t caller, size_t num_args) {
  if (num_args > 4) {
    return false;
  }

  static constexpr std::array<regs_x86_64_t, 4> registers = {R_RCX, R_RDX, R_R8,
                                                             R_R9};

  insn_t insn;
  auto ea = caller;
  size_t index = 0;

  while (index < num_args) {
    ea = prev_head(ea, 0);
    decode_insn(&insn, ea);

    if (insn.ops[0].type == o_reg && insn.ops[0].reg == registers[index]) {
      out->resize_noinit(index + 1);
      out->at(index) = ea;
      index += 1;
    }

    if (is_basic_block_end(insn, false)) {
      break;
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// convert GUID value to string
std::string efi_utils::guid_to_string(const json &guid) {
  if (!guid.is_array() || guid.size() < 11) {
    return {};
  }

  char guid_str[37] = {0};
  snprintf(guid_str, sizeof(guid_str),
           "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
           static_cast<uint32_t>(guid[0]), static_cast<uint16_t>(guid[1]),
           static_cast<uint16_t>(guid[2]), static_cast<uint8_t>(guid[3]),
           static_cast<uint8_t>(guid[4]), static_cast<uint8_t>(guid[5]),
           static_cast<uint8_t>(guid[6]), static_cast<uint8_t>(guid[7]),
           static_cast<uint8_t>(guid[8]), static_cast<uint8_t>(guid[9]),
           static_cast<uint8_t>(guid[10]));
  return guid_str;
}

uint8_list_t efi_utils::unpack_guid(std::string guid) {
  uint8_list_t res;
  const std::string delim = "-";
  std::string byte_str;
  uint8_t byte;
  size_t pos = 0;
  int index = 0;

  uint8_list_t tmp;
  while ((pos = guid.find(delim)) != std::string::npos) {
    const auto hex = guid.substr(0, pos);
    if (hex.size() % 2) {
      break;
    }

    for (auto i = 0; i < hex.size(); i += 2) {
      byte_str = hex.substr(i, 2);
      byte = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
      tmp.push_back(byte);
    }

    if (index != 3) {
      res.insert(res.end(), tmp.rbegin(), tmp.rend());
    } else {
      res.insert(res.end(), tmp.begin(), tmp.end());
    }

    ++index;
    guid.erase(0, pos + delim.size());
    tmp.clear();
  }

  for (auto i = 0; i < guid.size(); i += 2) {
    byte_str = guid.substr(i, 2);
    byte = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
    res.push_back(byte);
  }

  return res;
}

ea_set_t efi_utils::search_protocol(const std::string &protocol) {
  ea_set_t res;

  const uint8_list_t guid_bytes = efi_utils::unpack_guid(protocol);
  if (guid_bytes.size() != 16) {
    return res;
  }

  std::array<uchar, 16> bytes{};
  std::copy(guid_bytes.begin(), guid_bytes.end(), bytes.begin());

  ea_t start = 0;
  while (true) {
#if IDA_SDK_VERSION < 850
    ea_t addr = bin_search2(start, BADADDR, bytes.data(), nullptr, 16,
                            BIN_SEARCH_FORWARD);
#else
    ea_t addr = bin_search(start, BADADDR, bytes.data(), nullptr, 16,
                           BIN_SEARCH_FORWARD);
#endif
    if (addr == BADADDR) {
      break;
    }

    res.insert(addr);
    start = addr + 16;
  }

  return res;
}

bool efi_utils::check_install_protocol(ea_t ea) {
  insn_t insn;
  // search for `call [R + offset]` insn
  // offset in [0x80, 0xA8, 0x148]
  ea_t addr = ea;
  for (auto i = 0; i < 16; i++) {
    addr = next_head(addr, BADADDR);
    decode_insn(&insn, addr);
    if ((insn.itype == NN_jmpni || insn.itype == NN_callni) &&
        insn.ops[0].type == o_displ) {
      auto service = insn.ops[0].addr;
      // check for InstallProtocolInterface, InstallMultipleProtocolInterfaces,
      // SmmInstallProtocolInterface
      if (service == 0x80 || service == 0xa8 || service == 0x148) {
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// convert 64-bit value to hex string
std::string efi_utils::as_hex(uint64_t value) {
  char hexstr[21] = {0};
  std::snprintf(hexstr, sizeof(hexstr), "%" PRIX64, value);
  return hexstr;
}

//--------------------------------------------------------------------------
// make sure that the first argument looks like a protocol
bool efi_utils::check_boot_service_protocol(ea_t call_addr) {
  bool valid = false;
  auto addr = prev_head(call_addr, 0);
  insn_t insn;
  decode_insn(&insn, addr);
  while (!is_basic_block_end(insn, false)) {
    // for next iteration
    decode_insn(&insn, addr);
    addr = prev_head(addr, 0);

    // check current instruction
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_RCX) {
      if (insn.ops[1].type == o_mem) {
        // will still be a false positive if the Handle in
        // SmmInstallProtocolInterface is a global variable)
        valid = true;
      }
      break;
    }
  }
  return valid;
}

//--------------------------------------------------------------------------
// make sure that the address does not belong to the protocol interface
bool efi_utils::check_boot_service_protocol_xrefs(ea_t call_addr) {
  insn_t insn;
  for (const auto &xref : efi_utils::get_xrefs(call_addr)) {
    decode_insn(&insn, xref);
    if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
        insn.ops[0].reg == R_R8) {
      // load interface instruction
      return false;
    }
  }
  return true;
}

bool efi_utils::mark_copies_for_gvars(const ea_set_t &gvars,
                                      const std::string &type) {
  for (const auto &var : gvars) {
    for (const auto &addr : efi_utils::get_xrefs(var)) {
      mark_copy(addr, var, type);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// generate name string from type
std::string efi_utils::type_to_name(std::string type) {
  std::string result;
  size_t pos = 0;
  for (char const &c : type) {
    if (std::islower(c) || std::isdigit(c)) {
      result.push_back(c);
      pos += 1;
      continue;
    } else if (std::isupper(c)) {
      result.push_back(pos > 0 ? std::tolower(c) : c);
      ++pos;
    } else if (c == '_') {
      pos = 0;
    } else {
      ++pos;
    }
  }

  return result;
}

void op_stroff_for_addr(ea_t ea, const qstring &type_name) {
  insn_t insn;

  for (int i = 0; i < 16; ++i) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);

    const auto &op = insn.ops[0];

    if ((insn.itype == NN_call || insn.itype == NN_callfi ||
         insn.itype == NN_callni) &&
        (op.type == o_displ || op.type == o_phrase) && op.reg == R_RAX) {
      efi_utils::op_stroff(ea, type_name.c_str());
      efi_utils::log("mark arguments at address 0x%" PRIx64
                     " (interface type: %s)\n",
                     u64_addr(ea), type_name.c_str());

      if (type_name == "EFI_SMM_BASE2_PROTOCOL" && op.type == o_displ &&
          op.addr == 8) {
        g_get_smst_location_calls.insert(ea);
      }

      if (type_name == "EFI_SMM_VARIABLE_PROTOCOL") {
        if (op.type == o_phrase) {
          g_smm_get_variable_calls.insert(ea);
        } else if (op.type == o_displ && op.addr == 0x10) {
          g_smm_set_variable_calls.insert(ea);
        }
      }

      break;
    }

    if (op.type == o_reg && op.reg == R_RAX) {
      break;
    }
  }
}

//--------------------------------------------------------------------------
// mark the arguments of each function from an interface derived from
// a local variable
void efi_utils::op_stroff_for_interface(xreflist_t local_xrefs,
                                        qstring type_name) {
  insn_t insn;
  for (const auto &xref : local_xrefs) {
    decode_insn(&insn, xref.ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == R_RAX) {
      op_stroff_for_addr(xref.ea, type_name);
    }
  }
}

//--------------------------------------------------------------------------
// mark the arguments of each function from an interface derived from
// a global variable
void efi_utils::op_stroff_for_global_interface(ea_set_t xrefs,
                                               qstring type_name) {
  insn_t insn;
  for (const auto &ea : xrefs) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_mov && insn.ops[0].reg == R_RAX) {
      op_stroff_for_addr(ea, type_name);
    }
  }
}

bool efi_utils::json_in_vec(const json_list_t &vec, const json &item) {
  return std::find(vec.begin(), vec.end(), item) != vec.end();
}

bool efi_utils::uint64_in_vec(const uint64_list_t &vec, uint64_t value) {
  return std::find(vec.begin(), vec.end(), value) != vec.end();
}

bool efi_utils::addr_in_tables(const ea_set_t &t1, const ea_set_t &t2,
                               ea_t ea) {
  return t1.contains(ea) || t2.contains(ea);
}

bool efi_utils::addr_in_tables(const ea_set_t &t1, const ea_set_t &t2,
                               const ea_set_t &t3, ea_t ea) {
  return t1.contains(ea) || t2.contains(ea) || t3.contains(ea);
}

ea_set_t efi_utils::find_data(ea_t start_ea, ea_t end_ea, uchar *data,
                              size_t len) {
  ea_set_t res;
  ea_t start = start_ea;
  int counter = 0;
  while (true) {
#if IDA_SDK_VERSION < 850
    auto ea =
        bin_search2(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
#else
    auto ea = bin_search(start, end_ea, data, nullptr, len, BIN_SEARCH_FORWARD);
#endif
    if (ea == BADADDR) {
      break;
    }
    res.insert(ea);
    start = ea + len;
  }

  return res;
}

//--------------------------------------------------------------------------
// get wide string by address
std::string efi_utils::get_wide_string(ea_t addr) {
  std::string res;
  int index = 0;

  while (get_wide_word(addr + index)) {
    auto byte = get_wide_byte(addr + index);
    if (byte < 0x20 || byte > 0x7e) {
      return "invalid string";
    }

    res.push_back(byte);
    index += 2;
  }

  return res;
}

//--------------------------------------------------------------------------
// get efi_guid_t by address
efi_guid_t efi_utils::get_global_guid(ea_t addr) {
  efi_guid_t guid;

  guid.data1 = get_wide_dword(addr);
  guid.data2 = get_wide_word(addr + 4);
  guid.data3 = get_wide_word(addr + 6);

  for (auto i = 0; i < 8; i++) {
    guid.data4[i] = get_wide_byte(addr + 8 + i);
  }

  return guid;
}

//--------------------------------------------------------------------------
// get efi_guid_t by stack offset
efi_guid_t efi_utils::get_local_guid(func_t *f, uint64_t offset) {
  efi_guid_t guid{};
  insn_t insn;
  auto ea = f->start_ea;
  int counter = 0;

  auto decode_dword = [](uint32_t dword, uint8_t *out) {
    out[0] = static_cast<uint8_t>(dword & 0xff);
    out[1] = static_cast<uint8_t>((dword >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((dword >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((dword >> 24) & 0xff);
  };

  while (ea <= f->end_ea) {
    if (counter == 16) {
      break;
    }

    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype != NN_mov || insn.ops[0].type != o_displ ||
        insn.ops[1].type != o_imm) {
      continue;
    }

    const auto &dst = insn.ops[0];
    const auto &src = insn.ops[1];

    if (dst.reg != R_RSP && dst.reg != R_RBP) {
      continue;
    }

    const auto addr = dst.addr;

    if (addr == offset + 0) {
      guid.data1 = static_cast<uint32_t>(src.value);
      counter += 4;
    } else if (addr == offset + 4) {
      guid.data2 = static_cast<uint16_t>(src.value & 0xffff);
      guid.data3 = static_cast<uint16_t>((src.value >> 16) & 0xffff);
      counter += 4;
    } else if (addr == offset + 8) {
      decode_dword(static_cast<uint32_t>(src.value), &guid.data4[0]);
      counter += 4;
    } else if (addr == offset + 12) {
      decode_dword(static_cast<uint32_t>(src.value), &guid.data4[4]);
      counter += 4;
    }
  }

  return guid;
}

std::string efi_utils::get_table_name(const std::string &service_name) {
  for (auto i = 0; i < g_boot_services_table_all_count; i++) {
    if (g_boot_services_table_all[i].name == service_name) {
      return "EFI_BOOT_SERVICES";
    }
  }

  for (auto i = 0; i < g_runtime_services_table_all_count; i++) {
    if (g_runtime_services_table_all[i].name == service_name) {
      return "EFI_RUNTIME_SERVICES";
    }
  }

  return "Unknown";
}

std::string efi_utils::lookup_boot_service_name(uint64_t offset) {
  for (auto i = 0; i < g_boot_services_table_all_count; i++) {
    if (g_boot_services_table_all[i].offset64 == offset) {
      return g_boot_services_table_all[i].name;
    }
  }

  return "Unknown";
}

std::string efi_utils::lookup_runtime_service_name(uint64_t offset) {
  for (auto i = 0; i < g_runtime_services_table_all_count; i++) {
    if (g_runtime_services_table_all[i].offset64 == offset) {
      return g_runtime_services_table_all[i].name;
    }
  }

  return "Unknown";
}

uint16_t get_machine_type() {
  ea_t pe_offset = get_dword(0x3c);
  return get_word(pe_offset + 4);
}

uint32_t u32_addr(ea_t addr) { return addr; }
uint64_t u64_addr(ea_t addr) { return addr; }

size_t get_ptrsize() { return inf_is_64bit() ? 8 : 4; }

#if IDA_SDK_VERSION >= 850
tid_t import_type(const til_t *til, int _idx, const char *name) {
  tinfo_t tinfo;
  if (!tinfo.get_named_type(til, name)) {
    return BADADDR;
  }

  return tinfo.force_tid();
}
#endif
