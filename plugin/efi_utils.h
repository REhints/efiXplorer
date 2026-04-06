// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_defs.h"
#include <string>

namespace efi_utils {
analysis_kind_t get_analysis_kind();

bool add_struct_for_shifted_ptr();
bool add_efi_standalone_smm_entry_point();

bool addr_in_tables(const ea_set_t &t1, const ea_set_t &t2, ea_t ea);
bool addr_in_tables(const ea_set_t &t1, const ea_set_t &t2, const ea_set_t &t3,
                    ea_t ea);
bool json_in_vec(const json_list_t &vec, const json &item);
bool uint64_in_vec(const uint64_list_t &vec, uint64_t value);

bool check_boot_service_protocol_xrefs(ea_t call_addr);
bool check_boot_service_protocol(ea_t call_addr);
bool check_install_protocol(ea_t ea);
bool mark_copies_for_gvars(const ea_set_t &gvars, const std::string &type);
bool op_stroff(ea_t addr, std::string type);
bool set_ptr_type(ea_t addr, std::string type);
bool set_ret_to_pei_svc(ea_t start_ea);
bool summary_json_exists();
bool valid_guid(json guid);
bool get_arg_addrs_with(eavec_t *out, ea_t caller, size_t num_args);

ea_set_t find_data(ea_t start_ea, ea_t end_ea, uchar *data, size_t len);
ea_set_t get_xrefs_to_array(ea_t addr);
ea_set_t get_xrefs(ea_t addr);
ea_set_t search_protocol(const std::string &protocol);

ea_t find_unknown_bs_var64(ea_t ea);

efi_guid_t get_global_guid(ea_t addr);
efi_guid_t get_local_guid(func_t *f, uint64_t offset);

ffs_file_type_t ask_file_type(json_list_t *m_all_guids);

json get_guid_by_address(ea_t addr);

qstring get_module_name_loader(ea_t addr);

std::filesystem::path get_guids_json_file();
std::filesystem::path get_summary_file();

std::string as_hex(uint64_t value);
std::string get_table_name(const std::string &service_name);
std::string get_wide_string(ea_t addr);
std::string guid_to_string(const json &guid);
std::string lookup_boot_service_name(uint64_t offset);
std::string lookup_runtime_service_name(uint64_t offset);
std::string type_to_name(std::string type);

uint8_list_t unpack_guid(std::string guid);

void op_stroff_for_global_interface(ea_set_t xrefs, qstring type_name);
void op_stroff_for_interface(xreflist_t local_xrefs, qstring type_name);
void set_const_char16_type(ea_t ea);
void set_entry_arg_to_pei_svc();
void set_pei_entry_type_for_uefi();
void set_guid_type(ea_t ea);
void set_ptr_type_and_name(ea_t ea, std::string name, std::string type);
void set_type_and_name(ea_t ea, std::string name, std::string type);

int log(const char *fmt, ...);
} // namespace efi_utils

uint16_t get_machine_type();
uint32_t u32_addr(ea_t addr);
uint64_t u64_addr(ea_t addr);
size_t get_ptrsize();

#if IDA_SDK_VERSION >= 850
tid_t import_type(const til_t *til, int _idx, const char *name);
#endif
