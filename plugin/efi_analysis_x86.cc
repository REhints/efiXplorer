// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_analysis.h"
#include "efi_global.h"
#include "efi_ui.h"
#include "efi_utils.h"
#ifdef HEX_RAYS
#include "efi_hexrays.h"
#endif

#include <map>
#include <string>
#include <utility>

extern ea_set_t g_get_smst_location_calls;
extern ea_set_t g_smm_get_variable_calls;
extern ea_set_t g_smm_set_variable_calls;

efi_analysis::efi_analyser_t::efi_analyser_t() {
  // 32-bit, 64-bit, ARM or UEFI (in loader instance)
  m_analysis_kind = efi_utils::get_analysis_kind();

  // get guids.json path
  m_guids_json_path /= efi_utils::get_guids_json_file();

  func_t *start_func = nullptr;
  func_t *end_func = nullptr;

  // get start address for scan
  start_func = getn_func(0);
  if (start_func) {
    m_start_addr = start_func->start_ea;
  }

  // get end address for scan
  end_func = getn_func(get_func_qty() - 1);
  if (end_func) {
    m_end_addr = end_func->end_ea;
  }

  // save all m_funcs
  for (auto i = 0; i < get_func_qty(); ++i) {
    const auto func = getn_func(i);
    m_funcs.insert(func->start_ea);
  }

  ea_list_t addrs;
  for (const auto &service : m_prot_bs_names) {
    m_boot_services[service] = addrs;
  }

  for (const auto &service : m_prot_smms_names) {
    m_smm_services[service] = addrs;
  }

  try {
    // load protocols from guids.json file
    std::ifstream in(m_guids_json_path);
    in >> m_guiddb;
  } catch (const std::exception &e) {
    m_guiddb.clear();
    warning("%s: %s\n", g_plugin_name, "guids.json file is invalid");
  }

  // get reverse dictionary
  for (const auto &[key, value] : m_guiddb.items()) {
    m_guiddb_map[value] = key;
  }

  // set mask and masked value for MACRO_EFI enum value detection
  if (m_analysis_kind == analysis_kind_t::x86_32 ||
      (m_analysis_kind == analysis_kind_t::uefi && inf_is_32bit_exactly())) {
    m_mask = 0xffffff00;
    m_masked_value = 0x80000000;
  } else {
    // analysis_kind_t::x86_64
    // analysis_kind_t::aarch64
    // analysis_kind_t::uefi (64-bit)
    m_mask = 0xffffffffffffff00;
    m_masked_value = 0x8000000000000000;
  }
}

efi_analysis::efi_analyser_t::~efi_analyser_t() {
  m_funcs.clear();

  m_st_list.clear();
  m_bs_list.clear();
  m_rt_list.clear();
  m_smst_list.clear();
  m_image_handle_list.clear();
  m_runtime_services_list.clear();

  m_stack_guids.clear();
  m_data_guids.clear();

  m_code_segs.clear();
  m_data_segs.clear();

  m_callout_addrs.clear();
  m_exc_funcs.clear();
  m_read_save_state_calls.clear();
  m_smi_handlers.clear();
  m_child_smi_handlers.clear();

  m_double_get_variable_pei.clear();
  m_double_get_variable.clear();
  m_double_get_variable_smm.clear();

  g_get_smst_location_calls.clear();
  g_smm_get_variable_calls.clear();
  g_smm_set_variable_calls.clear();

#ifdef HEX_RAYS
  if (init_hexrays_plugin()) {
    clear_cached_cfuncs();
  }
#endif
}

void efi_analysis::efi_analyser_t::set_pvalues() {
  if (m_ftype == ffs_file_type_t::driver) {
    m_pname = "protocols";
    m_pkey = "prot_name";
    m_ptable = &m_all_protocols;
  } else if (m_ftype == ffs_file_type_t::peim) {
    m_pname = "ppis";
    m_pkey = "ppi_name";
    m_ptable = &m_all_ppis;
  }
}

//--------------------------------------------------------------------------
// get all .text and .data segments
void efi_analysis::efi_analyser_t::get_segments() {
  for (segment_t *s = get_first_seg(); s != nullptr;
       s = get_next_seg(s->start_ea)) {
    qstring seg_name;
    get_segm_name(&seg_name, s);

    string_list_t code_seg_names{
        ".text", ".code"}; // for compatibility with ida-efitools2
    for (auto name : code_seg_names) {
      auto index = seg_name.find(name.c_str());
      if (index != std::string::npos) {
        // fix permissions and class for code segment
        // in order for decompilation to work properly
        s->perm = (SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC);
        set_segm_class(s, "DATA");
        m_code_segs.push_back(s);
        continue;
      }
    }

    auto index = seg_name.find(".data");
    if (index != std::string::npos) {
      m_data_segs.push_back(s);
      continue;
    }
  }

  // print all .text and .code segments addresses
  for (auto seg : m_code_segs) {
    segment_t *s = seg;
    efi_utils::log("code segment: 0x%" PRIx64 "\n", u64_addr(s->start_ea));
  }

  // print all .data segments addresses
  for (auto seg : m_data_segs) {
    segment_t *s = seg;
    efi_utils::log("data segment: 0x%" PRIx64 "\n", u64_addr(s->start_ea));
  }
}

// TODO(yeggor):
// merge find_image_handle64 and find_system_table64

//--------------------------------------------------------------------------
// find gImageHandle address for 64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_image_handle64() {
  insn_t insn;
  for (auto idx = 0; idx < get_entry_qty(); ++idx) {
    // get address of entry point
    const auto ord = get_entry_ordinal(idx);
    auto ea = get_entry(ord);

    // search for EFI_IMAGE_HANDLE, check 8 instructions
    for (auto i = 0; i < 8; i++) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
          insn.ops[1].reg == R_RCX && insn.ops[0].type == o_mem) {
        efi_utils::set_type_and_name(insn.ops[0].addr, "gImageHandle",
                                     "EFI_IMAGE_HANDLE");
        m_image_handle_list.insert(insn.ops[0].addr);
        break;
      }
      ea = next_head(ea, m_end_addr);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// find gST address for 64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_system_table64() {
  insn_t insn;
  for (auto idx = 0; idx < get_entry_qty(); ++idx) {
    // get address of entry point
    const auto ord = get_entry_ordinal(idx);
    auto ea = get_entry(ord);

    // search for EFI_SYSTEM_TABLE, check 16 instructions
    for (auto i = 0; i < 16; ++i) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
          insn.ops[1].reg == R_RDX && insn.ops[0].type == o_mem) {
        efi_utils::set_ptr_type_and_name(insn.ops[0].addr, "gST",
                                         "EFI_SYSTEM_TABLE");
        m_st_list.insert(insn.ops[0].addr);
        return true;
      }
      ea = next_head(ea, BADADDR);
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// find and mark gSmst global variable for 64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_smst64() {
  ea_set_t smst_list_smm_base = efi_smm_utils::find_smst_smm_base(m_bs_list);
  ea_set_t smst_list_sw_dispatch =
      efi_smm_utils::find_smst_sw_dispatch(m_bs_list);
  m_smst_list.insert(smst_list_sw_dispatch.begin(),
                     smst_list_sw_dispatch.end());
  m_smst_list.insert(smst_list_smm_base.begin(), smst_list_smm_base.end());

  for (const auto smst : m_smst_list) {
    efi_utils::log("0x%" PRIx64 ": gSmst\n", u64_addr(smst));
  }

  return !m_smst_list.empty();
}

//--------------------------------------------------------------------------
// find and mark gSmst global and local variable address for 64-bit
// modules after Hex-Rays based analysis
bool efi_analysis::efi_analyser_x86_t::find_smst_postproc64() {
  for (const auto ea : g_get_smst_location_calls) {
    efi_utils::log("EfiSmmBase2Protocol->GetSmstLocation call: 0x%" PRIx64 "\n",
                   u64_addr(ea));
    insn_t insn;
    auto addr = ea;
    ea_t smst_addr = BADADDR;
    json smst_stack;
    while (true) {
      addr = prev_head(addr, 0);
      decode_insn(&insn, addr);

      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_RDX) {
        switch (insn.ops[1].type) {
        case o_displ:
          if (insn.ops[1].reg == R_RSP || insn.ops[1].reg == R_RBP) {
            smst_addr = insn.ops[1].addr;
            smst_stack["addr"] = smst_addr;
            smst_stack["reg"] = insn.ops[1].reg;
            smst_stack["start"] = next_head(ea, BADADDR);
            // get bounds
            const auto f = get_func(addr);
            if (f == nullptr) {
              smst_stack["end"] = BADADDR;
            } else {
              smst_stack["end"] = f->end_ea;
            }
          }
          break;
        case o_mem:
          smst_addr = insn.ops[1].addr;
          break;
        }
      }

      // exit loop if end of previous basic block found
      if (is_basic_block_end(insn, false)) {
        break;
      }
    }

    if (smst_stack.is_null() && smst_addr != BADADDR) {
      efi_utils::log("   gSmst: 0x%" PRIx64 "\n", u64_addr(smst_addr));
      if (m_smst_list.insert(smst_addr).second) {
        efi_utils::set_ptr_type_and_name(smst_addr, "gSmst",
                                         "_EFI_SMM_SYSTEM_TABLE2");
      }
    }

    if (!smst_stack.is_null()) {
      auto reg = smst_stack["reg"] == R_RSP ? "RSP" : "RBP";
      efi_utils::log("   Smst: 0x%" PRIx64 ", reg = %s\n", u64_addr(smst_addr),
                     reg);

      // try to extract ChildSwSmiHandler
      auto counter = 0;
      ea_t ea = smst_stack["start"];
      uint16_t smst_reg = NONE_REG;
      uint64_t rcx_last = BADADDR;
      while (ea < smst_stack["end"]) {
        counter += 1;
        if (counter > 500) {
          break; // just in case
        }

        ea = next_head(ea, BADADDR);
        decode_insn(&insn, ea);

        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_displ &&
            smst_stack["addr"] == insn.ops[1].addr) {
          switch (insn.ops[1].reg) {
          case R_RSP:
            if (smst_stack["reg"] == R_RSP) {
              smst_reg = insn.ops[0].reg;
            }
            break;
          case R_RBP:
            if (smst_stack["reg"] == R_RBP) {
              smst_reg = insn.ops[0].reg;
            }
          default:
            break;
          }
        }

        // save potencial ChildSwSmiHandler address
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == R_RCX && insn.ops[1].type == o_mem) {
          rcx_last = insn.ops[1].addr;
        }

        if (rcx_last == BADADDR || smst_reg == NONE_REG) {
          continue;
        }

        if (insn.itype == NN_callni && insn.ops[0].type == o_displ &&
            insn.ops[0].reg == smst_reg && insn.ops[0].addr == 0xe0) {
          efi_utils::op_stroff(ea, "_EFI_SMM_SYSTEM_TABLE2");

          // save child SW SMI handler
          func_t *handler_func = get_func(rcx_last);
          if (handler_func != nullptr) {
            m_child_smi_handlers.push_back(handler_func);
            set_name(rcx_last, "ChildSwSmiHandler", SN_FORCE);
            break;
          }
        }
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// find gBS addresses for 32-bit and 64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_boot_services_tables() {
  // init architecture specific constants
  auto BS_OFFSET = BS_OFFSET_64;
  uint16_t R_SP = R_RSP;

  if (m_analysis_kind == analysis_kind_t::x86_32) {
    BS_OFFSET = BS_OFFSET_32;
    R_SP = R_ESP;
  }

  insn_t insn;
  for (auto seg : m_code_segs) {
    segment_t *s = seg;
    ea_t ea = s->start_ea;
    uint16_t bs_reg = 0;
    uint16_t st_reg = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
          insn.ops[1].phrase != R_SP) {
        if (insn.ops[0].type == o_reg && insn.ops[1].addr == BS_OFFSET) {
          auto bs_found = false;
          auto st_found = false;
          ea_t base_insn_addr = BADADDR;
          bs_reg = insn.ops[0].reg;
          st_reg = insn.ops[1].phrase;

          // found BS_OFFSET, check 10 instructions below
          for (auto i = 0; i < 10; i++) {
            ea = next_head(ea, m_end_addr);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov &&
                  next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg &&
                  next_insn.ops[1].reg == bs_reg) {
                base_insn_addr = ea;
                if (m_bs_list.insert(var_addr).second) {
                  efi_utils::set_ptr_type_and_name(var_addr, "gBS",
                                                   "EFI_BOOT_SERVICES");
                }
                bs_found = true;
              }
            }

            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[0].type == o_mem) {
              if (insn.ops[1].reg == bs_reg && !bs_found) {
                base_insn_addr = ea;
                var_addr = insn.ops[0].addr;
                if (m_bs_list.insert(var_addr).second) {
                  efi_utils::set_ptr_type_and_name(var_addr, "gBS",
                                                   "EFI_BOOT_SERVICES");
                }
                bs_found = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == st_reg && !st_found && st_reg != bs_reg) {
                var_addr = insn.ops[0].addr;
                if (!efi_utils::addr_in_tables(m_st_list, m_bs_list, m_rt_list,
                                               var_addr)) {
                  efi_utils::set_ptr_type_and_name(var_addr, "gST",
                                                   "EFI_SYSTEM_TABLE");
                  m_st_list.insert(var_addr);
                }
                st_found = true;
              }
            }

            if (bs_found && st_found) {
              break;
            }

            if (bs_found && !st_found) {
              // check 8 instructions above base_insn_addr
              auto addr = base_insn_addr;
              for (auto i = 0; i < 8; i++) {
                addr = prev_head(addr, m_start_addr);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == st_reg && insn.ops[0].type == o_mem) {
                  var_addr = insn.ops[0].addr;
                  if (!efi_utils::addr_in_tables(m_st_list, m_bs_list,
                                                 m_rt_list, var_addr)) {
                    efi_utils::set_ptr_type_and_name(var_addr, "gST",
                                                     "EFI_SYSTEM_TABLE");
                    m_st_list.insert(var_addr);
                  }
                  st_found = true;
                  break;
                }
              }
            }
          }
        }
      }
    }
  }
  return !m_bs_list.empty();
}

//--------------------------------------------------------------------------
// find gRT addresses for 32-bit and 64-bit modules
bool efi_analysis::efi_analyser_x86_t::find_runtime_services_tables() {
  // init architecture specific constants
  auto RT_OFFSET = RT_OFFSET_64;
  uint16_t R_SP = R_RSP;

  if (m_analysis_kind == analysis_kind_t::x86_32) {
    RT_OFFSET = RT_OFFSET_32;
    R_SP = R_ESP;
  }

  insn_t insn;
  for (auto seg : m_code_segs) {
    segment_t *s = seg;
    ea_t ea = s->start_ea;
    uint16_t rt_register = 0;
    uint16_t st_reg = 0;
    ea_t var_addr = BADADDR; // current global variable address
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
          insn.ops[1].phrase != R_SP) {
        if (insn.ops[0].type == o_reg && insn.ops[1].addr == RT_OFFSET) {
          rt_register = insn.ops[0].reg;
          st_reg = insn.ops[1].phrase;
          auto rt_found = false;
          auto st_found = false;
          ea_t base_insn_addr;

          // found RT_OFFSET, check 10 instructions below
          for (auto i = 0; i < 10; i++) {
            ea = next_head(ea, m_end_addr);
            decode_insn(&insn, ea);
            if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
                insn.ops[1].type == o_imm) {
              var_addr = insn.ops[1].value;
              auto phrase_reg = insn.ops[0].phrase;
              auto next_ea = next_head(ea, BADADDR);
              insn_t next_insn;
              decode_insn(&next_insn, next_ea);
              if (next_insn.itype == NN_mov &&
                  next_insn.ops[0].type == o_phrase &&
                  next_insn.ops[0].phrase == phrase_reg &&
                  next_insn.ops[1].type == o_reg &&
                  next_insn.ops[1].reg == rt_register) {
                base_insn_addr = ea;
                if (m_rt_list.insert(var_addr).second) {
                  efi_utils::set_ptr_type_and_name(var_addr, "gRT",
                                                   "EFI_RUNTIME_SERVICES");
                }
                rt_found = true;
              }
            }

            if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                insn.ops[0].type == o_mem) {
              if (insn.ops[1].reg == rt_register && !rt_found) {
                base_insn_addr = ea;
                var_addr = insn.ops[0].addr;
                if (m_rt_list.insert(var_addr).second) {
                  efi_utils::set_ptr_type_and_name(var_addr, "gRT",
                                                   "EFI_RUNTIME_SERVICES");
                }
                rt_found = true;
              }

              // here you can also find gST
              if (insn.ops[1].reg == st_reg && !st_found &&
                  st_reg != rt_register) {
                var_addr = insn.ops[0].addr;
                if (!efi_utils::addr_in_tables(m_st_list, m_bs_list, m_rt_list,
                                               var_addr)) {
                  efi_utils::set_ptr_type_and_name(insn.ops[0].addr, "gST",
                                                   "EFI_SYSTEM_TABLE");
                  m_st_list.insert(insn.ops[0].addr);
                }
                st_found = true;
              }
            }

            if (rt_found && st_found) {
              break;
            }

            if (rt_found && !st_found) {
              // check 8 instructions above base_insn_addr
              auto addr = base_insn_addr;
              for (auto i = 0; i < 8; i++) {
                addr = prev_head(addr, m_start_addr);
                decode_insn(&insn, addr);
                if (insn.itype == NN_mov && insn.ops[1].type == o_reg &&
                    insn.ops[1].reg == st_reg && insn.ops[0].type == o_mem) {
                  if (!efi_utils::addr_in_tables(m_st_list, m_bs_list,
                                                 m_rt_list, var_addr)) {
                    efi_utils::set_ptr_type_and_name(var_addr, "gST",
                                                     "EFI_SYSTEM_TABLE");
                    m_st_list.insert(var_addr);
                  }
                  st_found = true;
                  break;
                }
              }
            }
          }
        }
      }
    }
  }

  return !m_rt_list.empty();
}

//--------------------------------------------------------------------------
// get all boot services by xrefs for 32-bit and 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_boot_services_all() {
  if (m_bs_list.empty()) {
    return;
  }

  insn_t insn;
  for (auto bs : m_bs_list) {
    auto xrefs = efi_utils::get_xrefs(bs);
    for (auto ea : xrefs) {
      bool found = false;
      decode_insn(&insn, ea);

      if (!(insn.itype == NN_mov &&
            (insn.ops[1].addr == bs || insn.ops[1].value == bs))) {
        continue;
      }

      auto bs_reg = insn.ops[0].reg;

      // 16 instructions below
      auto addr = ea;
      ea_t service_offset = BADADDR;
      for (auto i = 0; i < 16; i++) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);

        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].reg == bs_reg && insn.ops[1].addr) {
          service_offset = insn.ops[1].addr;
        }

        if (insn.itype == NN_callni && insn.ops[0].reg == bs_reg) {
          if (insn.ops[0].addr) {
            service_offset = insn.ops[0].addr;
          }

          for (int j = 0; j < g_boot_services_table_all_count; j++) {
            // architecture-specific variables
            auto offset = g_boot_services_table_all[j].offset64;
            if (m_analysis_kind == analysis_kind_t::x86_32) {
              offset = g_boot_services_table_all[j].offset32;
            }

            if (service_offset == u32_addr(offset)) {
              // additional check for gBS->RegisterProtocolNotify
              // (can be confused with gSmst->SmmInstallProtocolInterface)
              if (u32_addr(offset) == 0xa8) {
                if (!efi_utils::check_boot_service_protocol(addr)) {
                  break;
                }
              }

              efi_utils::op_stroff(addr, "EFI_BOOT_SERVICES");
              efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(addr),
                             g_boot_services_table_all[j].name);

              m_boot_services[g_boot_services_table_all[j].name].push_back(
                  addr);

              json s;
              s["address"] = addr;
              s["service_name"] = g_boot_services_table_all[j].name;
              s["table_name"] = "EFI_BOOT_SERVICES";
              s["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              s["args"] = args;

              if (!efi_utils::json_in_vec(m_all_services, s)) {
                m_all_services.push_back(s);
              }

              found = true;
              break;
            }
          }
        }

        if (found) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get all runtime services for 32-bit and 64-bit modules by xrefs
void efi_analysis::efi_analyser_x86_t::get_runtime_services_all() {
  if (m_rt_list.empty()) {
    return;
  }

  insn_t insn;
  for (auto rt : m_rt_list) {
    auto xrefs = efi_utils::get_xrefs(rt);
    for (auto ea : xrefs) {
      decode_insn(&insn, ea);

      if (!(insn.itype == NN_mov &&
            (insn.ops[1].addr == rt || insn.ops[1].value == rt))) {
        continue;
      }

      auto rt_reg = insn.ops[0].reg;

      // 16 instructions below
      ea_t addr = ea;
      ea_t service_offset = BADADDR;
      for (int i = 0; i < 16; i++) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);

        if (insn.itype == NN_mov && insn.ops[1].type == o_displ &&
            insn.ops[1].reg == rt_reg && insn.ops[1].addr) {
          service_offset = insn.ops[1].addr;
        }

        if (insn.itype == NN_callni && insn.ops[0].reg == rt_reg) {
          if (insn.ops[0].addr) {
            service_offset = insn.ops[0].addr;
          }

          for (int j = 0; j < g_runtime_services_table_all_count; j++) {
            // architecture specific variables
            auto offset = g_runtime_services_table_all[j].offset64;
            if (m_analysis_kind == analysis_kind_t::x86_32) {
              offset = g_runtime_services_table_all[j].offset32;
            }
            if (service_offset == u32_addr(offset)) {
              efi_utils::op_stroff(addr, "EFI_RUNTIME_SERVICES");
              efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(addr),
                             g_runtime_services_table_all[j].name);

              m_runtime_services_all[g_runtime_services_table_all[j].name]
                  .push_back(addr);

              json s;
              s["address"] = addr;
              s["service_name"] = g_runtime_services_table_all[j].name;
              s["table_name"] = "EFI_RUNTIME_SERVICES";
              s["offset"] = offset;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              s["args"] = args;

              if (!efi_utils::json_in_vec(m_all_services, s)) {
                m_all_services.push_back(s);
              }
              m_runtime_services_list.insert(addr);
              break;
            }
          }
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get all SMM services for 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_smm_services_all64() {
  if (m_smst_list.empty()) {
    return;
  }

  insn_t insn;
  for (auto smms : m_smst_list) {
    auto xrefs = efi_utils::get_xrefs(smms);
    for (auto ea : xrefs) {
      auto addr = ea;
      decode_insn(&insn, addr);

      if (!(insn.itype == NN_mov && insn.ops[1].type == o_mem &&
            insn.ops[1].addr == smms)) {
        continue;
      }

      auto smst_reg = insn.ops[0].reg;
      uint32_t offset = 0;

      while (!is_basic_block_end(insn, false) || addr == ea) {
        addr = next_head(addr, BADADDR);
        decode_insn(&insn, addr);

        // handle cases like this
        // mov rax, cs:gSmst
        // mov rax, [rax+0E0h] <- we are here
        // ...
        // call rax
        if (insn.itype == NN_mov && insn.ops[0].reg == smst_reg &&
            (insn.ops[1].type == o_displ || insn.ops[1].type == o_phrase) &&
            insn.ops[1].reg == smst_reg) {
          offset = u32_addr(insn.ops[1].addr);
        }

        // add NN_jmpni insn type to handle such cases
        // jmp qword ptr [r9+0D0h]
        if ((insn.itype == NN_callni || insn.itype == NN_jmpni) &&
            insn.ops[0].reg == smst_reg) {
          // if instruction is not call smst_reg, rewrite the offset
          if (insn.ops[0].type != o_reg) {
            offset = insn.ops[0].addr;
          }

          for (int j = 0; j < g_smm_services_table_all_count; j++) {
            if (offset == g_smm_services_table_all[j].offset64) {
              // handle SmiHandlerRegister service call
              if (g_smm_services_table_all[j].offset64 == 0xe0) {
                // set name for Handler argument
                auto smi_handler_addr =
                    efi_smm_utils::mark_child_sw_smi_handlers(addr);
                // save SMI handler
                func_t *child_smi_handler = get_func(smi_handler_addr);
                if (child_smi_handler != nullptr) {
                  m_child_smi_handlers.push_back(child_smi_handler);
                }
              }

              efi_utils::op_stroff(addr, "_EFI_SMM_SYSTEM_TABLE2");
              efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(addr),
                             g_smm_services_table_all[j].name);

              // add address to m_smm_services
              if (find(m_prot_smms_names.begin(), m_prot_smms_names.end(),
                       g_smm_services_table_all[j].name) !=
                  m_prot_smms_names.end()) {
                m_smm_services[g_smm_services_table_all[j].name].push_back(
                    addr);
              }
              m_smm_services_all[g_smm_services_table_all[j].name].push_back(
                  addr);

              json s;
              s["address"] = addr;
              s["service_name"] = g_smm_services_table_all[j].name;
              s["table_name"] = "_EFI_SMM_SYSTEM_TABLE2";
              s["offset"] = g_smm_services_table_all[j].offset64;

              // add code addresses for arguments
              eavec_t args;
              get_arg_addrs(&args, addr);
              s["args"] = args;

              if (!efi_utils::json_in_vec(m_all_services, s)) {
                m_all_services.push_back(s);
              }
              break;
            }
          }
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get all PEI services for 32-bit modules
void efi_analysis::efi_analyser_x86_t::get_pei_services_all32() {
  ea_t ea = m_start_addr;
  insn_t insn;
  auto found = false;
  while (ea <= m_end_addr) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni &&
        (insn.ops[0].reg == R_EAX || insn.ops[0].reg == R_ECX ||
         insn.ops[0].reg == R_EDX)) {
      for (int j = 0; j < g_pei_services_table32_count; j++) {
        if (insn.ops[0].addr == u32_addr(g_pei_services_table32[j].offset)) {
          bool found_src_reg = false;
          ea_t address = ea;
          insn_t a_insn;
          uint16_t src_reg = NONE_REG;

          // 15 instructions above
          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&a_insn, address);
            if (a_insn.itype == NN_mov && a_insn.ops[0].type == o_reg &&
                a_insn.ops[0].reg == insn.ops[0].reg &&
                a_insn.ops[1].type == o_phrase) {
              found_src_reg = true;
              src_reg = a_insn.ops[1].reg;
            }
          }

          bool found_push = false;

          // 15 instructions above
          address = ea;
          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&a_insn, address);
            if (a_insn.itype == NN_push) {
              if (a_insn.ops[0].type == o_reg && a_insn.ops[0].reg == src_reg) {
                found_push = true;
              }
              break;
            }
          }

          if (found_src_reg && found_push) {
            eavec_t args;
            get_arg_addrs(&args, ea);
            if (args.empty()) {
              // looks like a FP
              break;
            }

            efi_utils::op_stroff(ea, "EFI_PEI_SERVICES");
            efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(ea),
                           g_pei_services_table32[j].name);

            m_pei_services_all[g_pei_services_table32[j].name].push_back(ea);

            json s;
            s["address"] = ea;
            s["service_name"] = g_pei_services_table32[j].name;
            s["table_name"] = "EFI_PEI_SERVICES";
            s["offset"] = g_pei_services_table32[j].offset;

            // add code addresses for arguments
            s["args"] = args;

            if (!efi_utils::json_in_vec(m_all_services, s)) {
              m_all_services.push_back(s);
            }
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get all EFI_PEI_READ_ONLY_VARIABLE2_PPI (GetVariable, NextVariableName)
void efi_analysis::efi_analyser_x86_t::get_variable_ppi_calls_all32() {
  ea_t ea = m_start_addr;
  insn_t insn;
  auto found = false;
  while (ea <= m_end_addr) {
    ea = next_head(ea, BADADDR);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].type == o_phrase) {
      for (int j = 0; j < g_variable_ppi_table_all_count; j++) {
        if (insn.ops[0].addr ==
            u32_addr(g_variable_ppi_table_all[j].offset32)) {
          uint16_t ppi_reg = insn.ops[0].reg;
          insn_t a_insn;
          ea_t address = ea;
          bool found_push = false;

          for (auto j = 0; j < 15; j++) {
            address = prev_head(address, m_start_addr);
            decode_insn(&a_insn, address);
            if (a_insn.itype == NN_push) {
              if (a_insn.ops[0].type == o_reg && a_insn.ops[0].reg == ppi_reg) {
                found_push = true;
              }
              break;
            }
          }

          if (found_push) {
            efi_utils::op_stroff(ea, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
            efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(ea),
                           g_variable_ppi_table_all[j].name);

            std::string ppi_call =
                "VariablePPI->" +
                static_cast<std::string>(g_variable_ppi_table_all[j].name);
            m_ppi_calls_all[ppi_call].push_back(ea);

            json s;
            s["address"] = ea;
            s["service_name"] = ppi_call;
            s["table_name"] = "EFI_PEI_READ_ONLY_VARIABLE2_PPI";
            s["offset"] = g_variable_ppi_table_all[j].offset32;

            // add code addresses for arguments
            eavec_t args;
            get_arg_addrs(&args, ea);
            s["args"] = args;

            if (!efi_utils::json_in_vec(m_all_services, s)) {
              m_all_services.push_back(s);
            }
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get PPI names for 32-bit PEI modules
void efi_analysis::efi_analyser_x86_t::get_ppi_names32() {
  ea_t start = m_start_addr;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_pei_services_table32_count; i++) {
    if (g_pei_services_table32[i].push_number == NONE_PUSH ||
        !m_pei_services_all.contains(g_pei_services_table_all[i].name)) {
      continue;
    }

    ea_list_t addrs = m_pei_services_all[g_pei_services_table32[i].name];

    // for each PEI service
    for (auto ea : addrs) {
      ea_t address = ea;

      insn_t insn;
      ea_t guid_code_address = 0;
      ea_t guid_data_address = 0;
      uint16_t push_counter = 0;
      auto found = false;

      // check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        if (insn.itype == NN_push) {
          push_counter += 1;
        }

        if (push_counter == g_pei_services_table32[i].push_number &&
            insn.ops[0].type == o_imm &&
            (insn.ops[0].value & 0xffffffff) >= start &&
            insn.ops[0].value != BADADDR) {
          // found `push {GUID}` instruction
          guid_code_address = address;
          guid_data_address = insn.ops[0].value & 0xffffffff;
          found = true;
          break;
        }

        // exit loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }
      }

      if (found) {
        efi_utils::log("found PPI GUID parameter at 0x%" PRIx64 "\n",
                       u64_addr(guid_code_address));
        auto guid = efi_utils::get_guid_by_address(guid_data_address);
        if (!efi_utils::valid_guid(guid)) {
          continue;
        }

        json s;
        s["address"] = guid_data_address;
        s["xref"] = guid_code_address;
        s["service"] = g_pei_services_table_all[i].name;
        s["guid"] = efi_utils::guid_to_string(guid);
        s["module"] = "Current";

        // find GUID name
        auto it = m_guiddb_map.find(guid);
        if (it != m_guiddb_map.end()) {
          std::string name = it->second;
          s["ppi_name"] = name;

          if (!efi_utils::json_in_vec(m_all_ppis, s)) {
            m_all_ppis.push_back(s);
          }
          continue;
        }

        // unknown PPI
        if (s["ppi_name"].is_null()) {
          s["ppi_name"] = "UNKNOWN_PPI";

          if (!efi_utils::json_in_vec(m_all_ppis, s)) {
            m_all_ppis.push_back(s);
          }
          continue;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// get boot services by protocols for 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_prot_boot_services64() {
  insn_t insn;
  for (auto s : m_code_segs) {
    ea_t ea = s->start_ea;
    uint16_t bs_reg = 0;
    while (ea <= s->end_ea) {
      ea = next_head(ea, m_end_addr);
      decode_insn(&insn, ea);
      if (insn.itype != NN_callni || insn.ops[0].reg != R_RAX) {
        continue;
      }
      for (auto i = 0; i < g_boot_services_table64_count; i++) {
        if (insn.ops[0].addr != u32_addr(g_boot_services_table64[i].offset)) {
          continue;
        }

        // additional check for gBS->RegisterProtocolNotify
        // (can be confused with gSmst->SmmInstallProtocolInterface)
        if (u32_addr(g_boot_services_table64[i].offset) == 0xa8) {
          if (!efi_utils::check_boot_service_protocol(ea)) {
            break;
          }
        }

        // check that address does not belong to the protocol interface
        // (gBS != gInterface)
        auto bs_addr = efi_utils::find_unknown_bs_var64(ea);
        if (m_rt_list.contains(bs_addr) ||
            !efi_utils::check_boot_service_protocol_xrefs(bs_addr)) {
          break;
        }

        efi_utils::op_stroff(ea, "EFI_BOOT_SERVICES");
        efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(ea),
                       g_boot_services_table64[i].name);

        m_boot_services[g_boot_services_table64[i].name].push_back(ea);

        json s;
        s["address"] = ea;
        s["service_name"] = g_boot_services_table64[i].name;
        s["table_name"] = "EFI_BOOT_SERVICES";
        s["offset"] = g_boot_services_table64[i].offset;

        // add code addresses for arguments
        eavec_t args;
        get_arg_addrs(&args, ea);
        s["args"] = args;

        if (!efi_utils::json_in_vec(m_all_services, s)) {
          m_all_services.push_back(s);
        }
        break;
      }
    }
  }
}

//--------------------------------------------------------------------------
// get boot services by protocols for 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_prot_boot_services32() {
  ea_t ea = m_start_addr;
  insn_t insn;
  uint16_t bs_reg = 0;
  while (ea <= m_end_addr) {
    ea = next_head(ea, m_end_addr);
    decode_insn(&insn, ea);
    if (insn.itype == NN_callni && insn.ops[0].reg == R_EAX) {
      for (auto i = 0; i < g_boot_services_table32_count; i++) {
        if (insn.ops[0].addr == u32_addr(g_boot_services_table32[i].offset)) {
          efi_utils::op_stroff(ea, "EFI_BOOT_SERVICES");
          efi_utils::log("0x%" PRIx64 ": %s\n", u64_addr(ea),
                         g_boot_services_table32[i].name);

          m_boot_services[g_boot_services_table32[i].name].push_back(ea);

          json s;
          s["address"] = ea;
          s["service_name"] = g_boot_services_table32[i].name;
          s["table_name"] = "EFI_BOOT_SERVICES";
          s["offset"] = g_boot_services_table32[i].offset;

          // add code addresses for arguments
          eavec_t args;
          get_arg_addrs(&args, ea);
          s["args"] = args;

          if (!efi_utils::json_in_vec(m_all_services, s)) {
            m_all_services.push_back(s);
          }
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// find other addresses of gBS variables for 64-bit modules
void efi_analysis::efi_analyser_x86_t::find_other_boot_services_tables64() {
  for (auto s : m_all_services) {
    std::string table_name = s["table_name"];
    if (table_name.compare("EFI_BOOT_SERVICES")) {
      continue;
    }

    auto offset = u32_addr(s["offset"]);
    if (offset < 0xf0) {
      continue;
    }

    ea_t addr = s["address"];
    ea_t addr_bs = efi_utils::find_unknown_bs_var64(addr);

    if (addr_bs == BADADDR ||
        efi_utils::addr_in_tables(m_bs_list, m_rt_list, addr_bs)) {
      continue;
    }

    efi_utils::log("found boot services table at 0x%" PRIx64
                   ", address = 0x%" PRIx64 "\n",
                   u64_addr(addr), u64_addr(addr_bs));

    efi_utils::set_ptr_type_and_name(addr_bs, "gBS", "EFI_BOOT_SERVICES");

    m_bs_list.insert(addr_bs);
  }
}

//--------------------------------------------------------------------------
// add protocol in protocols list
bool efi_analysis::efi_analyser_t::add_protocol(std::string service_name,
                                                ea_t guid_addr, ea_t xref_addr,
                                                ea_t call_addr) {
  if (m_analysis_kind != analysis_kind_t::uefi && guid_addr >= m_start_addr &&
      guid_addr <= m_end_addr) {
    return false; // filter FP
  }

  json p;
  auto guid = efi_utils::get_guid_by_address(guid_addr);
  p["address"] = guid_addr;
  p["xref"] = xref_addr;
  p["service"] = service_name;
  p["guid"] = efi_utils::guid_to_string(guid);
  p["ea"] = call_addr;

  qstring module_name("Current");
  if (efi_utils::get_analysis_kind() == analysis_kind_t::uefi) {
    module_name = efi_utils::get_module_name_loader(call_addr);
  }

  p["module"] = module_name.c_str();

  // find GUID name
  auto it = m_guiddb_map.find(guid);
  if (it != m_guiddb_map.end()) {
    std::string name = it->second;
    p["prot_name"] = name;
  } else {
    p["prot_name"] = "UNKNOWN_PROTOCOL_GUID";
    efi_utils::set_type_and_name(guid_addr, "UNKNOWN_PROTOCOL_GUID",
                                 "EFI_GUID");
  }
  if (!efi_utils::json_in_vec(m_all_protocols, p)) {
    m_all_protocols.push_back(p);
  }
  return true;
}

//--------------------------------------------------------------------------
// extract protocols from InstallMultipleProtocolInterfaces service call
bool efi_analysis::efi_analyser_x86_t::
    install_multiple_prot_interfaces_analyser() {
  ea_list_t addrs = m_boot_services["InstallMultipleProtocolInterfaces"];
  std::map<ea_t, ea_t> stack_params;
  insn_t insn;

  for (auto ea : addrs) {
    ea_t address = ea;
    bool found = false;
    bool check_stack = true;
    ea_t handle_arg = BADADDR;
    stack_params.clear();

    // check current basic block
    while (true) {
      address = prev_head(address, m_start_addr);
      decode_insn(&insn, address);

      if (!check_stack && found) {
        break; // installed only one protocol
      }

      // exit loop if end of previous basic block found
      if (is_basic_block_end(insn, false)) {
        break;
      }

      // get handle stack/data parameter
      if (handle_arg == BADADDR && insn.itype == NN_lea &&
          insn.ops[0].reg == R_RCX) {
        switch (insn.ops[1].type) {
        case o_displ:
          if (insn.ops[1].reg == R_RSP || insn.ops[1].reg == R_RBP) {
            handle_arg = insn.ops[1].addr;
          }
          break;
        case o_mem:
          handle_arg = insn.ops[1].addr;
          break;
        }
      }

      // exit loop if last argument found
      if (insn.itype == NN_xor && insn.ops[0].reg == R_R9 &&
          insn.ops[1].reg == R_R9) {
        check_stack = false;
      }

      if (insn.itype == NN_and && insn.ops[0].type == o_displ &&
          (insn.ops[0].reg == R_RSP || insn.ops[0].reg == R_RBP) &&
          insn.ops[0].addr != handle_arg && insn.ops[1].type == o_imm &&
          insn.ops[1].value == 0) {
        check_stack = false;
        break;
      }

      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[1].type == o_mem) {
        switch (insn.ops[0].reg) {
        case R_RDX:
        case R_R9:
          add_protocol("InstallMultipleProtocolInterfaces", insn.ops[1].addr,
                       address, ea);
          found = true;
          break;
        case R_RAX:
          stack_params.insert(std::make_pair(address, insn.ops[1].addr));
          break;
        }
      }
    }

    // enumerate all stack params
    auto index = 0;
    for (auto const &param : stack_params) {
      if (index++ % 2) {
        add_protocol("InstallMultipleProtocolInterfaces", param.second,
                     param.first, ea);
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// get boot services protocols names for 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_bs_prot_names64() {
  if (m_code_segs.empty()) {
    return;
  }
  segment_t *s = m_code_segs.at(0);
  ea_t start = s->start_ea;

  install_multiple_prot_interfaces_analyser();

  for (int i = 0; i < g_boot_services_table64_count; i++) {
    if (g_boot_services_table64[i].offset == 0x148) {
      // handle InstallMultipleProtocolInterfaces separately
      continue;
    }

    ea_list_t addrs = m_boot_services[g_boot_services_table64[i].name];
    for (auto ea : addrs) {
      ea_t address = ea;
      insn_t insn;
      ea_t guid_code_address = 0;
      ea_t guid_data_address = 0;
      auto found = false;

      // check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_boot_services_table64[i].reg &&
            insn.ops[1].type == o_mem) {
          guid_code_address = address;
          guid_data_address = insn.ops[1].addr;
          if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
            found = true;
            break;
          }
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_boot_services_table64[i].reg &&
            insn.ops[1].type == o_imm) {
          guid_code_address = address;
          guid_data_address = insn.ops[1].value;
          if (insn.ops[1].value > start && insn.ops[1].value != BADADDR) {
            found = true;
            break;
          }
        }
      }

      if (found) {
        efi_utils::log("found protocol GUID at 0x%" PRIx64 "\n",
                       u64_addr(guid_code_address));
        auto guid = efi_utils::get_guid_by_address(guid_data_address);
        if (!efi_utils::valid_guid(guid)) {
          continue;
        }

        add_protocol(g_boot_services_table64[i].name, guid_data_address,
                     guid_code_address, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// get boot services protocols names for 32-bit modules
void efi_analysis::efi_analyser_x86_t::get_bs_prot_names32() {
  ea_t start = m_start_addr;
  segment_t *seg_info = get_segm_by_name(".text");
  if (seg_info != nullptr) {
    start = seg_info->start_ea;
  }
  for (int i = 0; i < g_boot_services_table32_count; i++) {
    ea_list_t addrs = m_boot_services[g_boot_services_table32[i].name];

    // for each boot service
    for (auto ea : addrs) {
      ea_t address = ea;
      insn_t insn;
      ea_t guid_code_address = 0;
      ea_t guid_data_address = 0;
      auto found = false;
      uint16_t push_number = g_boot_services_table32[i].push_number;

      // if service is not currently being processed
      if (push_number == NONE_PUSH) {
        break;
      }

      // check current basic block
      uint16_t push_counter = 0;
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit from loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_push) {
          push_counter += 1;
          if (push_counter > push_number) {
            break;
          }
          if (push_counter == push_number) {
            guid_code_address = address;
            guid_data_address = insn.ops[0].value;
            if (insn.ops[0].value > start && insn.ops[0].value != BADADDR) {
              found = true;
              break;
            }
          }
        }
      }

      if (found) {
        efi_utils::log("found protocol GUID at 0x%" PRIx64 "\n",
                       u64_addr(guid_code_address));
        auto guid = efi_utils::get_guid_by_address(guid_data_address);
        if (!efi_utils::valid_guid(guid)) {
          continue;
        }

        add_protocol(g_boot_services_table32[i].name, guid_data_address,
                     guid_code_address, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// get SMM services protocols names for 64-bit modules
void efi_analysis::efi_analyser_x86_t::get_smm_prot_names64() {
  if (m_code_segs.empty()) {
    return;
  }

  segment_t *s = m_code_segs.at(0);
  ea_t start = s->start_ea;
  for (int i = 0; i < g_smm_services_prot64_count; i++) {
    auto addrs = m_smm_services[g_smm_services_prot64[i].name];

    // for each SMM service
    for (auto ea : addrs) {
      ea_t address = ea;
      insn_t insn;
      ea_t guid_code_address = 0;
      ea_t guid_data_address = 0;
      auto found = false;

      // check current basic block
      while (true) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);

        // exit from loop if end of previous basic block found
        if (is_basic_block_end(insn, false)) {
          break;
        }

        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == g_smm_services_prot64[i].reg) {
          guid_code_address = address;
          guid_data_address = insn.ops[1].addr;
          if (insn.ops[1].addr > start && insn.ops[1].addr != BADADDR) {
            found = true;
            break;
          }
        }
      }

      if (found) {
        efi_utils::log("found protocol GUID at 0x%" PRIx64 "\n",
                       u64_addr(guid_code_address));
        auto guid = efi_utils::get_guid_by_address(guid_data_address);
        if (!efi_utils::valid_guid(guid)) {
          continue;
        }

        add_protocol(g_smm_services_prot64[i].name, guid_data_address,
                     guid_code_address, ea);
      }
    }
  }
}

//--------------------------------------------------------------------------
// annotate protocol GUIDs
void efi_analysis::efi_analyser_t::annotate_protocol_guids() {
  for (const auto &prot : *m_ptable) {
    ea_t addr = prot["address"];
    if (m_annotated_protocols.contains(addr)) {
      continue;
    }

    std::string name = prot[m_pkey];
    set_name(addr, name.c_str(), SN_FORCE);
    efi_utils::set_guid_type(addr);
    m_annotated_protocols.insert(addr);
  }
}

//--------------------------------------------------------------------------
// annotate GUIDs found in the .text and .data segment
void efi_analysis::efi_analyser_t::annotate_data_guids() {
  ea_t ptrsize = inf_is_64bit() ? 8 : 4;
  auto guids_segments = m_code_segs;
  guids_segments.insert(guids_segments.end(), m_data_segs.begin(),
                        m_data_segs.end());
  for (auto s : guids_segments) {
    ea_t ea = s->start_ea;
    while (ea != BADADDR && ea <= s->end_ea - 15) {
      if (get_wide_dword(ea) == 0x00000000 ||
          get_wide_dword(ea) == 0xffffffff) {
        ea += 1;
        continue;
      }
      auto guid = efi_utils::get_guid_by_address(ea);

      // find GUID name
      auto it = m_guiddb_map.find(guid);
      if (it != m_guiddb_map.end()) {
        std::string guid_name = it->second;
        set_name(ea, guid_name.c_str(), SN_FORCE);
        efi_utils::set_guid_type(ea);

        // rename PPI
        if (guid_name.length() > 9 &&
            guid_name.rfind("_PPI_GUID") == guid_name.length() - 9) {
          auto xrefs = efi_utils::get_xrefs(ea);
          for (auto addr : xrefs) {
            std::string type_name = guid_name.substr(0, guid_name.length() - 5);
            std::string ppi_name = "g" + efi_utils::type_to_name(type_name);

            ea_t ppi_ea = addr - ptrsize;

            // check flags
            if (ptrsize == 8 && get_wide_dword(ppi_ea + 4)) {
              // 4 high bytes must be 0
              continue;
            }

            uint64_t flags = get_wide_dword(ppi_ea);
            if (!efi_utils::uint64_in_vec(m_ppi_flags, flags)) {
              continue;
            }

            efi_utils::log("found %s PPI at 0x%" PRIx64 "\n", ppi_name.c_str(),
                           u64_addr(ppi_ea));
            set_name(ppi_ea, ppi_name.c_str(), SN_FORCE);
          }
        }

        json g;
        g["address"] = ea;
        g["name"] = guid_name;
        g["guid"] = efi_utils::guid_to_string(guid);
        m_all_guids.push_back(g);
        m_data_guids.push_back(g);
      }

      ea += 1;
    }
  }
}

//--------------------------------------------------------------------------
// find GUIDs stored in local variables for 64-bit modules
void efi_analysis::efi_analyser_x86_t::find_local_guids64() {
  for (auto seg : m_code_segs) {
    segment_t *s = seg;
    ea_t ea = s->start_ea;
    insn_t insn;
    insn_t insn_next;
    while (ea <= s->end_ea) {
      ea = next_head(ea, BADADDR);
      decode_insn(&insn, ea);

      // check if insn like `mov dword ptr [...], data1`
      if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            insn.ops[1].type == o_imm)) {
        continue;
      }

      // get guid->data1 value
      uint32_t data1 = u32_addr(insn.ops[1].value);
      if (!data1 || data1 == 0xffffffff) {
        ea = next_head(ea, BADADDR);
        continue;
      }

      // check 4 insns
      bool exit = false;
      for (auto i = 0; i < 4; i++) {
        auto ea_next = next_head(ea, BADADDR);
        decode_insn(&insn_next, ea_next);
        // check if insn like `mov dword ptr [...], data2`
        if (insn_next.itype == NN_mov && insn_next.ops[0].type == o_displ &&
            insn_next.ops[1].type == o_imm) {
          // get guid->data2 value
          uint16_t data2 = insn_next.ops[1].value;
          if (!data2 || data2 == 0xffff) {
            ea = next_head(ea, BADADDR);
            continue;
          }

          // found guid->data1 and guid->data2 values
          // try to get GUID name
          for (const auto &[name, guid] : m_guiddb.items()) {
            if (data1 == static_cast<uint32_t>(guid[0]) &&
                data2 == static_cast<uint16_t>(guid[1])) {
              std::string name_str = name;
              set_cmt(ea, name.c_str(), true);
              efi_utils::log("found local GUID %s at 0x%" PRIx64 "\n",
                             name.c_str(), u64_addr(ea));

              json g;
              g["address"] = ea;
              g["name"] = name;
              g["guid"] = efi_utils::guid_to_string(guid);
              m_all_guids.push_back(g);
              m_stack_guids.push_back(g);
              exit = true;
              break;
            }
          }
        }
        if (exit) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// search for callouts recursively
void efi_analysis::efi_analyser_x86_t::find_callout_rec(func_t *func) {
  insn_t insn;
  for (ea_t ea = func->start_ea; ea < func->end_ea;
       ea = next_head(ea, BADADDR)) {
    decode_insn(&insn, ea);
    if (insn.itype == NN_call) {
      ea_t next_func_addr = insn.ops[0].addr;
      func_t *next_func = get_func(next_func_addr);
      if (next_func) {
        auto it = std::find(m_exc_funcs.begin(), m_exc_funcs.end(), next_func);
        if (it == m_exc_funcs.end()) {
          m_exc_funcs.push_back(next_func);
          find_callout_rec(next_func);
        }
      }
    }

    if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
        insn.ops[1].type == o_mem) {
      // search for callouts with gBS
      if (m_bs_list.contains(insn.ops[1].addr)) {
        // filter FP
        auto reg = insn.ops[0].reg;
        auto addr = ea;
        insn_t next_insn;
        auto fp = false;
        while (true) {
          addr = next_head(addr, BADADDR);
          decode_insn(&next_insn, addr);
          if ((next_insn.itype == NN_jmpni || next_insn.itype == NN_callni) &&
              next_insn.ops[0].type == o_displ && next_insn.ops[0].reg == reg &&
              next_insn.ops[0].addr == 0x48) {
            fp = true;
            break;
          }
          if (is_basic_block_end(next_insn, false)) {
            break;
          }
        }
        if (!fp) {
          efi_utils::log("found SMM callout via boot services at 0x%" PRIx64
                         "\n",
                         u64_addr(ea));
          m_callout_addrs.insert(ea);
          continue;
        }
      }

      // search for callouts with gRT
      if (m_rt_list.contains(insn.ops[1].addr)) {
        efi_utils::log("found SMM callout via runtime services at 0x%" PRIx64
                       "\n",
                       u64_addr(ea));
        m_callout_addrs.insert(ea);
        continue;
      }

      // search for usage of interfaces installed with gBS->LocateProtocol()
      auto g_addr = insn.ops[1].addr;
      insn_t insn_xref;
      bool found = false;
      // check all xrefs for found global variable
      for (auto xref : efi_utils::get_xrefs(g_addr)) {
        // chcek if it looks like interface
        decode_insn(&insn_xref, xref);
        if (insn_xref.itype != NN_lea || insn_xref.ops[0].type != o_reg ||
            insn_xref.ops[0].reg != R_R8) {
          continue;
        }

        // check rest of basic block to find gBS->LocateProtocol()
        insn_t next_insn;
        auto current_addr = xref;
        while (true) {
          current_addr = next_head(current_addr, BADADDR);
          decode_insn(&next_insn, current_addr);

          if (next_insn.itype == NN_callni &&
              next_insn.ops[0].type == o_displ &&
              next_insn.ops[0].reg == R_RAX) {
            if (next_insn.ops[0].addr == 0x140 ||
                next_insn.ops[0].addr == 0x40) {
              efi_utils::log("found SMM callout via interface at 0x%" PRIx64
                             "\n",
                             u64_addr(ea));
              m_callout_addrs.insert(ea);
              found = true;
            } // else: FP
            break;
          }

          if (is_basic_block_end(next_insn, false)) {
            break;
          }
        }
        if (found) {
          break;
        }
      }
    }
  }
}

//--------------------------------------------------------------------------
// find SMI handlers
void efi_analysis::efi_analyser_t::find_smi_handlers() {
  std::map<efi_guid_t *, std::string> types = {
      {&m_sw_guid2, "Sw"},
      {&m_sw_guid, "Sw"},
      {&m_sx_guid2, "Sx"},
      {&m_sx_guid, "Sx"},
      {&m_io_trap_guid2, "IoTrap"},
      {&m_io_trap_guid, "IoTrap"},
      {&m_gpi_guid2, "Gpi"},
      {&m_gpi_guid, "Gpi"},
      {&m_usb_guid2, "Usb"},
      {&m_usb_guid, "Usb"},
      {&m_standby_button_guid2, "StandbyButton"},
      {&m_standby_button_guid, "StandbyButton"},
      {&m_periodic_timer_guid2, "PeriodicTimer"},
      {&m_periodic_timer_guid, "PeriodicTimer"},
      {&m_power_button_guid2, "PowerButton"},
      {&m_power_button_guid, "PowerButton"},
      {&m_ichn_guid, "Ichn"},
      {&m_ichn_guid2, "Ichn"},
      {&m_tco_guid, "Tco"},
      {&m_pcie_guid, "Pcie"},
      {&m_acpi_guid, "Acpi"},
      {&m_gpio_unlock_guid, "GpioUnlock"},
      {&m_pch_guid, "Pch"},
      {&m_espi_guid, "Espi"},
      {&m_acpi_en_guid, "AcpiEn"},
      {&m_acpi_dis_guid, "AcpiDis"},
      {&m_fch_gpi_guid2, "Gpi"},
      {&m_fch_io_trap_guid2, "IoTrap"},
      {&m_fch_periodical_guid2, "PeriodicTimer"},
      {&m_fch_pwr_btn_guid2, "PowerButton"},
      {&m_fch_sw_guid2, "Sw"},
      {&m_fch_sx_guid2, "Sx"},
      {&m_fch_usb_guid2, "Usb"},
      {&m_fch_usb_guid, "Usb"},
      {&m_fch_misc_guid, "Misc"},
      {&m_fch_apu_ras_guid, "ApuRas"},
  };
  for (auto &[guid, prefix] : types) {
    auto res = efi_smm_utils::find_smi_handlers_dispatch(*guid, prefix);
    m_smi_handlers.insert(m_smi_handlers.end(), res.begin(), res.end());
  }
}

//--------------------------------------------------------------------------
// find callouts inside SwSmiHandler functions
bool efi_analysis::efi_analyser_x86_t::find_smm_callout() {
  if (m_bs_list.empty() && m_rt_list.empty()) {
    return false;
  }
  if (m_smi_handlers.empty() && m_child_smi_handlers.empty()) {
    return false;
  }
  for (auto func : m_smi_handlers) {
    find_callout_rec(func);
  }
  for (auto func : m_child_smi_handlers) {
    find_callout_rec(func);
  }
  return true;
}

//--------------------------------------------------------------------------
// find potential double GetVariable patterns in PEI modules
bool efi_analysis::efi_analyser_x86_t::find_double_get_variable_pei() {
  ea_set_t get_variable_services_calls;
  std::string get_variable_str("VariablePPI->GetVariable");

  for (auto j_service : m_all_services) {
    json service = j_service;
    std::string service_name = service["service_name"];
    std::string table_name = service["table_name"];
    ea_t addr = service["address"];
    if (service_name.compare(get_variable_str) == 0) {
      get_variable_services_calls.insert(addr);
    }
  }

  if (get_variable_services_calls.size() < 2) {
    return false;
  }

  auto it = get_variable_services_calls.begin();
  ea_t prev_addr = *it;
  insn_t insn;

  ++it;
  for (; it != get_variable_services_calls.end(); ++it) {
    ea_t curr_addr = *it;
    efi_utils::log("first call to VariablePPI->GetVariable: 0x%" PRIx64 "\n",
                   u64_addr(prev_addr));
    efi_utils::log("second call to VariablePPI->GetVariable: 0x%" PRIx64 "\n",
                   u64_addr(curr_addr));

    // check code from first call to second call
    ea_t ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_callni || insn.itype == NN_call ||
          insn.itype == NN_retn || insn.itype == NN_jmp ||
          insn.itype == NN_jmpni) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }

    if (ok) {
      bool same_datasize = false;
      uint16_t push_number = 5;
      uint16_t push_counter = 0;
      uint16_t arg5_reg = NONE_REG;
      ea_t curr_datasize_addr = 0xffff;
      bool datasize_addr_found = false;
      ea_t address = curr_addr;
      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_push) {
          push_counter += 1;
          if (push_counter == push_number) {
            if (insn.ops[0].type == o_reg) {
              arg5_reg = insn.ops[0].reg;
            } else {
              // if it's not `push {reg}`, just let the pattern
              // trigger - for manual review
              same_datasize = true;
            }
            break;
          }
        }
      }

      if (same_datasize) {
        m_double_get_variable_pei.insert(curr_addr);
        efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                       u64_addr(curr_addr));
        continue;
      }

      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
          curr_datasize_addr = insn.ops[1].addr;
          datasize_addr_found = true;
          break;
        }
      }

      if (!datasize_addr_found) {
        // if datasize wasn't found, just let the pattern
        // trigger - for manual review
        m_double_get_variable_pei.insert(curr_addr);
        efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                       u64_addr(curr_addr));
        continue;
      }

      push_counter = 0;
      arg5_reg = NONE_REG;
      ea_t prev_datasize_addr = 0xffff;
      datasize_addr_found = false;
      address = prev_addr;
      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_push) {
          push_counter += 1;
          if (push_counter == push_number) {
            if (insn.ops[0].type == o_reg) {
              arg5_reg = insn.ops[0].reg;
            } else {
              // if it's not `push {reg}`, just let the pattern
              // trigger - for manual review
              same_datasize = true;
            }
            break;
          }
        }
      }

      if (same_datasize) {
        m_double_get_variable_pei.insert(curr_addr);
        efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                       u64_addr(curr_addr));
        continue;
      }

      for (auto j = 0; j < 15; j++) {
        address = prev_head(address, m_start_addr);
        decode_insn(&insn, address);
        if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
            insn.ops[0].reg == arg5_reg && insn.ops[1].type == o_displ) {
          prev_datasize_addr = insn.ops[1].addr;
          datasize_addr_found = true;
          break;
        }
      }

      if (!datasize_addr_found) {
        m_double_get_variable_pei.insert(curr_addr);
        efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                       u64_addr(curr_addr));
      } else if (prev_datasize_addr == curr_datasize_addr) {
        m_double_get_variable_pei.insert(curr_addr);
        efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                       u64_addr(curr_addr));
      }
    }
    prev_addr = curr_addr;
  }
  return !m_double_get_variable_pei.empty();
}

//--------------------------------------------------------------------------
// find potential double GetVariable patterns
bool efi_analysis::efi_analyser_x86_t::find_double_get_variable() {
  ea_set_t get_variable_services_calls;
  std::string get_variable_str("GetVariable");

  for (auto j_service : m_all_services) {
    json service = j_service;
    std::string service_name = service["service_name"];
    ea_t addr = service["address"];
    if (service_name.compare(get_variable_str) == 0) {
      get_variable_services_calls.insert(addr);
    }
  }

  if (get_variable_services_calls.size() < 2) {
    return false;
  }

  auto it = get_variable_services_calls.begin();
  ea_t prev_addr = *it;
  insn_t insn;

  ++it;
  for (; it != get_variable_services_calls.end(); ++it) {
    ea_t curr_addr = *it;
    efi_utils::log("first call to GetVariable: 0x%" PRIx64 "\n",
                   u64_addr(prev_addr));
    efi_utils::log("second call to GetVariable: 0x%" PRIx64 "\n",
                   u64_addr(curr_addr));

    int datasize_stack_addr = 0;
    uint16 datasize_op_reg = 0xFF;
    ea_t ea = prev_head(curr_addr, 0);
    for (auto i = 0; i < 10; ++i) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R9) {
        datasize_stack_addr = insn.ops[1].addr;
        datasize_op_reg = insn.ops[1].phrase;
        break;
      }
      ea = prev_head(ea, 0);
    }

    // check code from first call to second call
    ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    size_t datasize_user_count = 0;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (((datasize_stack_addr == insn.ops[0].addr) &&
           (datasize_op_reg == insn.ops[0].phrase)) ||
          ((datasize_stack_addr == insn.ops[1].addr) &&
           (datasize_op_reg == insn.ops[1].phrase))) {
        datasize_user_count++;
      }
      if ((insn.itype == NN_callni && insn.ops[0].addr == 0x48) ||
          insn.itype == NN_retn || insn.itype == NN_jmp ||
          insn.itype == NN_jmpni || datasize_user_count > 1) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }

    if (ok) {
      // check for wrong GetVariable detection
      bool wrong_detection = false;
      ea = prev_head(curr_addr, 0);
      for (auto i = 0; i < 8; ++i) {
        decode_insn(&insn, ea);
        if (insn.itype == NN_mov && insn.ops[0].type == o_reg &&
            insn.ops[1].type == o_mem) {
          ea_t mem_addr = insn.ops[1].addr;
          if (m_bs_list.contains(mem_addr)) {
            wrong_detection = true;
            break;
          }
        }
        ea = prev_head(ea, 0);
      }

      // check DataSize initialisation
      bool init_ok = false;
      decode_insn(&insn, prev_head(curr_addr, 0));
      if (!wrong_detection &&
          !(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            (insn.ops[0].phrase == R_RSP || insn.ops[0].phrase == R_RBP) &&
            (insn.ops[0].addr == datasize_stack_addr))) {
        init_ok = true;
      }

      // check that the DataSize argument variable is the same for two calls
      if (init_ok) {
        ea = prev_head(prev_addr, 0);
        func_t *func_start = get_func(ea);
        if (func_start == nullptr) {
          return !m_double_get_variable.empty();
        }

        uint16 stack_base_reg = 0xff;
        decode_insn(&insn, func_start->start_ea);
        if (insn.itype == NN_mov && insn.ops[1].is_reg(R_RSP) &&
            insn.ops[0].type == o_reg) {
          stack_base_reg = insn.ops[0].reg;
        }

        while (ea >= func_start->start_ea) {
          decode_insn(&insn, ea);
          if (insn.itype == NN_call)
            break;
          if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
              insn.ops[0].reg == R_R9) {
            ea_t stack_addr = insn.ops[1].addr;
            sval_t sval = get_spd(func_start, ea) * -1;

            if ((insn.ops[1].phrase == stack_base_reg &&
                 (sval + stack_addr) == datasize_stack_addr) ||
                (datasize_stack_addr == insn.ops[1].addr)) {
              m_double_get_variable.insert(curr_addr);
              efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                             u64_addr(curr_addr));
              break;
            }
          }
          ea = prev_head(ea, 0);
        }
      }
    }
    prev_addr = curr_addr;
  }
  return !m_double_get_variable.empty();
}

//--------------------------------------------------------------------------
// find potential double GetVariable patterns in SMM modules
bool efi_analysis::efi_analyser_x86_t::find_double_get_variable_smm() {
  ea_set_t smm_get_variable_calls =
      efi_smm_utils::find_smm_get_variable_calls(m_data_segs, &m_all_services);
  if (smm_get_variable_calls.size() < 2) {
    return false;
  }

  auto it = smm_get_variable_calls.begin();
  ea_t prev_addr = *it;
  insn_t insn;

  ++it;
  for (; it != smm_get_variable_calls.end(); ++it) {
    ea_t curr_addr = *it;
    efi_utils::log("first call to SmmGetVariable: 0x%" PRIx64 "\n",
                   u64_addr(prev_addr));
    efi_utils::log("second call to SmmGetVariable: 0x%" PRIx64 "\n",
                   u64_addr(curr_addr));

    uint32_t datasize_stack_addr = 0xffffffff;
    ea_t ea = prev_head(curr_addr, 0);
    for (auto i = 0; i < 10; ++i) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
          insn.ops[0].reg == R_R9) {
        datasize_stack_addr = insn.ops[1].addr;
        break;
      }
      ea = prev_head(ea, 0);
    }

    // check code from first call to second call
    ea = next_head(prev_addr, BADADDR);
    bool ok = true;
    while (ea < curr_addr) {
      decode_insn(&insn, ea);
      if (insn.itype == NN_callni || insn.itype == NN_retn ||
          insn.itype == NN_jmpni || insn.itype == NN_jmp) {
        ok = false;
        break;
      }
      ea = next_head(ea, BADADDR);
    }

    if (ok) {
      // check DataSize initialisation
      bool init_ok = false;
      decode_insn(&insn, prev_head(curr_addr, 0));
      if (!(insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            (insn.ops[0].phrase == R_RSP || insn.ops[0].phrase == R_RBP))) {
        init_ok = true;
      }

      // check that the DataSize argument variable is the same for two calls
      if (init_ok) {
        ea = prev_head(prev_addr, 0);
        for (auto i = 0; i < 10; ++i) {
          decode_insn(&insn, ea);
          if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
              insn.ops[0].reg == R_R9) {
            if (datasize_stack_addr == insn.ops[1].addr) {
              m_double_get_variable_smm.insert(curr_addr);
              efi_utils::log("overflow may occur here: 0x%" PRIx64 "\n",
                             u64_addr(curr_addr));
              break;
            }
          }
          ea = prev_head(ea, 0);
        }
      }
    }
    prev_addr = curr_addr;
  }
  return !m_double_get_variable_smm.empty();
}

//--------------------------------------------------------------------------
// apply enum values from MACRO_EFI
bool efi_analysis::efi_analyser_x86_t::set_enums_repr(ea_t ea, insn_t insn) {
  if (m_macro_efi_tid == BADADDR) {
    return false;
  }

  if (insn.itype != NN_mov || insn.ops[0].type != o_reg) {
    return false;
  }

  int index = 1;
  if ((insn.ops[index].value & m_mask) == m_masked_value) {
    op_enum(ea, index, m_macro_efi_tid, 0);
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
// set operands representation
void efi_analysis::efi_analyser_x86_t::set_operands_repr() {
  insn_t insn;
  for (auto faddr : m_funcs) {
    func_t *f = get_func(faddr);

    if (f == nullptr) {
      continue;
    }

    ea_t ea = f->start_ea;
    while (ea < f->end_ea) {
      ea = next_head(ea, BADADDR);
      decode_insn(&insn, ea);

      // set enums representation
      set_enums_repr(ea, insn);
    }
  }
}

//--------------------------------------------------------------------------
// analyse calls to GetVariable/SetVariable to extract variables information
bool efi_analysis::efi_analyser_t::analyse_variable_service(
    ea_t ea, std::string service_str) {
  func_t *f = get_func(ea);
  if (f == nullptr) {
    return false;
  }

  efi_utils::log("analysing %s call at 0x%" PRIx64 "\n", service_str.c_str(),
                 u64_addr(ea));

  eavec_t args;
  if (!get_arg_addrs(&args, ea)) {
    // handle cases when get_arg_addrs will fail
    //
    // e.g:
    // mov     rax, cs:gEfiSmmVariableProtocol
    // mov     rax, [rax]
    // ...
    // call    rax
    args.clear();
    efi_utils::log("extracting argument addresses\n");
    efi_utils::get_arg_addrs_with(&args, ea, 3);
  }

  if (args.size() < 3) {
    return false;
  }

  json v;
  v["addr"] = ea;

  insn_t insn;
  bool name_found = false;
  bool guid_found = false;

  // variable name argument
  auto addr = args[0];
  decode_insn(&insn, addr);

  if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == R_RCX && insn.ops[1].type == o_mem) {
    std::string var_name = efi_utils::get_wide_string(insn.ops[1].addr);

    // retype CHAR16 to const CHAR16 to improve pseudocode quality
    efi_utils::set_const_char16_type(insn.ops[1].addr);
    efi_utils::log("  VariableName: %s (at 0x%" PRIx64 ")\n", var_name.c_str(),
                   u64_addr(insn.ops[1].addr));

    v["VariableName"] = var_name;
    name_found = true;
  }

  // vendor GUID argument
  addr = args[1];
  decode_insn(&insn, addr);

  // if GUID is a global variable
  if (insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == R_RDX && insn.ops[1].type == o_mem) {
    efi_guid_t guid = efi_utils::get_global_guid(insn.ops[1].addr);
    efi_utils::log("  VendorGuid: %s (at 0x%" PRIx64 ")\n",
                   guid.to_string().c_str(), u64_addr(insn.ops[1].addr));

    v["VendorGuid"] = guid.to_string();
    guid_found = true;
  }

  // if GUID is local variable
  if (!guid_found && insn.itype == NN_lea && insn.ops[0].type == o_reg &&
      insn.ops[0].reg == R_RDX && insn.ops[1].type == o_displ) {
    switch (insn.ops[1].reg) {
    case R_RBP: {
      efi_guid_t guid = efi_utils::get_local_guid(f, insn.ops[1].addr);
      efi_utils::log("  VendorGuid: %s, RBP offset: 0x%" PRIx64 "\n",
                     guid.to_string().c_str(), u64_addr(insn.ops[1].addr));

      v["VendorGuid"] = guid.to_string();
      guid_found = true;
    }
    case R_RSP: {
      efi_guid_t guid = efi_utils::get_local_guid(f, insn.ops[1].addr);
      efi_utils::log("  VendorGuid: %s, RSP offset: 0x%" PRIx64 "\n",
                     guid.to_string().c_str(), u64_addr(insn.ops[1].addr));

      v["VendorGuid"] = guid.to_string();
      guid_found = true;
    }
    }
  }

  std::map<uint8_t, std::string> attributes_defs = {
      {0x00000001, "NON_VOLATILE"},
      {0x00000002, "BOOTSERVICE_ACCESS"},
      {0x00000004, "RUNTIME_ACCESS"},
      {0x00000008, "HARDWARE_ERROR_RECORD"},
      {0x00000010, "AUTHENTICATED_WRITE_ACCESS"}};

  addr = args[2]; // Attributes argument
  decode_insn(&insn, addr);

  if (insn.itype == NN_mov && insn.ops[1].type == o_imm) {
    // attempt to annotate Attributes argument
    //
    // mostly we see such code where op_enum() does not
    // help, because operand is not an immediate value:
    // mov r9d, X      ; DataSize
    // lea r8d, [r9+Y] ; Attributes (X + Y)
    //
    // however, it will work when we encounter:
    // mov r8d, X      ; Attributes
    op_enum(addr, 1, m_macro_var_attr_tid, 0);
  }

  if (insn.itype == NN_xor && insn.ops[0].type == o_reg &&
      insn.ops[1].type == o_reg && insn.ops[0].reg == insn.ops[1].reg &&
      insn.ops[0].reg == R_R8) {
    std::string attributes_hr = "No attributes";
    v["Attributes"] = 0;
    v["AttributesHumanReadable"] = attributes_hr;
    efi_utils::log("  Attributes: %s\n", attributes_hr.c_str());
  } else {
#ifdef HEX_RAYS
    // extract attributes with Hex-Rays SDK
    auto res = efi_hexrays::variables_info_extract_all(f, ea);
    v["Attributes"] = res;
    std::string attributes_hr;
    if (res == 0xff) {
      attributes_hr = "Unknown";
    } else if (!res) {
      attributes_hr = "No attributes";
    } else {
      for (auto &[attr, attr_def] : attributes_defs) {
        if (res & attr & 0x0f) {
          attributes_hr += attr_def + " | ";
        }
      }
      if (attributes_hr.size() >= 3) { // remove the last |
        attributes_hr = attributes_hr.substr(0, attributes_hr.size() - 3);
      } else if (attributes_hr.empty()) {
        attributes_hr = "Unknown";
      }
    }
    v["AttributesHumanReadable"] = attributes_hr;
    efi_utils::log("  Attributes: %s (%d)\n", attributes_hr.c_str(), res);
#else
    // use stubs when hex-rays analysis is disabled
    v["Attributes"] = 0xff;
    v["AttributesHumanReadable"] = "Unknown";
#endif
  }

  // if only the name or GUID is found, it will not be saved
  if (name_found && guid_found) {
    v["service"] = service_str;
    m_nvram_variables.push_back(v);
  }

  return true;
}

//--------------------------------------------------------------------------
// analyse NVRAM variables
bool efi_analysis::efi_analyser_t::analyse_nvram_variables() {
  string_list_t service_names = {"GetVariable", "SetVariable",
                                 "gEfiSmmVariableProtocol->SmmGetVariable",
                                 "gEfiSmmVariableProtocol->SmmGetVariable"};
  for (auto &service_str : service_names) {
    ea_set_t var_services;
    for (auto &j_service : m_all_services) {
      json service = j_service;
      std::string service_name = service["service_name"];
      ea_t addr = service["address"];
      if (!service_name.compare(service_str)) {
        var_services.insert(addr);
      }
    }

    for (auto &ea : var_services) {
      analyse_variable_service(ea, service_str);
    }
  }

  return true;
}

//--------------------------------------------------------------------------
// resolve EFI_SMM_CPU_PROTOCOL
bool efi_analysis::efi_analyser_t::smm_cpu_protocol_resolver() {
  m_read_save_state_calls = efi_smm_utils::resolve_efi_smm_cpu_protocol(
      m_stack_guids, m_data_guids, &m_all_services);
  return true;
}

//--------------------------------------------------------------------------
// dump all info to JSON file
void efi_analysis::efi_analyser_t::dump_json() {
  json info;
  if (m_st_list.size()) {
    info["st_list"] = m_st_list;
  }
  if (m_bs_list.size()) {
    info["bs_list"] = m_bs_list;
  }
  if (m_rt_list.size()) {
    info["rt_list"] = m_rt_list;
  }
  if (m_smst_list.size()) {
    info["smst_list"] = m_smst_list;
  }
  if (m_image_handle_list.size()) {
    info["image_handle_list"] = m_image_handle_list;
  }
  if (m_all_ppis.size()) {
    info["all_ppis"] = m_all_ppis;
  }
  if (m_all_protocols.size()) {
    info["all_protocols"] = m_all_protocols;
  }
  if (m_all_services.size()) {
    info["all_services"] = m_all_services;
  }
  if (m_all_guids.size()) {
    info["all_guids"] = m_all_guids;
  }
  if (m_nvram_variables.size()) {
    info["m_nvram_variables"] = m_nvram_variables;
  }
  if (m_read_save_state_calls.size()) {
    info["read_save_state_calls"] = m_read_save_state_calls;
  }
  if (m_callout_addrs.size()) {
    info["vulns"]["smm_callout"] = m_callout_addrs;
  }
  if (m_double_get_variable_pei.size()) {
    info["vulns"]["pei_get_variable_buffer_overflow"] =
        m_double_get_variable_pei;
  }
  if (m_double_get_variable.size()) {
    info["vulns"]["get_variable_buffer_overflow"] = m_double_get_variable;
  }
  if (m_double_get_variable_smm.size()) {
    info["vulns"]["smm_get_variable_buffer_overflow"] =
        m_double_get_variable_smm;
  }

  json_list_t smi_handlers_addrs;
  if (!m_smi_handlers.empty()) {
    for (auto f : m_smi_handlers) {
      func_t *func = f;
      smi_handlers_addrs.push_back(func->start_ea);
    }
    info["smi_handlers_addrs"] = smi_handlers_addrs;
  }

  std::string idb_path;
  idb_path = get_path(PATH_TYPE_IDB);
  std::filesystem::path log_file;
  log_file /= idb_path;
  log_file.replace_extension(".efixplorer.json");
  std::ofstream out(log_file);
  out << std::setw(2) << info << std::endl;

  efi_utils::log("the log is saved in a JSON file\n");
}

//--------------------------------------------------------------------------
// show all non-empty choosers windows (services, protocols, nvram, etc)
void efi_analysis::efi_analyser_x86_t::show_all_choosers() {
  qstring title;

  // open window with all services
  if (m_all_services.size()) {
    title = "efiXplorer: services";
    show_services(m_all_services, title);
  }

  // open window with protocols
  if (m_ftype == ffs_file_type_t::peim) {
    if (m_all_ppis.size()) {
      title = "efiXplorer: PPIs";
      show_ppis(m_all_ppis, title);
    }
  } else { // ffs_file_type_t::driver
    if (m_all_protocols.size()) {
      title = "efiXplorer: protocols";
      show_protocols(m_all_protocols, title);
    }
  }

  // open window with data guids
  if (m_all_guids.size()) {
    qstring title = "efiXplorer: GUIDs";
    show_guids(m_all_guids, title);
  }

  // open window with NVRAM variables
  if (m_nvram_variables.size()) {
    qstring title = "efiXplorer: NVRAM";
    show_nvram(m_nvram_variables, title);
  }

  // open window with vulnerabilities
  if (m_callout_addrs.size() || m_double_get_variable_pei.size() ||
      m_double_get_variable.size() || m_double_get_variable_smm.size()) {
    json_list_t vulns;
    std::map<std::string, ea_set_t> vulns_map = {
        {"SmmCallout", m_callout_addrs},
        {"DoubleGetVariablePei", m_double_get_variable_pei},
        {"DoubleGetVariable", m_double_get_variable},
        {"DoubleGetVariableSmm", m_double_get_variable_smm}};

    for (const auto &[type, addrs] : vulns_map) {
      for (auto addr : addrs) {
        json v;
        v["type"] = type;
        v["address"] = addr;
        vulns.push_back(v);
      }
    }

    qstring title = "efiXplorer: vulns";
    show_vulns(vulns, title);
  }
}

//--------------------------------------------------------------------------
// main function for x86 64-bit modules
bool efi_analysis::efi_analyse_main_x86_64() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::efi_analyser_x86_t analyser;

  while (!auto_is_ok()) {
    auto_wait();
  }

  // find .text and .data segments
  analyser.get_segments();

  // analyse all
  auto res = ASKBTN_NO;
  if (analyser.m_analysis_kind == analysis_kind_t::uefi) {
    res = ask_yn(1, "Do you want to analyse all modules with auto_mark_range?");
  }
  if (res == ASKBTN_YES && analyser.m_code_segs.size() &&
      analyser.m_data_segs.size()) {
    segment_t *start_seg = analyser.m_code_segs.at(0);
    segment_t *end_seg =
        analyser.m_data_segs.at(analyser.m_data_segs.size() - 1);
    ea_t start_ea = start_seg->start_ea;
    ea_t end_ea = end_seg->end_ea;
    auto_mark_range(start_ea, end_ea, AU_USED);
    plan_and_wait(start_ea, end_ea, 1);
  }

  // mark GUIDs
  analyser.annotate_data_guids();
  analyser.find_local_guids64();

  // set operands representation
  analyser.set_operands_repr();

  if (g_args.disable_ui) {
    analyser.m_ftype = g_args.module_type == module_type_t::pei
                           ? analyser.m_ftype = ffs_file_type_t::peim
                           : analyser.m_ftype = ffs_file_type_t::driver;
  } else {
    analyser.m_ftype = efi_utils::ask_file_type(&analyser.m_all_guids);
  }

  analyser.set_pvalues();

  // find global vars for gImageHandle, gST, gBS, gRT, gSmst
  if (analyser.m_ftype == ffs_file_type_t::driver) {
    analyser.find_image_handle64();
    analyser.find_system_table64();
    analyser.find_boot_services_tables();
    analyser.find_runtime_services_tables();

    analyser.find_smst64();

    // find boot services and runtime services
    analyser.get_prot_boot_services64();
    analyser.find_other_boot_services_tables64();
    analyser.get_boot_services_all();
    analyser.get_runtime_services_all();

    analyser.get_bs_prot_names64();

#ifdef HEX_RAYS
    efi_hexrays::apply_all_types_for_interfaces(analyser.m_all_protocols);
    analyser.find_smst_postproc64();
#endif

    // find SMM services
    analyser.get_smm_services_all64();
    analyser.get_smm_prot_names64();

    // mark protocols
    analyser.annotate_protocol_guids();

    // search for copies of global variables
    efi_utils::mark_copies_for_gvars(analyser.m_smst_list, "gSmst");
    efi_utils::mark_copies_for_gvars(analyser.m_bs_list, "gBS");
    efi_utils::mark_copies_for_gvars(analyser.m_rt_list, "gRT");

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {
      // find potential SMM callouts
      analyser.find_smi_handlers();
      analyser.find_smm_callout();

      // find potential OOB RW with GetVariable function
      analyser.find_double_get_variable();

      // find potential OOB RW with SmmGetVariable function
      analyser.find_double_get_variable_smm();
      analyser.smm_cpu_protocol_resolver();
    }

#ifdef HEX_RAYS
    efi_hexrays::apply_all_types_for_interfaces_smm(analyser.m_all_protocols);
#endif

    analyser.analyse_nvram_variables();

  } else {
    efi_utils::log("analysis of x86 64-bit PEI files is not supported\n");
  }

  // dump info to JSON file
  analyser.dump_json();

  // show all choosers windows
  if (!g_args.disable_ui) {
    analyser.show_all_choosers();
  }

  if (analyser.m_analysis_kind == analysis_kind_t::uefi) {
    // init public EdiDependencies members
    g_deps.get_protocols_chooser(analyser.m_all_protocols);
    g_deps.get_protocols_by_guids(analyser.m_all_protocols);

    // save all protocols information to build dependencies
    attach_action_protocols_deps();
    attach_action_modules_seq();
  }

  hide_wait_box();

  return true;
}

//--------------------------------------------------------------------------
// main function for x86 32-bit modules
bool efi_analysis::efi_analyse_main_x86_32() {
  show_wait_box("HIDECANCEL\nAnalysing module(s) with efiXplorer...");

  efi_analysis::efi_analyser_x86_t analyser;

  while (!auto_is_ok()) {
    auto_wait();
  }

  // find .text and .data segments
  analyser.get_segments();

  // analyse all modules (for UEFI firmware with multiple modules)
  auto res = ASKBTN_NO;
  if (analyser.m_analysis_kind == analysis_kind_t::uefi) {
    res = ask_yn(1, "Do you want to analyse all modules with auto_mark_range?");
  }
  if (res == ASKBTN_YES && analyser.m_code_segs.size() &&
      analyser.m_data_segs.size()) {
    segment_t *start_seg = analyser.m_code_segs.at(0);
    segment_t *end_seg =
        analyser.m_data_segs.at(analyser.m_data_segs.size() - 1);
    ea_t start_ea = start_seg->start_ea;
    ea_t end_ea = end_seg->end_ea;
    auto_mark_range(start_ea, end_ea, AU_USED);
    plan_and_wait(start_ea, end_ea, 1);
  }

  // mark GUIDs
  analyser.annotate_data_guids();

  // set operands representation
  analyser.set_operands_repr();

  if (analyser.m_analysis_kind == analysis_kind_t::uefi) {
    // UEFI firmware with 32-bit PEI modules
    analyser.m_ftype = ffs_file_type_t::peim;
  } else if (g_args.disable_ui) {
    analyser.m_ftype = g_args.module_type == module_type_t::pei
                           ? analyser.m_ftype = ffs_file_type_t::peim
                           : analyser.m_ftype = ffs_file_type_t::driver;
  } else {
    analyser.m_ftype = efi_utils::ask_file_type(&analyser.m_all_guids);
  }

  analyser.set_pvalues();

  if (analyser.m_ftype == ffs_file_type_t::driver) {
    // find global vars for gST, gBS, gRT
    analyser.find_boot_services_tables();
    analyser.find_runtime_services_tables();

    // find boot services and runtime services
    analyser.get_runtime_services_all();
    analyser.get_prot_boot_services32();
    analyser.get_boot_services_all();

    // print and mark protocols
    analyser.get_bs_prot_names32();
    analyser.annotate_protocol_guids();

#ifdef HEX_RAYS
    efi_hexrays::apply_all_types_for_interfaces(analyser.m_all_protocols);
    efi_hexrays::apply_all_types_for_interfaces_smm(analyser.m_all_protocols);
#endif
  } else if (analyser.m_ftype == ffs_file_type_t::peim) {
    if (analyser.m_analysis_kind == analysis_kind_t::uefi) {
      // UEFI multi-module: force-apply PEI entry prototype
      efi_utils::set_pei_entry_type_for_uefi();
    } else {
      efi_utils::set_entry_arg_to_pei_svc();
    }
    efi_utils::add_struct_for_shifted_ptr();
#ifdef HEX_RAYS
    for (auto addr : analyser.m_funcs) {
      efi_hexrays::detect_pei_services(get_func(addr));
    }
#endif
    analyser.get_pei_services_all32();
    analyser.get_ppi_names32();
    analyser.get_variable_ppi_calls_all32();
    analyser.annotate_protocol_guids();

    // search for vulnerabilities
    if (!g_args.disable_vuln_hunt) {
      analyser.find_double_get_variable_pei();
    }
  }

  // dump info to JSON file
  analyser.dump_json();

  // show all choosers windows
  if (!g_args.disable_ui) {
    analyser.show_all_choosers();
  }

  hide_wait_box();

  return true;
}
