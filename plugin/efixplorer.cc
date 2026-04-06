// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_analysis.h"
#include "efi_global.h"
#include "efi_ui.h"

static const char hotkey[] = "Ctrl+Alt+E";
static const char description[] =
    "This plugin performs automatic analysis of the input UEFI module";
static const char welcome_msg[] = "      ____ _  __     __\n"
                                  " ___ / _(_) |/_/__  / /__  _______ ____\n"
                                  "/ -_) _/ />  </ _ \\/ / _ \\/ __/ -_) __/\n"
                                  "\\__/_//_/_/|_/ .__/_/\\___/_/  \\__/_/\n"
                                  "            /_/\n";

// default arguments
args_t g_args{module_type_t::dxe_smm, 0, 0};

#if IDA_SDK_VERSION < 760
hexdsp_t *hexdsp = nullptr;
#endif

//--------------------------------------------------------------------------
static plugmod_t *idaapi init(void) {
  const auto analysis_kind = efi_utils::get_analysis_kind();
  if (analysis_kind == analysis_kind_t::unsupported) {
    return PLUGIN_SKIP;
  }

  msg(welcome_msg);
  msg("%s\n\n", COPYRIGHT);

  // register action
  register_action(action_load_report);
  attach_action_to_menu("File/Load file/", action_load_report.name,
                        SETMENU_APP);

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
bool idaapi run(size_t arg) {
  // parse argument:
  //  - bit 0: disable UI
  //  - bit 1: disable vulnerability hunting
  //  - bits 2..N: module type (0 = DXE, 4 = PEI, 8 = standalone SMM)
  g_args.disable_ui = arg & 1;
  g_args.disable_vuln_hunt = (arg >> 1) & 1;

  switch (arg >> 2) {
  case 1:
    g_args.module_type = module_type_t::pei;
    break;
  case 2:
    g_args.module_type = module_type_t::standalone_smm;
    break;
  default:
    g_args.module_type = module_type_t::dxe_smm;
    break;
  }

  efi_utils::log("plugin run with argument %lu (sdk version: %d)\n", arg,
                 IDA_SDK_VERSION);

  const auto guids_path = efi_utils::get_guids_json_file();
  if (guids_path.empty()) {
    warning("%s: %s\n", g_plugin_name,
            "guids.json file not found, copy guids.json to plugins");
    return false;
  }

  const auto analysis_kind = efi_utils::get_analysis_kind();
  if (analysis_kind == analysis_kind_t::x86_64) {
    efi_utils::log("input file is x86 64-bit module\n");
    efi_analysis::efi_analyse_main_x86_64();
  } else if (analysis_kind == analysis_kind_t::x86_32) {
    efi_utils::log("input file is x86 32-bit module\n");
    efi_analysis::efi_analyse_main_x86_32();
  } else if (analysis_kind == analysis_kind_t::uefi) {
    warning("%s: input file is UEFI firmware, analysis can be time consuming\n",
            g_plugin_name);
    if (get_machine_type() == AARCH64) {
      efi_utils::log("analyse ARM64 modules\n");
      efi_analysis::efi_analyse_main_aarch64();
    } else if (inf_is_32bit_exactly()) {
      efi_utils::log("analyse x86 32-bit modules\n");
      efi_analysis::efi_analyse_main_x86_32();
    } else {
      efi_utils::log("analyse AMD64 modules\n");
      efi_analysis::efi_analyse_main_x86_64();
    }
  } else if (analysis_kind == analysis_kind_t::aarch64) {
    efi_utils::log("input file is ARM 64-bit module\n");
    efi_analysis::efi_analyse_main_aarch64();
  }

  // reset arguments
  g_args = {module_type_t::dxe_smm, 0, 0};

  return true;
}

//--------------------------------------------------------------------------
// plugin description block
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    0,             // plugin flags
    init,          // initialize plugin
    nullptr,       // terminate plugin
    run,           // invoke plugin
    description,   // long comment about the plugin
    description,   // multiline help about the plugin
    g_plugin_name, // the preferred short name of the plugin
    hotkey         // the preferred hotkey to run the plugin
};
