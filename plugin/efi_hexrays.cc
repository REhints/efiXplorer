// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_hexrays.h"

#include <string>

// the analysis applies types before the passes below, so a cached ctree can be
// outdated and has to be dropped; done holds the functions dropped by the
// current pass
static cfuncptr_t decompile_uncached(func_t *f, ea_set_t *done = nullptr) {
  if (done == nullptr || done->insert(f->start_ea).second) {
    mark_cfunc_dirty(f->start_ea);
  }

  hexrays_failure_t hf;
  return decompile(f, &hf, DECOMP_NO_WAIT);
}

// given a tinfo_t specifying a user-defined type (UDT), look up the specified
// field by its name, and retrieve its offset.
bool efi_hexrays::offset_of(tinfo_t tif, const char *name,
                            unsigned int *offset) {
  // get the udt details
  udt_type_data_t udt;
  if (!tif.get_udt_details(&udt)) {
    qstring str;
    tif.get_type_name(&str);
    return false;
  }

  // find the udt member
#if IDA_SDK_VERSION < 840
  udt_member_t udm;
  udm.name = name;
  int fidx = tif.find_udt_member(&udm, STRMEM_NAME);
#else
  udm_t udm;
  udm.name = name;
  int fidx = tif.find_udm(&udm, STRMEM_NAME);
#endif
  if (fidx < 0) {
    qstring tstr;
    tif.get_type_name(&tstr);
    return false;
  }

  // get the offset of the field in bytes
  *offset = static_cast<unsigned int>(udt.at(fidx).offset >> 3);
  return true;
}

xreflist_t efi_hexrays::xrefs_to_stack_var(ea_t func_addr, lvar_t &ll,
                                           qstring name) {
  efi_utils::log("get xrefs to stack variable %s at 0x%" PRIx64 "\n",
                 name.c_str(), func_addr);

  xreflist_t xrefs_list;

#if IDA_SDK_VERSION < 850
  struc_t *frame = get_frame(func_addr);
  if (frame == nullptr) {
    return xrefs_list;
  }

  func_t *f = get_func(func_addr);
  if (f == nullptr) {
    return xrefs_list;
  }

  member_t *member = get_member_by_name(frame, name.c_str());
  if (member != nullptr) {
    build_stkvar_xrefs(&xrefs_list, f, member);
  }
#else
  sval_t stkoff = ll.get_stkoff();

  func_t *f = get_func(func_addr);
  if (f == nullptr) {
    return xrefs_list;
  }

  build_stkvar_xrefs(&xrefs_list, f, stkoff, stkoff + get_ptrsize());

#endif
  return xrefs_list;
}

// utility function to set a Hex-Rays variable name
bool efi_hexrays::set_lvar_name(qstring name, lvar_t &lvar, ea_t func_addr) {
  lvar_saved_info_t lsi;
  lvar_uservec_t lvuv;

  lsi.ll = lvar;
  lsi.name = name;
  if (!lvuv.lvvec.add_unique(lsi)) {
    return false;
  }
  save_user_lvar_settings(func_addr, lvuv);
  return true;
}

// utility function to set a Hex-Rays variable type and name
bool efi_hexrays::set_hexrays_var_info(ea_t func_addr, lvar_t &ll, tinfo_t tif,
                                       std::string name) {
  if (ll.is_stk_var()) { // rename local variable on stack
#if IDA_SDK_VERSION < 850
    sval_t stkoff = ll.get_stkoff();

    struc_t *frame = get_frame(func_addr);
    if (frame == nullptr) {
      return false;
    }

    if (!set_member_name(frame, stkoff, name.c_str())) {
      return false;
    }

    member_t *member = get_member_by_name(frame, name.c_str());
    if (member != nullptr) {
      set_member_tinfo(frame, member, 0, tif, 0);
    }
#else
    sval_t stkoff = ll.get_stkoff();

    func_t *f = get_func(func_addr);
    if (f == nullptr) {
      return false;
    }

    tinfo_t frame;
    frame.get_func_frame(f);
    if (frame.empty()) {
      return false;
    }

    ssize_t stkvar_idx = frame.find_udm(stkoff << 3);
    if (stkvar_idx != -1) {
      frame.rename_udm(stkvar_idx, name.c_str());
      frame.set_udm_type(stkvar_idx, tif);
    }
#endif
  } else {
    lvar_saved_info_t lsi;
    lsi.ll = ll;

    // modufy user lvar type
    lsi.type = tif;
    modify_user_lvar_info(func_addr, MLI_TYPE, lsi);

    // modufy user lvar name
    lsi.name = name.c_str();
    modify_user_lvar_info(func_addr, MLI_NAME, lsi);
  }

  return true;
}

// utility function to set a Hex-Rays variable type and set types for the
// interfaces
bool efi_hexrays::set_hexrays_var_info_and_handle_interfaces(ea_t func_addr,
                                                             lvar_t &ll,
                                                             tinfo_t tif,
                                                             std::string name) {
  set_hexrays_var_info(func_addr, ll, tif, name);

  ptr_type_data_t pi;
  tif.get_ptr_details(&pi);

  qstring type_name;
  pi.obj_type.get_type_name(&type_name);

  // handle all interface functions (to rename function arguments)
  xreflist_t xrefs = xrefs_to_stack_var(func_addr, ll, name.c_str());
  efi_utils::op_stroff_for_interface(xrefs, type_name);

  return true;
}

// I added this bit of logic when I noticed that sometimes Hex-Rays
// will aggressively create arrays on the stack. So, I wanted to apply types to
// stack "variables" (whose pointers are passed to the protocol location
// functions), but according to Hex-Rays, they weren't "variables", they
// were arrays. This bit of logic generically detects arrays of either POD
// types, or perhaps pointers to POD types. The final argument allows the
// caller to specify the maximum depth "depth" of the pointers. E.g. at
// depth 1, "int *[10]" is acceptable. At depth 2, "int **[10]" is acceptable.
bool efi_hexrays::is_pod_array(tinfo_t tif, unsigned int ptr_depth = 0) {
  // if it's not an array, we're done
  if (!tif.is_array())
    return false;

  qstring tstr;

  // if it is an array, we should be able to get its array details.
  array_type_data_t atd;
  if (!tif.get_array_details(&atd)) {
    tif.get_type_name(&tstr);
    return false;
  }

  // get the element type from the array
  tinfo_t et = atd.elem_type;

  // start off with depth + 1, so the loop will execute at least once
  int depth = ptr_depth + 1;

  // loop over the user-specified depth
  while (depth > 0) {
    // use typeid last checks. I should clean this up; I'm sure I
    // can get rid of one of them.
    bool b1 = is_typeid_last(et.get_realtype());
    bool b2 = et.is_decl_last();

    et.get_type_name(&tstr);

    // if it was an integer type, return true
    if (b1 || b2)
      return true;

    // otherwise, this is where the "pointer depth" comes in
    // if we haven't exhausted the pointer depth,
    if (--depth > 0) {
      // remove one layer of indirection from the element type
      if (et.is_ptr())
        et = remove_pointer(et);

      // unless it's not a pointer, then return false
      else
        return false;
    }
  }

  // if the array wasn't pointers of POD types up to the specified depth, we
  // failed
  return false;
}

// utility function to get a printable qstring from a cexpr_t
const char *efi_hexrays::expr_to_string(cexpr_t *e, qstring *out) {
  e->print1(out, nullptr);
  tag_remove(out);
  return out->c_str();
}

bool efi_hexrays::apply_all_types_for_interfaces(json_list_t protocols) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  // descriptors for EFI_BOOT_SERVICES functions
  struct target_funcptr_t boot_services_functions[5]{
      {"InstallProtocolInterface", 0x80, 4, 1, 3},
      {"HandleProtocol", 0x98, 3, 1, 2},
      {"OpenProtocol", 0x118, 6, 1, 2},
      {"LocateProtocol", 0x140, 3, 0, 2},
      {"InstallMultipleProtocolInterfaces", 0x148, 4, 1, 2}};

  // initialise
  service_descriptor_t sd_bs;
  sd_bs.initialise("EFI_BOOT_SERVICES", boot_services_functions, 5);

  service_descriptor_map_t bs;
  bs.register_sd(sd_bs);

  guid_retyper_t bs_retyper(bs);
  bs_retyper.set_protocols(protocols);

  // handle all protocols
  ea_set_t done;
  for (auto protocol : protocols) {
    auto code_addr = protocol["ea"];
    auto service = protocol["service"];

    func_t *f = get_func(code_addr);
    if (f == nullptr) {
      continue;
    }

    bs_retyper.set_code_ea(code_addr);
    bs_retyper.set_func_ea(f->start_ea);

    cfuncptr_t cfunc = decompile_uncached(f, &done);

    // check that the function is decompiled
    if (cfunc == nullptr) {
      continue;
    }

    bs_retyper.apply_to(&cfunc->body, nullptr);
  }

  return true;
}

bool efi_hexrays::apply_all_types_for_interfaces_smm(json_list_t protocols) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  // descriptors for _EFI_SMM_SYSTEM_TABLE2 functions
  struct target_funcptr_t smm_services_functions[2]{
      {"SmmHandleProtocol", 0xb8, 3, 1, 2},
      {"SmmLocateProtocol", 0xd0, 3, 0, 2},
  };

  // initialise
  service_descriptor_t sd_smm;
  sd_smm.initialise("_EFI_SMM_SYSTEM_TABLE2", smm_services_functions, 2);

  service_descriptor_map_t smm;
  smm.register_sd(sd_smm);

  guid_retyper_t smm_retyper(smm);
  smm_retyper.set_protocols(protocols);

  // Handle all protocols
  ea_set_t done;
  for (auto protocol : protocols) {
    auto code_addr = protocol["ea"];
    auto service = protocol["service"];

    func_t *f = get_func(code_addr);
    if (f == nullptr) {
      continue;
    }

    smm_retyper.set_code_ea(code_addr);
    smm_retyper.set_func_ea(f->start_ea);

    cfuncptr_t cfunc = decompile_uncached(f, &done);

    // check that the function is decompiled
    if (cfunc == nullptr) {
      continue;
    }

    smm_retyper.apply_to(&cfunc->body, nullptr);
  }

  return true;
}

uint8_t efi_hexrays::variables_info_extract_all(func_t *f, ea_t code_addr) {
  if (!init_hexrays_plugin()) {
    return 0xff;
  }

  if (f == nullptr) {
    return 0xff;
  }

  variables_info_extractor_t extractor(code_addr);
  cfuncptr_t cfunc = decompile_uncached(f);

  // check that the function is decompiled
  if (cfunc == nullptr) {
    return 0xff;
  }

  extractor.apply_to(&cfunc->body, nullptr);
  return extractor.m_attributes;
}

bool efi_hexrays::propagate_types(func_t *f, uint8_t depth) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  if (depth == 2) {
    return true;
  }

  if (f == nullptr) {
    return false;
  }

  cfuncptr_t cfunc = decompile_uncached(f);
  if (cfunc == nullptr) {
    return false;
  }

  type_propagator_t *pf = new type_propagator_t();
  pf->apply_to(&cfunc->body, nullptr);
  for (auto addr : pf->m_child_functions) {
    efi_hexrays::propagate_types(get_func(addr), ++depth);
  }

  delete pf;

  return true;
}

json efi_hexrays::detect_vars(func_t *f) {
  json res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  if (f == nullptr) {
    return res;
  }

  variables_detector_t vars_detector;
  cfuncptr_t cfunc = decompile_uncached(f);
  if (cfunc == nullptr) {
    return res;
  }

  vars_detector.set_func_ea(f->start_ea);
  vars_detector.apply_to(&cfunc->body, nullptr);

  res["image_handle_list"] = vars_detector.m_image_handle_list;
  res["st_list"] = vars_detector.m_st_list;
  res["bs_list"] = vars_detector.m_bs_list;
  res["rt_list"] = vars_detector.m_rt_list;

  return res;
}

json_list_t efi_hexrays::detect_services(func_t *f) {
  json_list_t res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  if (f == nullptr) {
    return res;
  }

  services_detector_t services_detector;
  cfuncptr_t cfunc = decompile_uncached(f);
  if (cfunc == nullptr) {
    return res;
  }

  services_detector.apply_to(&cfunc->body, nullptr);
  return services_detector.m_services;
}

bool efi_hexrays::detect_pei_services(func_t *f) {
  if (!init_hexrays_plugin()) {
    return false;
  }

  if (f == nullptr) {
    return false;
  }

  pei_services_detector_t pei_services_detector;
  cfuncptr_t cfunc = decompile_uncached(f);
  if (cfunc == nullptr) {
    return false;
  }

  pei_services_detector.apply_to(&cfunc->body, nullptr);

  return true;
}

json_list_t efi_hexrays::detect_pei_services_arm(func_t *f) {
  json_list_t res;

  if (!init_hexrays_plugin()) {
    return res;
  }

  if (f == nullptr) {
    return res;
  }

  pei_services_detector_arm_t pei_services_detector_arm;
  cfuncptr_t cfunc = decompile_uncached(f);
  if (cfunc == nullptr) {
    return res;
  }
  pei_services_detector_arm.apply_to(&cfunc->body, nullptr);
  return pei_services_detector_arm.m_services;
}
