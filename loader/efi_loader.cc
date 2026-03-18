// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_loader.h"

#include <string>

#include "uefitool.h"
#include "utils.h"

#define USE_UEFITOOL_PARSER

//------------------------
// IDA wrappers
//------------------------

void idaapi load_binary(const char *fname) {
  static bool first_uefi_image = true;

  load_info_t *ld = nullptr;
  linput_t *li = nullptr;
  ushort nflags =
      NEF_SEGS | NEF_RSCS | NEF_NAME | NEF_IMPS | NEF_LALL | NEF_FLAT;
  if (first_uefi_image) {
    nflags |= NEF_FIRST;
    first_uefi_image = false;
  }
  // linput
  li = open_linput(fname, false);
  if (li == nullptr) {
    error("failed to process input source: %s", fname);
  }
  // get loaders
  ld = build_loaders_list(li, fname);
  msg("[efiXloader] using %s to load %s\n", ld->dllname.c_str(), fname);
  // load EFI binary into database
  if ((load_nonbinary_file(fname, li, ".", nflags, ld))) {
    msg("[efiXloader] successfully loaded %s\n", fname);
  } else {
    loader_failure("[efiXloader] 'load_nonbinary_file' failed");
  }
  close_linput(li);
  free_loaders_list(ld);
  return;
}

void idaapi wait(void) {
  while (!auto_is_ok()) {
    auto_wait();
  }
}

//------------------------
// IDA analysing
//------------------------

void inline idaapi reanalyse_all(void) {
  plan_range(inf_get_min_ea(), inf_get_max_ea());
  auto_wait();
  auto_make_proc(inf_get_min_ea());
}

void efi_til_init(const char *til_name) {
  qstring err;
  til_t *res;
  res = load_til(til_name, &err);
  if (!res) {
    loader_failure("failed to load %s", til_name);
  } else {
    msg("[efiXloader] lib %s is ready\n", til_name);
  }
}

//------------------------
// IDA loader
//------------------------

static int idaapi accept_file(qstring *fileformatname, qstring *processor,
                              linput_t *li, const char *filename) {
  efiloader::Utils utils;
  bytevec_t data;
  data.resize(qlsize(li));
  qlseek(li, 0);
  qlread(li, data.begin(), qlsize(li));
  *fileformatname = "UEFI firmware image";
  return utils.find_vol_test(data) != std::string::npos;
}

void idaapi load_file(linput_t *li, ushort neflag, const char *fileformatname) {
  bool ok = true;
  bool is_pe;
  Ui ui;
  bytevec_t data;
  data.resize(qlsize(li));
  qlread(li, data.begin(), qlsize(li));
  efiloader::Uefitool uefiParser(data);
  if (uefiParser.messages_occurs()) {
    uefiParser.show_messages();
  }
  uefiParser.dump();
  uefiParser.dump_jsons();
  efiloader::PeManager peManager(uefiParser.machine_type);

  // add_til("uefi.til", ADDTIL_DEFAULT);
  // we currently only handle 64-bit binaries with the EFI loader
  add_til("uefi64.til", ADDTIL_DEFAULT);

  if (uefiParser.files.empty()) {
    msg("[efiXloader] can not parse input firmware\n");
    return;
  }

  int processed = 0;
  for (size_t i = 0; i < uefiParser.files.size(); i++) {
    const auto &file = uefiParser.files[i];
    if (file->is_te) {
      continue;
    }
    auto inf = open_linput(file->dump_name.c_str(), false);
    if (!inf) {
      msg("[efiXloader] unable to open file %s\n", file->dump_name.c_str());
      continue;
    }
    if (peManager.process(inf, file->dump_name.c_str(), i)) {
      processed++;
    }
  }
  if (processed == 0) {
    msg("[efiXloader] no images were loaded\n");
    return;
  }

  plugin_t *findpat = find_plugin("patfind", true);
  if (findpat) {
    msg("[efiXloader] running the patfind plugin\n");
    run_plugin(findpat, 0);
  }
}

static int idaapi move_segm(ea_t from, ea_t to, asize_t, const char *) {
  return 1;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    // loader flags
    0,
    // check input file format. if recognized, then return 1
    // and fill 'fileformatname'.
    // otherwise return 0
    accept_file,
    // load file into the database.
    load_file,
    // create output file from the database.
    // this function may be absent.
    nullptr,
    // take care of a moved segment (fix up relocations, for example)
    nullptr,
    nullptr,
};
