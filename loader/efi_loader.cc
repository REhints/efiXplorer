// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "../ldr/idaldr.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>

#include "pe_manager.h"
#include "uefitool.h"

static constexpr char FMT_UEFI_64[] = "UEFI firmware image (64-bit modules)";
static constexpr char FMT_UEFI_32_PEI[] =
    "UEFI firmware image (32-bit PEI modules)";

//--------------------------------------------------------------------------
// detect UEFI firmware by searching for the "_FVH" signature
static bool is_uefi_firmware(linput_t *li) {
  constexpr char sig[] = "_FVH";
  constexpr size_t sig_len = 4;
  static constexpr size_t kBufSize = 4096;

  const int64 file_size = qlsize(li);
  qlseek(li, 0);

  char buf[kBufSize];
  for (int64 pos = 0; pos + static_cast<int64>(sig_len) <= file_size;) {
    qlseek(li, pos);
    auto to_read = qmin(static_cast<int64>(kBufSize), file_size - pos);
    auto nread = qlread(li, buf, static_cast<size_t>(to_read));
    if (nread < static_cast<ssize_t>(sig_len)) {
      break;
    }
    if (std::search(buf, buf + nread, sig, sig + sig_len) != buf + nread) {
      return true;
    }
    if (to_read < static_cast<int64>(kBufSize)) {
      break;
    }
    pos += nread - (sig_len - 1);
  }
  return false;
}

//--------------------------------------------------------------------------
// IDA loader: accept_file is called repeatedly when ACCEPT_CONTINUE is set
static int idaapi accept_file(qstring *fileformatname, qstring * /*processor*/,
                              linput_t *li, const char * /*filename*/) {
  static int order = 0;

  if (!is_uefi_firmware(li)) {
    order = 0;
    return 0;
  }

  switch (order++) {
  case 0:
    *fileformatname = FMT_UEFI_64;
    return 1 | ACCEPT_CONTINUE;
  case 1:
    *fileformatname = FMT_UEFI_32_PEI;
    order = 0;
    return 1;
  default:
    order = 0;
    return 0;
  }
}

void idaapi load_file(linput_t *li, ushort /*neflag*/,
                      const char *fileformatname) {
  int64 fsize = qlsize(li);
  if (fsize <= 0) {
    msg("[efiXloader] invalid input file size\n");
    return;
  }
  bytevec_t data;
  data.resize(fsize);
  qlseek(li, 0);
  if (qlread(li, data.begin(), fsize) != fsize) {
    msg("[efiXloader] failed to read input file\n");
    return;
  }

  bool load_32bit_pei =
      fileformatname != nullptr && strcmp(fileformatname, FMT_UEFI_32_PEI) == 0;

  // rename the IDB to include bitness suffix so that 32-bit and 64-bit
  // sessions produce distinct database files (e.g. fw.32.i64 / fw.64.i64)
  //
  // IDA has already created the initial .i64 under the original
  // name by the time load_file() runs; set_path only redirects future saves
  std::filesystem::path idb_path(get_path(PATH_TYPE_IDB));
  auto ext = idb_path.extension(); // ".i64"
  auto stem = idb_path.stem();
  auto parent = idb_path.parent_path();
  std::string new_stem = stem.string() + (load_32bit_pei ? ".32" : ".64");
  auto new_path = parent / (new_stem + ext.string());
  set_path(PATH_TYPE_IDB, new_path.string().c_str());

  efiloader::Uefitool uefi_parser(data);
  if (uefi_parser.messages_occurs()) {
    uefi_parser.show_messages();
  }
  uefi_parser.dump();
  uefi_parser.dump_jsons();

  if (uefi_parser.files.empty()) {
    msg("[efiXloader] can not parse input firmware\n");
    return;
  }

  if (load_32bit_pei) {
    add_til("uefi.til", ADDTIL_DEFAULT);
  } else {
    add_til("uefi64.til", ADDTIL_DEFAULT);
  }

  efiloader::PeManager pe_manager(uefi_parser.machine_type, load_32bit_pei);

  int processed = 0;
  for (size_t i = 0; i < uefi_parser.files.size(); i++) {
    const auto &file = uefi_parser.files[i];
    if (!load_32bit_pei && file->is_te) {
      // 64-bit mode: skip TE files (original behaviour)
      continue;
    }
    auto inf = open_linput(file->dump_name.c_str(), false);
    if (!inf) {
      msg("[efiXloader] unable to open file %s\n", file->dump_name.c_str());
      continue;
    }
    bool ok = false;
    if (file->is_te) {
      ok = pe_manager.process_te(inf, file->dump_name.c_str(), i);
    } else if (file->is_pe) {
      ok = pe_manager.process(inf, file->dump_name.c_str(), i);
    }
    if (ok) {
      processed++;
    }
  }

  if (processed == 0) {
    loader_failure("[efiXloader] no images were loaded");
  }

  plugin_t *findpat = find_plugin("patfind", true);
  if (findpat) {
    msg("[efiXloader] running the patfind plugin\n");
    run_plugin(findpat, 0);
  }
}

//--------------------------------------------------------------------------
// loader description block
loader_t LDSC = {
    IDP_INTERFACE_VERSION, 0, accept_file, load_file, nullptr, nullptr, nullptr,
};
