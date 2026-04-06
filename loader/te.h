// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <string>

#include "pe.h"

constexpr uint16_t TE_SIGN = 0x5A56; // "VZ"
constexpr size_t TE_HEADER_SIZE = 40;

// TE image header (PI Specification)
#pragma pack(push, 1)
struct te_header_t {
  uint16_t signature;
  uint16_t machine;
  uint8_t number_of_sections;
  uint8_t subsystem;
  uint16_t stripped_size;
  uint32_t address_of_entry_point;
  uint32_t base_of_code;
  uint64_t image_base;
  // data_directory[0] = base relocation
  // data_directory[1] = debug
  uint32_t reloc_dir_rva;
  uint32_t reloc_dir_size;
  uint32_t debug_dir_rva;
  uint32_t debug_dir_size;
};
#pragma pack(pop)

namespace efiloader {

class TE {
public:
  TE(linput_t *i_li, const std::string &fname, ea_t *base, ushort *sel_base,
     int ord)
      : _image_name(fname.substr(fname.find_last_of("/\\") + 1)), pe_base(base),
        pe_sel_base(sel_base), li(i_li), _ord(ord) {
    if (default_compiler() == COMP_UNK) {
      set_compiler_id(COMP_MS);
    }
    qlseek(li, 0);
  }

  ~TE() { close_linput(li); }

  bool good();
  bool process();

  [[nodiscard]] uint16_t machine() const { return _header.machine; }

private:
  std::string _image_name;
  linput_t *li;
  te_header_t _header = {};
  qvector<pesection_t> _sec_headers;

  ea_t *pe_base;
  ushort *pe_sel_base;
  uval_t _ord;

  ea_t image_base = 0;
  uint32_t image_size = 0;

  // adjustment: original PE headers were stripped, TE header replaces them
  // file offsets in section headers are relative to the original PE layout
  // adjustment = stripped_size - sizeof(te_header_t)
  int32_t _adjust = 0;

  void make_entry(ea_t rva);
  segment_t *make_segment(ea_t start, ea_t end, const char *name,
                          uint32_t flags);
};

} // namespace efiloader
