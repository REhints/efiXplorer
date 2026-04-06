// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <string>

#include "../ldr/idaldr.h"
#include "../ldr/pe/pe.h"

#include <typeinf.hpp>

#define PAGE_SIZE 0x1000

constexpr uint16_t MZ_SIGN = 0x5A4D; // MZ header
constexpr uint16_t PE_SIGN = 0x4550; // PE signature

namespace efiloader {

class PE {
public:
  PE(linput_t *i_li, const std::string &fname, ea_t *base, ushort *sel_base,
     int ord)
      : _image_name(fname.substr(fname.find_last_of("/\\") + 1)), pe_base(base),
        pe_sel_base(sel_base), li(i_li), _sec_off(0), _sec_ea(0), _sel(0),
        _ord(ord) {
    // compiler model is set after good() determines _bits
    if (default_compiler() == COMP_UNK) {
      set_compiler_id(COMP_MS);
    }
    reset();
  }

  ~PE() { close_linput(li); }

  uint32_t number_of_sections = 0;
  uint32_t number_of_dirs = 0;

  [[nodiscard]] bool is_reloc_dir(uint32_t i) const { return i == 5; }
  [[nodiscard]] bool is_debug_dir(uint32_t i) const { return i == 6; }
  [[nodiscard]] uint16_t bits() const { return _bits; }

  bool is_p32();
  bool is_p32_plus();
  bool is_pe();
  bool good();
  bool process();

  void push_to_idb(ea_t start, ea_t end) {
    file2base(li, 0x0, start, start + headers_size, FILEREG_PATCHABLE);
    for (uint32_t i = 0; i < number_of_sections; i++) {
      file2base(li, _sec_headers[i].s_scnptr, start + _sec_headers[i].s_vaddr,
                start + _sec_headers[i].s_vaddr + _sec_headers[i].s_psize,
                FILEREG_PATCHABLE);
    }
  }

private:
  std::string _image_name;
  linput_t *li;
  qoff64_t head_start();
  qoff64_t _pe_header_off = 0;
  uint16_t headers_size = 0;
  peheader_t pe = {};
  peheader64_t pe64 = {};
  uint16_t _bits = 0;

  void reset() { qlseek(li, 0); }

  void preprocess();
  ea_t create_byte_with(ea_t ea, const char *comment);
  ea_t create_word_with(ea_t ea, const char *comment);
  ea_t create_dword_with(ea_t ea, const char *comment);
  ea_t create_qword_with(ea_t ea, const char *comment);

  qvector<pesection_t> _sec_headers;
  ea_t *pe_base;
  ushort *pe_sel_base;
  ushort _sel;
  ea_t _sec_off;
  ea_t _sec_ea;
  uval_t _ord;
  ea_t image_base = 0;
  uint64_t default_image_base = 0;
  uint32_t image_size = 0;
  qvector<size_t> segm_sizes;
  qvector<size_t> segm_raw_sizes;
  qvector<ea_t> segm_entries;

  int preprocess_sections();

  void make_entry(ea_t ea);

  qvector<segment_t *> segments;
  qvector<qstring> segm_names;
  ea_t process_section_entry(ea_t ea);
  segment_t *make_generic_segment(ea_t seg_ea, ea_t seg_ea_end,
                                  const char *section_name, uint32_t flags);
  segment_t *make_head_segment(ea_t start, ea_t end, const char *name);
};
} // namespace efiloader

enum MachineType { AMD64 = 0x8664, I386 = 0x014C, AARCH64 = 0xaa64 };
