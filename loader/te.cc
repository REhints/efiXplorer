// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "te.h"

#include <cinttypes>

bool efiloader::TE::good() {
  qlseek(li, 0);
  if (qlread(li, &_header, sizeof(te_header_t)) != sizeof(te_header_t)) {
    return false;
  }
  if (_header.signature != TE_SIGN) {
    return false;
  }
  if (_header.number_of_sections == 0 || _header.number_of_sections > 64) {
    return false;
  }

  // adjustment: original PE header was larger, TE header is smaller
  _adjust = _header.stripped_size - static_cast<int32_t>(TE_HEADER_SIZE);

  // read section headers (immediately after TE header)
  _sec_headers.resize(_header.number_of_sections);
  for (int i = 0; i < _header.number_of_sections; i++) {
    if (qlread(li, &_sec_headers[i], sizeof(pesection_t)) !=
        sizeof(pesection_t)) {
      return false;
    }
  }

  return true;
}

bool efiloader::TE::process() {
  // set compiler model for 32-bit
  cm_t cm = inf_get_cc_cm() & ~CM_MASK;
  if (_header.machine == I386) {
    inf_set_cc_cm(cm | CM_N32_F48);
  } else {
    inf_set_cc_cm(cm | CM_N64);
  }

  int bitness = (_header.machine == I386) ? 1 : 2;

  ea_t ea = align_up(*pe_base, PAGE_SIZE);
  image_base = ea;

  // compute image size from sections
  uint32_t max_end = 0;
  for (int i = 0; i < _header.number_of_sections; i++) {
    uint32_t sec_end = _sec_headers[i].s_vaddr + _sec_headers[i].s_psize;
    if (sec_end > max_end) {
      max_end = sec_end;
    }
  }
  image_size = max_end;

  // load TE header into IDB
  int64 file_size = qlsize(li);
  file2base(li, 0, ea, ea + file_size, FILEREG_PATCHABLE);

  // create header segment
  char seg_name[MAXNAMESIZE] = {0};
  qsnprintf(seg_name, sizeof(seg_name), "%s_HEADER", _image_name.c_str());

  uint32_t headers_end =
      TE_HEADER_SIZE + _header.number_of_sections * sizeof(pesection_t);

  segment_t *hdr_seg = new segment_t;
  hdr_seg->bitness = bitness;
  hdr_seg->perm = SEG_DATA;
  hdr_seg->sel = allocate_selector(0x0);
  hdr_seg->start_ea = ea;
  hdr_seg->end_ea = ea + headers_end;
  add_segm_ex(hdr_seg, seg_name, "DATA", ADDSEG_NOAA | ADDSEG_NOSREG);

  // create segments for each section
  for (int i = 0; i < _header.number_of_sections; i++) {
    const pesection_t &sec = _sec_headers[i];

    // section file offset is adjusted: original offset - adjustment
    int32_t file_off = sec.s_scnptr - _adjust;
    ea_t seg_ea = image_base + sec.s_vaddr - _adjust;
    ea_t seg_end = seg_ea + sec.s_psize;

    char section_name[8 + 1] = {0};
    memcpy(section_name, sec.s_name, 8);

    qstring full_name(_image_name.c_str());
    full_name += qstring("_") + qstring(section_name);

    msg("[efiXloader] TE processing: %s\n", section_name);

    segment_t *seg = new segment_t;
    seg->sel = allocate_selector(0x0);
    seg->start_ea = seg_ea;
    seg->end_ea = seg_end;
    seg->bitness = bitness;
    seg->perm = SEGPERM_READ;
    if (sec.s_flags & PEST_EXEC) {
      seg->perm |= SEGPERM_EXEC;
    }
    if (sec.s_flags & PEST_WRITE) {
      seg->perm |= SEGPERM_WRITE;
    }

    if (sec.s_flags & PEST_EXEC) {
      seg->type = SEG_CODE;
      add_segm_ex(seg, full_name.c_str(), "CODE", ADDSEG_NOAA);
    } else {
      seg->type = SEG_DATA;
      add_segm_ex(seg, full_name.c_str(), "DATA", ADDSEG_NOAA);
    }
  }

  // create entry point
  make_entry(_header.address_of_entry_point);

  *pe_base = image_base + image_size;
  return true;
}

void efiloader::TE::make_entry(ea_t rva) {
  char func_name[MAXNAMESIZE] = {0};
  // entry point RVA needs adjustment for the stripped header
  ea_t entry_ea = image_base + rva - _adjust;
  qsnprintf(func_name, sizeof(func_name), "%s_entry_%08X", _image_name.c_str(),
            calc_file_crc32(li));
  add_entry(entry_ea, entry_ea, func_name, true);
}

segment_t *efiloader::TE::make_segment(ea_t start, ea_t end, const char *name,
                                       uint32_t flags) {
  int bitness = (_header.machine == I386) ? 1 : 2;
  segment_t *seg = new segment_t;
  seg->sel = allocate_selector(0x0);
  seg->start_ea = start;
  seg->end_ea = end;
  seg->bitness = bitness;
  seg->perm = SEGPERM_READ;
  if (flags & PEST_EXEC) {
    seg->perm |= SEGPERM_EXEC;
    seg->type = SEG_CODE;
    add_segm_ex(seg, name, "CODE", ADDSEG_NOAA);
  } else {
    seg->type = SEG_DATA;
    add_segm_ex(seg, name, "DATA", ADDSEG_NOAA);
  }
  return seg;
}
