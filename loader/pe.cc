// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "pe.h"

#include <cinttypes>

constexpr int DIRECTORIES_MAX_ID = 15;

constexpr const char *DIRECTORIES[] = {
    "Export Directory",
    "Import Directory",
    "Resource Directory",
    "Exception Directory",
    "Security Directory",
    "Base Relocation Table",
    "Debug Directory",
    "Architecture Specific Data",
    "RVA of GP",
    "TLS Directory",
    "Load Configuration Directory",
    "Bound Import Directory in headers",
    "Import Address Table",
    "Delay Load Import Descriptors",
    "COM Runtime descriptor",
    "Image data directory",
};

//--------------------------------------------------------------------------
// efiloader core routines
qoff64_t efiloader::PE::head_start() {
  qlseek(li, 0x3c);
  qoff64_t off = readshort(li);
  reset();
  return off;
}

//--------------------------------------------------------------------------
// PE feature extraction
bool efiloader::PE::good() {
  uint16_t mz = 0;
  qlread(li, &mz, sizeof(uint16_t));
  if (mz != MZ_SIGN) {
    return false;
  }
  _pe_header_off = head_start();
  if (is_p32_plus()) {
    _bits = 64;
  } else if (!is_p32()) {
    loader_failure("[efiXloader] failed to guess PE bitness");
  } else {
    _bits = 32;
  }
  return is_pe();
}

bool efiloader::PE::is_p32() {
  uint16_t magic = 0;
  qlseek(li, _pe_header_off + sizeof(uint32_t));
  qlread(li, &magic, sizeof(uint16_t));
  reset();
  return magic == I386;
}

bool efiloader::PE::is_p32_plus() {
  uint16_t magic = 0;
  qlseek(li, _pe_header_off + sizeof(uint32_t));
  qlread(li, &magic, sizeof(uint16_t));
  reset();
  return (magic == AMD64 || magic == AARCH64);
}

bool efiloader::PE::is_pe() {
  uint16_t pe_sign = 0;
  qlseek(li, _pe_header_off);
  pe_sign = readshort(li);
  reset();
  return pe_sign == PE_SIGN;
}

bool efiloader::PE::process() {
  cm_t cm = inf_get_cc_cm() & ~CM_MASK;
  inf_set_cc_cm(cm | ((_bits == 64) ? CM_N64 : CM_N32_F48));
  preprocess();
  *pe_base = image_base + image_size;
  return true;
}

//--------------------------------------------------------------------------
// entry point processing
void efiloader::PE::make_entry(ea_t ea) {
  char func_name[MAXNAMESIZE] = {0};
  ea_t new_ea = image_base + ea;
  qsnprintf(func_name, sizeof(func_name), "%s_entry_%08X", _image_name.c_str(),
            calc_file_crc32(li));
  add_entry(new_ea, new_ea, func_name, true);
}

//--------------------------------------------------------------------------
// segment creation
segment_t *efiloader::PE::make_head_segment(ea_t start, ea_t end,
                                            const char *section_name) {
  segment_t *seg = new segment_t;
  seg->bitness = (_bits == 64) ? 2 : 1;
  seg->perm = SEG_DATA;
  seg->sel = allocate_selector(0x0);
  seg->start_ea = start;
  seg->end_ea = end;
  add_segm_ex(seg, section_name, "DATA", ADDSEG_NOAA | ADDSEG_NOSREG);
  return seg;
}

segment_t *efiloader::PE::make_generic_segment(ea_t seg_ea, ea_t seg_ea_end,
                                               const char *section_name,
                                               uint32_t flags) {
  segment_t *generic_segm = new segment_t;
  generic_segm->sel = allocate_selector(0x0);
  generic_segm->start_ea = seg_ea;
  generic_segm->end_ea = seg_ea_end;
  generic_segm->bitness = (_bits == 64) ? 2 : 1;
  generic_segm->perm = SEGPERM_READ;
  if (flags & PEST_EXEC)
    generic_segm->perm |= SEGPERM_EXEC;
  if (flags & PEST_WRITE)
    generic_segm->perm |= SEGPERM_WRITE;

  qstring name(section_name);

  if (name.find('.') == qstring::npos) {
    name += qstring(".unkn");
  }

  if (flags & PEST_EXEC) {
    generic_segm->type = SEG_CODE;
    add_segm_ex(generic_segm, name.c_str(), "CODE", ADDSEG_NOAA);
  } else {
    generic_segm->type = SEG_DATA;
    add_segm_ex(generic_segm, name.c_str(), "DATA", ADDSEG_NOAA);
  }

  return generic_segm;
}

int efiloader::PE::preprocess_sections() {
  qlseek(li, _pe_header_off);
  qlread(li, &pe, sizeof(peheader_t));

  // x86
  number_of_sections = pe.nobjs;
  int section_headers_offset = pe.first_section_pos(_pe_header_off);
  headers_size = pe.allhdrsize;

  if (pe.machine == PECPU_AMD64 || pe.machine == PECPU_ARM64) { // AMD64/AARCH64
    qlseek(li, _pe_header_off);
    qlread(li, &pe64, sizeof(peheader64_t));
    number_of_sections = pe64.nobjs;
    section_headers_offset = pe64.first_section_pos(_pe_header_off);
    headers_size = pe64.allhdrsize;
  }

  if (!headers_size) {
    return -1;
  }

  _sec_headers.resize(number_of_sections);
  qlseek(li, section_headers_offset);
  for (int i = 0; i < number_of_sections; i++) {
    qlread(li, &_sec_headers[i], sizeof(pesection_t));
  }

  return 0;
}

ea_t efiloader::PE::process_section_entry(ea_t next_ea) {
  create_strlit(next_ea, 8, STRTYPE_C);
  set_cmt(next_ea, "Name", 0);
  op_hex(next_ea, 0);
  size_t segm_name_len = get_max_strlit_length(next_ea, STRTYPE_C);

  if (segm_name_len) {
    get_strlit_contents(&segm_names.push_back(), next_ea, segm_name_len,
                        STRTYPE_C);
  } else {
    // if the segm_name_len is 0, it will trigger a crash on
    // segm_names.pop_back() later.
    segm_names.push_back("UNKNOWN");
  }

  next_ea += 8;
  create_dword_with(next_ea, "Virtual size");
  segm_sizes.push_back(get_dword(next_ea));
  next_ea += 4;
  create_dword_with(next_ea, "Virtual address");
  segm_entries.push_back(get_dword(next_ea));
  next_ea += 4;
  create_dword_with(next_ea, "Size of raw data");
  segm_raw_sizes.push_back(get_dword(next_ea));
  next_ea += 4;
  next_ea = create_dword_with(next_ea, "Pointer to raw data");
  next_ea = create_dword_with(next_ea, "Pointer to relocations");
  next_ea = create_dword_with(next_ea, "Pointer to line numbers");
  next_ea = create_word_with(next_ea, "Number of relocations");
  next_ea = create_word_with(next_ea, "Number of linenumbers");
  create_dword_with(next_ea, "Characteristics");
  uint32_t section_characteristics = get_dword(next_ea);
  next_ea += 4;

  qstring section_name = qstring(_image_name.c_str());
  section_name += qstring("_") + qstring(segm_names[0].c_str());

  ea_t seg_ea = image_base + segm_entries[0];
  ea_t seg_ea_end = seg_ea + segm_raw_sizes[0];
  msg("[efiXloader] processing: %s\n", segm_names[0].c_str());

  segments.push_back(make_generic_segment(
      seg_ea, seg_ea_end, section_name.c_str(), section_characteristics));
  segm_names.pop_back();
  segm_sizes.pop_back();
  segm_raw_sizes.pop_back();
  segm_entries.pop_back();
  return next_ea;
}

//--------------------------------------------------------------------------
// PE core processing
void efiloader::PE::preprocess() {
  char seg_header_name[MAXNAMESIZE] = {0};
  ea_t next_ea = 0;
  ea_t ea = align_up(*pe_base, PAGE_SIZE);
  image_base = ea;
  ea_t start = ea;
  ea_t end = ea + qlsize(li);
  qsnprintf(seg_header_name, sizeof(seg_header_name), "%s_HEADER",
            _image_name.c_str());

  if (preprocess_sections() == -1) {
    msg("[efiXloader]\tcannot load %s\n", _image_name.c_str());
    image_base = 0;
    image_size = 0;
    return;
  }
  push_to_idb(start, end);
  segments.push_back(make_head_segment(image_base, image_base + headers_size,
                                       seg_header_name));
  create_word_with(ea, "PE magic number");
  create_word_with(ea + 2, "Bytes on last page of file");
  create_word_with(ea + 4, "Pages in file");
  create_word_with(ea + 6, "Relocations");
  create_word_with(ea + 8, "Size of header in paragraphs");
  create_word_with(ea + 10, "Minimum extra paragraphs needed");
  create_word_with(ea + 12, "Maximum extra paragraphs needed");
  create_word_with(ea + 14, "Initial (relative) SS value");
  create_word_with(ea + 16, "Initial SP value");
  create_word_with(ea + 18, "Checksum");
  create_word_with(ea + 20, "Initial IP value");
  create_word_with(ea + 22, "Initial (relative) CS value");
  create_word_with(ea + 24, "File address of relocation table");
  op_offset(ea + 24, 0, (_bits == 64) ? REF_OFF64 : REF_OFF32, BADADDR,
            image_base);
  create_word_with(ea + 26, "Overlay number");
  create_word(ea + 28, 8);
  set_cmt(ea + 28, "Reserved words", 0);
  op_hex(ea + 28, 0);
  create_word_with(ea + 36, "OEM identifier (for e_oeminfo)");
  create_word_with(ea + 38, "OEM information; e_oemid specific");
  create_word_with(ea + 40, "Reserved words");
  ea_t old_ea = ea;
  ea = ea + 0x3c;
  create_dword_with(ea, "File address of new exe header");
  if (is_loaded(ea) && get_dword(ea)) {
    msg("[efiXloader] making relative offset: 0x%" PRIx64 "\n",
        static_cast<uint64_t>(ea));
    op_plain_offset(ea, 0, *pe_base);
  }
  uint32_t nt_headers_off = get_dword(ea);
  create_byte(old_ea + 0x40, nt_headers_off - 0x40);
  set_cmt(old_ea + 0x40, "DOS Stub code", 0);
  ea_t nt_headers_ea = old_ea + nt_headers_off;
  add_extra_cmt(nt_headers_ea, 1, "IMAGE_NT_HEADERS");
  switch (get_word(old_ea)) {
  case 0x20B:
    del_items(nt_headers_ea, 3, 0x108);
    break;
  default:
    del_items(nt_headers_ea, 3, 0xf8);
    break;
  }
  create_dword_with(nt_headers_ea, "Signature");
  ea_t image_file_header_ea = nt_headers_ea + 4;
  add_extra_cmt(image_file_header_ea, 1, "IMAGE_FILE_HEADER");
  create_word_with(image_file_header_ea, "Machine");
  image_file_header_ea += 2;
  create_word_with(image_file_header_ea, "Number of sections");
  number_of_sections = get_word(image_file_header_ea);
  ea_t timestamp_ea = image_file_header_ea + 2;
  create_dword_with(timestamp_ea, "Time stamp");
  ea_t pointer_to_symbol_table = timestamp_ea + 4;
  create_dword_with(pointer_to_symbol_table, "Pointer to symbol table");
  next_ea = pointer_to_symbol_table + 4;
  next_ea = create_dword_with(next_ea, "Number of symbols");
  uint16_t size_of_optional_header = get_word(next_ea);
  next_ea = create_word_with(next_ea, "Size of optional header");
  next_ea = create_word_with(next_ea, "Characteristics");
  add_extra_cmt(next_ea, 1, "IMAGE_OPTIONAL_HEADER");
  ea_t image_optional_header = next_ea;
  next_ea = create_word_with(next_ea, "Magic number");
  next_ea = create_byte_with(next_ea, "Major linker version");
  next_ea = create_byte_with(next_ea, "Minor linker version");
  next_ea = create_dword_with(next_ea, "Size of code");
  next_ea = create_dword_with(next_ea, "Size of initialized data");
  next_ea = create_dword_with(next_ea, "Size of uninitialized data");
  create_dword_with(next_ea, "Address of entry point");
  make_entry(get_dword(next_ea));
  refinfo_t ri;
  ri.init((_bits == 64) ? REF_OFF64 : REF_OFF32, image_base);
  if (is_loaded(next_ea) && get_dword(next_ea)) {
    op_offset_ex(next_ea, 0, &ri);
  }
  next_ea += 4;
  create_dword_with(next_ea, "Base of code");
  if (is_loaded(next_ea) && get_dword(next_ea)) {
    op_offset_ex(next_ea, 0, &ri);
  }
  next_ea += 4;
  if (_bits == 32) {
    // PE32: Base of data field (not present in PE32+)
    create_dword_with(next_ea, "Base of data");
    if (is_loaded(next_ea) && get_dword(next_ea)) {
      op_offset_ex(next_ea, 0, &ri);
    }
    next_ea += 4;
    // PE32: Image base is DWORD
    default_image_base = get_dword(next_ea);
    create_dword(next_ea, 4);
    set_cmt(next_ea, "Image base", 0);
    op_hex(next_ea, 0);
    op_plain_offset(next_ea, 0, *pe_base);
    next_ea += 4;
  } else {
    // PE32+: Image base is QWORD
    default_image_base = get_qword(next_ea);
    create_qword(next_ea, 8);
    set_cmt(next_ea, "Image base", 0);
    op_hex(next_ea, 0);
    op_plain_offset(next_ea, 0, *pe_base);
    next_ea += 8;
  }
  next_ea = create_dword_with(next_ea, "Section alignment");
  next_ea = create_dword_with(next_ea, "File alignment");
  next_ea = create_word_with(next_ea, "Major operating system version");
  next_ea = create_word_with(next_ea, "Minor operating system version");
  next_ea = create_word_with(next_ea, "Major image version");
  next_ea = create_word_with(next_ea, "Minor image version");
  next_ea = create_word_with(next_ea, "Major subsystem version");
  next_ea = create_word_with(next_ea, "Minor subsystem version");
  next_ea = create_dword_with(next_ea, "Win32 Version value");
  create_dword_with(next_ea, "Size of image");
  image_size = get_dword(next_ea);
  next_ea += 4;
  next_ea = create_dword_with(next_ea, "Size of headers");
  next_ea = create_dword_with(next_ea, "Checksum");
  next_ea = create_word_with(next_ea, "Subsystem");
  next_ea = create_word_with(next_ea, "Dll characteristics");
  if (_bits == 32) {
    // PE32: stack/heap sizes are DWORDs
    next_ea = create_dword_with(next_ea, "Size of stack reserve");
    next_ea = create_dword_with(next_ea, "Size of stack commit");
    next_ea = create_dword_with(next_ea, "Size of heap reserve");
    next_ea = create_dword_with(next_ea, "Size of heap commit");
  } else {
    // PE32+: stack/heap sizes are QWORDs
    next_ea = create_qword_with(next_ea, "Size of stack reserve");
    next_ea = create_qword_with(next_ea, "Size of stack commit");
    next_ea = create_qword_with(next_ea, "Size of heap reserve");
    next_ea = create_qword_with(next_ea, "Size of heap commit");
  }
  next_ea = create_dword_with(next_ea, "Loader flag");
  create_dword_with(next_ea, "Number of data directories");
  if (!is_loaded(next_ea)) {
    msg("[efiXloader] warning: data directory count not mapped\n");
    number_of_dirs = 0;
  } else {
    number_of_dirs = get_dword(next_ea);
    if (number_of_dirs > DIRECTORIES_MAX_ID + 1) {
      number_of_dirs = DIRECTORIES_MAX_ID + 1;
    }
  }
  next_ea += 4;
  for (int i = 0; i < number_of_dirs; i++) {
    if (is_reloc_dir(i)) {
      uint32_t relocs_rva = get_dword(next_ea);
      uint32_t relocs_size = get_dword(next_ea + 4);
      if (relocs_rva && relocs_size) {
        ea_t relocs_va = image_base + relocs_rva;
        ea_t relocs_va_end = relocs_va + relocs_size;
        ea_t delta = image_base - default_image_base;
        ea_t block_addr = get_dword(relocs_va);
        ea_t block_size = get_dword(relocs_va + 4);
        while (block_size >= 8 && relocs_va < relocs_va_end) {
          ea_t block_base = image_base + block_addr;
          int block_reloc_count = (block_size - 8) / 2;

          ea_t block_ptr = relocs_va + 8;
          while (block_reloc_count--) {
            uint16_t reloc_value = get_word(block_ptr);
            uint16_t type = reloc_value & PER_TYPE;
            uint16_t offset = reloc_value & PER_OFF;
            if (type == PER_DIR64)
              add_qword(block_base + offset, delta);
            else if (type == PER_HIGHLOW)
              add_dword(block_base + offset, static_cast<uint32_t>(delta));
            else if (type == PER_HIGH)
              add_word(block_base + offset, static_cast<uint16_t>(delta >> 16));
            else if (type == PER_LOW)
              add_word(block_base + offset, static_cast<uint16_t>(delta));
            block_ptr += 2;
          }
          relocs_va += block_size;

          block_addr = get_dword(relocs_va);
          block_size = get_dword(relocs_va + 4);
        }
      }
    }
    if (is_reloc_dir(i) || is_debug_dir(i)) {
      add_extra_cmt(next_ea, true, "%s", DIRECTORIES[i]);
      create_dword(next_ea, 4);
      create_dword(next_ea + 4, 4);
      op_hex(next_ea, 0);
      op_hex(next_ea + 4, 0);
      set_cmt(next_ea, "Virtual address", 0);
      set_cmt(next_ea + 4, "Size", 0);
    } else {
      create_qword(next_ea, 8);
      set_cmt(next_ea, DIRECTORIES[i], 0);
    }
    next_ea += 8;
  }
  del_items(next_ea, DELIT_EXPAND | DELIT_DELNAMES, 0x28 * number_of_sections);
  for (int i = 0; i < number_of_sections; i++) {
    next_ea = process_section_entry(next_ea);
  }
}

ea_t efiloader::PE::create_byte_with(ea_t ea, const char *comment) {
  create_byte(ea, 1);
  set_cmt(ea, comment, 0);
  op_hex(ea, 0);
  return ea + 1;
}

ea_t efiloader::PE::create_word_with(ea_t ea, const char *comment) {
  create_word(ea, 2);
  set_cmt(ea, comment, 0);
  op_hex(ea, 0);
  return ea + 2;
}

ea_t efiloader::PE::create_dword_with(ea_t ea, const char *comment) {
  create_dword(ea, 4);
  set_cmt(ea, comment, 0);
  op_hex(ea, 0);
  return ea + 4;
}

ea_t efiloader::PE::create_qword_with(ea_t ea, const char *comment) {
  create_qword(ea, 8);
  set_cmt(ea, comment, 0);
  op_hex(ea, 0);
  return ea + 8;
}
