// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <string>

#include "pe.h"
#include "te.h"

namespace efiloader {
class PeManager {
public:
  explicit PeManager(uint16_t mt, bool mode_32bit = false)
      : machine_type(mt), m_32bit_mode(mode_32bit) {
    if (m_32bit_mode) {
      inf_set_64bit(false);
      inf_set_32bit();
    } else {
      inf_set_64bit();
    }
    set_imagebase(0x0);
    if (mt == PECPU_ARM64) {
      set_processor_type("arm", SETPROC_LOADER);
    } else {
      set_processor_type("metapc", SETPROC_LOADER);
    }
  }
  bool process(linput_t *li, const std::string &fname, int ord);
  bool process_te(linput_t *li, const std::string &fname, int ord);
  uint16_t machine_type;
  bool m_32bit_mode;

private:
  ushort pe_sel_base = 0;
  ea_t pe_base = 0;
};
} // namespace efiloader
