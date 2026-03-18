// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <memory>
#include <string>

#include "ida_core.h"
#include "pe.h"

namespace efiloader {
class PeManager {
public:
  explicit PeManager(uint16_t mt) {
    inf_set_64bit();
    set_imagebase(0x0);
    if (mt == PECPU_ARM64) {
      set_processor_type("arm", SETPROC_LOADER);
    } else {
      set_processor_type("metapc", SETPROC_LOADER);
    }
    pe_base = 0;
    pe_sel_base = 0;
    machine_type = mt;
  }
  bool process(linput_t *li, const std::string &fname, int ord);
  uint16_t machine_type;

private:
  void to_base(linput_t *);
  std::unique_ptr<efiloader::PE> pe;
  qvector<std::unique_ptr<efiloader::PE>> pe_files;
  ushort pe_sel_base;
  ea_t pe_base;
  // head processing
  void pe_head_to_base(linput_t *li);
};
} // namespace efiloader
