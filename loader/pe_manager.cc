// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "pe_manager.h"

#include <string>

bool efiloader::PeManager::process(linput_t *li, const std::string &fname,
                                   int ord) {
  // 32-bit modules and modules in the TE format will not be loaded
  efiloader::PE pe(li, fname, &pe_base, &pe_sel_base, ord, machine_type);
  if (!pe.good()) {
    msg("[efiXloader] %s is not loaded (invalid PE)\n", fname.c_str());
    return false;
  }
  if (!pe.is_p32_plus()) {
    msg("[efiXloader] %s is not loaded (32-bit)\n", fname.c_str());
    return false;
  }
  pe.process();
  return true;
}
