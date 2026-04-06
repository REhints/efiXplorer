// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "pe_manager.h"

#include <string>

bool efiloader::PeManager::process(linput_t *li, const std::string &fname,
                                   int ord) {
  efiloader::PE pe(li, fname, &pe_base, &pe_sel_base, ord);
  if (!pe.good()) {
    msg("[efiXloader] %s is not loaded (invalid PE)\n", fname.c_str());
    return false;
  }
  if (m_32bit_mode) {
    if (!pe.is_p32()) {
      msg("[efiXloader] %s is not loaded (not 32-bit)\n", fname.c_str());
      return false;
    }
  } else {
    if (!pe.is_p32_plus()) {
      msg("[efiXloader] %s is not loaded (32-bit)\n", fname.c_str());
      return false;
    }
  }
  pe.process();
  return true;
}

bool efiloader::PeManager::process_te(linput_t *li, const std::string &fname,
                                      int ord) {
  efiloader::TE te(li, fname, &pe_base, &pe_sel_base, ord);
  if (!te.good()) {
    msg("[efiXloader] %s is not loaded (invalid TE)\n", fname.c_str());
    return false;
  }
  if (m_32bit_mode) {
    if (te.machine() != I386) {
      msg("[efiXloader] %s is not loaded (TE not 32-bit)\n", fname.c_str());
      return false;
    }
  } else {
    if (te.machine() == I386) {
      msg("[efiXloader] %s is not loaded (TE 32-bit)\n", fname.c_str());
      return false;
    }
  }
  te.process();
  return true;
}
