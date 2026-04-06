// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_deps.h"

#include <map>
#include <string>

efi_deps_t::efi_deps_t() {
  // read DEPEX (for protocols) from
  // .deps.json file if this file exists
  load_deps_from_uefitool();
  // get modules names from IDB
  get_modules();
  // read modules with GUIDs from
  // .images.json file if this file exists
  load_modules_with_guids();
}

efi_deps_t::~efi_deps_t() {
  m_additional_installers.clear();
  m_modules_from_idb.clear();
  m_modules_guids.clear();
  m_modules_info.clear();
  m_modules_sequence.clear();
  m_protocols_by_guids.clear();
  m_protocols_chooser.clear();
  m_protocols_without_installers.clear();
  m_uefitool_deps.clear();
}

json efi_deps_t::get_deps_for(std::string guid) {
  json res;
  std::vector installers({"InstallProtocolInterface",
                          "InstallMultipleProtocolInterfaces",
                          "SmmInstallProtocolInterface"});
  for (auto &it : m_protocols_chooser.items()) {
    auto p = it.value();
    if (p["guid"] != guid) {
      continue;
    }
    p["ea"] = efi_utils::as_hex(u64_addr(p["ea"]));
    p["xref"] = efi_utils::as_hex(u64_addr(p["xref"]));
    p["address"] = efi_utils::as_hex(u64_addr(p["address"]));
    if (find(installers.begin(), installers.end(), p["service"]) !=
        installers.end()) {
      res["installed"].push_back(p);
    } else {
      res["used"].push_back(p);
    }
  }

  return res;
}

void efi_deps_t::get_protocols_by_guids(json_list_t protocols) {
  for (auto &p : protocols) {
    // check if entry for GUID already exists
    auto guid = p["guid"];
    auto &deps = m_protocols_by_guids[guid];
    if (deps.is_null()) {
      deps = get_deps_for(guid);
    }
  }
}

void efi_deps_t::get_protocols_chooser(json_list_t protocols) {
  auto i = 0;
  for (auto p : protocols) {
    m_protocols_chooser[i] = p;
    ++i;
  }
}

bool efi_deps_t::load_deps_from_uefitool() {
  std::string deps_json = std::string(get_path(PATH_TYPE_CMD)) + ".deps.json";
  if (!std::filesystem::exists(deps_json)) {
    return false;
  }
  std::ifstream file(deps_json);
  file >> m_uefitool_deps;
  return true;
}

bool efi_deps_t::load_modules_with_guids() {
  std::string modules_json =
      std::string(get_path(PATH_TYPE_CMD)) + ".images.json";
  if (!std::filesystem::exists(modules_json)) {
    return false;
  }
  std::ifstream file(modules_json);
  file >> m_modules_guids;
  return true;
}

bool efi_deps_t::installer_found(std::string protocol) {
  auto deps_prot = m_protocols_by_guids[protocol];
  if (deps_prot.is_null()) {
    return false;
  }
  auto installers = deps_prot["installed"];
  return installers.is_null();
}

void efi_deps_t::get_protocols_without_installers() {
  // check DXE_DEPEX and MM_DEPEX
  string_list_t sections{"EFI_SECTION_DXE_DEPEX", "EFI_SECTION_MM_DEPEX"};
  for (auto section : sections) {
    auto modules = m_uefitool_deps[section];
    for (auto &element : modules.items()) {
      auto protocols = element.value();
      for (std::string ps : protocols) {
        if (!installer_found(ps)) {
          m_protocols_without_installers.insert(ps);
        }
      }
    }
  }
}

void efi_deps_t::get_installers_modules() {
  // search for this protocols in binary
  for (auto &protocol : m_protocols_without_installers) {
    auto addrs = efi_utils::search_protocol(protocol);
    bool installer_found = false;
    for (auto addr : addrs) {
      auto xrefs = efi_utils::get_xrefs(addr);
      if (!xrefs.size()) {
        continue;
      }
      if (xrefs.size() == 1) {
        auto xref = *xrefs.begin();
        func_t *func = get_func(xref);
        if (func == nullptr) {
          xrefs = efi_utils::get_xrefs_to_array(xref);
        }
      }
      for (auto ea : xrefs) {
        if (efi_utils::check_install_protocol(ea)) {
          auto module = efi_utils::get_module_name_loader(ea);
          m_additional_installers[protocol] = module.c_str();
          installer_found = true;
          break;
        }
      }
      if (installer_found) {
        break;
      }
    }
    if (!installer_found) {
      m_untracked_protocols.insert(protocol);
    }
  }
}

void efi_deps_t::get_additional_installers() {
  get_protocols_without_installers();
  get_installers_modules();
  std::string installers = m_additional_installers.dump(2);
  efi_utils::log("additional installers: %s\n", installers.c_str());
  for (auto &protocol : m_untracked_protocols) {
    efi_utils::log("untracked protocol: %s\n", protocol.c_str());
  }
}

void efi_deps_t::get_modules() {
  for (segment_t *s = get_first_seg(); s != nullptr;
       s = get_next_seg(s->start_ea)) {
    qstring seg_name;
    get_segm_name(&seg_name, s);

    string_list_t cseg_names{"_.text", "_.code"};
    for (auto name : cseg_names) {
      auto index = seg_name.find(name.c_str());
      if (index != std::string::npos) {
        std::string module_name =
            static_cast<std::string>(seg_name.c_str()).substr(0, index);
        if (!module_name.rfind("_", 0)) {
          module_name = module_name.erase(0, 1);
        }
        m_modules_from_idb.insert(module_name);
      }
    }
  }
}

json efi_deps_t::get_module_info(std::string module) {
  json info;
  string_list_t deps_protocols;
  string_list_t installed_protocols;
  std::vector installers({"InstallProtocolInterface",
                          "InstallMultipleProtocolInterfaces",
                          "SmmInstallProtocolInterface"});

  // get installed protocols
  for (auto &p :
       m_additional_installers.items()) { // check additional installers
    std::string ad_installer_module = p.value();
    std::string ad_installer_protocol = p.key();
    if (ad_installer_module == module) {
      installed_protocols.push_back(ad_installer_protocol);
      break;
    }
  }

  for (auto &element : m_protocols_chooser.items()) { // check efiXplorer report
    json p = element.value();
    std::string module_name = p["module"];
    if (!module_name.rfind("_", 0)) {
      module_name = module_name.erase(0, 1);
    }
    if (module_name != module) {
      continue;
    }
    if (find(installers.begin(), installers.end(), p["service"]) !=
        installers.end()) {
      installed_protocols.push_back(p["guid"]);
    }
  }

  // get dependencies
  bool found = false;
  string_list_t sections{"EFI_SECTION_DXE_DEPEX", "EFI_SECTION_MM_DEPEX"};
  for (auto section : sections) {
    json deps_modules = m_uefitool_deps[section];
    for (auto &element : deps_modules.items()) {
      std::string dmodule_guid = element.key();
      if (m_modules_guids[dmodule_guid].is_null()) {
        // can not get name for module
        continue;
      }
      std::string dmodule_name = m_modules_guids[dmodule_guid]["name"];
      if (dmodule_name == module) {
        deps_protocols = element.value();
        found = true;
        break;
      }
    }
    if (found) {
      break;
    }
  }

  info["installed_protocols"] = installed_protocols;
  info["deps_protocols"] = deps_protocols;

  return info;
}

string_set_t efi_deps_t::get_apriori_modules() {
  string_set_t apriori_modules;
  string_list_t files{"DXE_APRIORI_FILE"};
  for (auto file : files) {
    auto modules = m_uefitool_deps[file];
    for (auto &mguid : modules) {
      std::string module = m_modules_guids[mguid]["name"];
      apriori_modules.insert(module);
    }
  }

  return apriori_modules;
}

bool efi_deps_t::get_modules_info() {
  if (!m_modules_info.empty()) {
    return true;
  }

  for (auto module : m_modules_from_idb) {
    m_modules_info[module] = get_module_info(module);
  }
  return true;
}

std::string efi_deps_t::get_installer(std::string protocol) {
  for (auto &e : m_modules_info.items()) {
    std::string module = e.key();
    string_list_t installers = m_modules_info[module]["installed_protocols"];
    if (find(installers.begin(), installers.end(), protocol) !=
        installers.end()) {
      return module;
    }
  }

  return std::string();
}

bool efi_deps_t::build_modules_sequence() {
  if (m_modules_sequence.size()) {
    return true;
  }

  string_set_t module_seq;
  string_set_t installed_protocols;

  // it's difficult to find installers for all the protocols statically
  get_protocols_without_installers();
  get_modules_info();

  // load apriori modules
  size_t index = 0;
  for (auto &module : get_apriori_modules()) {
    efi_utils::log("apriori module: %s\n", module.c_str());

    if (!m_modules_info.contains(module)) {
      continue;
    }

    string_list_t installers = m_modules_info[module]["installed_protocols"];
    installed_protocols.insert(installers.begin(), installers.end());

    json inf;
    inf["module"] = module;
    auto deps = m_modules_info[module]["deps_protocols"];
    if (!deps.empty()) {
      inf["deps"] = deps;
    }
    m_modules_sequence[index++] = inf;
    module_seq.insert(module);
  }

  while (module_seq.size() != m_modules_info.size()) {
    bool changed = false;

    for (auto &e : m_modules_info.items()) {
      auto module = e.key();  // current module
      auto minfo = e.value(); // current module information

      // check if the module is already loaded
      if (module_seq.find(module) != module_seq.end()) {
        continue;
      }

      string_list_t installers = minfo["installed_protocols"];

      // if there are no dependencies
      if (minfo["deps_protocols"].empty()) {
        installed_protocols.insert(installers.begin(), installers.end());

        json inf;
        inf["module"] = module;
        m_modules_sequence[index++] = inf;
        module_seq.insert(module);
        changed = true;
        continue;
      }

      string_list_t deps = minfo["deps_protocols"];
      string_list_t unresolved_deps;

      bool load = true;
      for (auto protocol : deps) {
        if (installed_protocols.find(protocol) != installed_protocols.end()) {
          continue;
        }

        if (m_protocols_without_installers.find(protocol) !=
            m_protocols_without_installers.end()) {
          unresolved_deps.push_back(protocol);
          continue;
        }

        load = false;
        break;
      }

      if (load) {
        installed_protocols.insert(installers.begin(), installers.end());

        json inf;
        inf["module"] = module;
        inf["deps"] = deps;
        if (!unresolved_deps.empty()) {
          inf["unresolved_deps"] = unresolved_deps;
        }
        m_modules_sequence[index++] = inf;
        module_seq.insert(module);
        changed = true;
      }
    }

    if (!changed) { // we are in a loop, we need to load a module that installs
                    // the most popular protocol
      std::map<std::string, size_t>
          protocols_usage; // get the most popular protocol
      for (auto &e : m_modules_info.items()) {
        auto module = e.key();
        auto minfo = e.value();

        // check if the module is already loaded
        if (module_seq.find(module) != module_seq.end() ||
            minfo["deps_protocols"].empty()) {
          continue;
        }

        string_list_t deps_protocols = minfo["deps_protocols"];
        for (auto protocol : deps_protocols) {
          if (installed_protocols.find(protocol) != installed_protocols.end() ||
              m_protocols_without_installers.find(protocol) !=
                  m_protocols_without_installers.end()) {
            continue;
          }

          if (protocols_usage.find(protocol) == protocols_usage.end()) {
            // initialise
            protocols_usage[protocol] = 1;
          } else {
            protocols_usage[protocol] += 1;
          }
        }
      }

      size_t mnum = 0;
      std::string mprotocol;
      for (auto const &[prot, counter] : protocols_usage) {
        if (counter > mnum) {
          mnum = counter;
          mprotocol = prot;
        }
      }

      if (!mnum) {
        break; // the most popular protocol was not found
      }

      // find installer module for mprotocol
      std::string installer_module = get_installer(mprotocol);
      if (!installer_module.size()) {
        efi_utils::log("can not find installer for protocol %s\n",
                       mprotocol.c_str());
        break;
      }

      // load installer module
      string_list_t current_installers =
          m_modules_info[installer_module]["installed_protocols"];
      auto deps = m_modules_info[installer_module]["deps_protocols"];

      installed_protocols.insert(current_installers.begin(),
                                 current_installers.end());

      json inf;
      inf["module"] = installer_module;
      if (!deps.empty()) {
        inf["deps"] = deps;
      }
      m_modules_sequence[index++] = inf;

      module_seq.insert(installer_module);
    }
  }

  return true;
}
