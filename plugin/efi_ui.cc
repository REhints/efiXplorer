// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#include "efi_ui.h"
#include "efi_deps.h"
#include "efi_global.h"

#include <string>

// vulns column widths
const int vulns_chooser_t::widths_vulns[] = {
    16, // Address
    32, // Vuln type
};

// vulns column headers
const char *const vulns_chooser_t::header_vulns[] = {
    "Address", // 0
    "Type",    // 1
};

// guids column widths
const int guids_chooser_t::widths_guids[] = {
    16, // Address
    32, // GUID
    32  // Name
};

// guids column headers
const char *const guids_chooser_t::header_guids[] = {
    "Address", // 0
    "GUID",    // 1
    "Name"     // 2
};

// protocols column widths
const int m_protocols_chooser_t::widths_protocols[] = {
    16, // Address
    32, // GUID
    32, // Name
    32, // Service
    32  // Module
};

// protocols column headers
const char *const m_protocols_chooser_t::header_protocols[] = {
    "Address", // 0
    "GUID",    // 1
    "Name",    // 2
    "Service", // 3
    "Module"   // 4
};

// services column widths
const int services_chooser_t::widths_s[] = {
    16, // Address
    32, // Service name
    32, // Table name
};

// services column headers
const char *const services_chooser_t::header_s[] = {
    "Address",      // 0
    "Service name", // 1
    "Table name"    // 2
};

// services column widths
const int nvram_chooser_t::widths_nvram[] = {
    16, // Address
    32, // Variable name
    32, // Variable GUID
    32, // Service
    64, // Attributes
};

// NVRAMs column headers
const char *const nvram_chooser_t::header_nvram[] = {
    "Address",       // 0
    "Variable name", // 1
    "Variable GUID", // 2
    "Service",       // 3
    "Attributes"     // 4
};

inline nvram_chooser_t::nvram_chooser_t(const char *title_, bool ok,
                                        json_list_t nvram)
    : chooser_t(0, qnumber(widths_nvram), widths_nvram, header_nvram, title_),
      list() {
  CASSERT(qnumber(widths_nvram) == qnumber(header_nvram));
  build_list(ok, nvram);
}

void idaapi nvram_chooser_t::get_row(qstrvec_t *cols_, int *,
                                     chooser_item_attrs_t *, size_t n) const {
  ea_t ea = list[n];
  qstrvec_t &cols = *cols_;
  json item = chooser_nvram[n];
  std::string name = item["VariableName"];
  std::string guid = item["VendorGuid"];
  std::string service = item["service"];
  std::string attributes = item["AttributesHumanReadable"];
  cols[0].sprnt("%016" PRIX64, u64_addr(ea));
  cols[1].sprnt("%s", name.c_str());
  cols[2].sprnt("%s", guid.c_str());
  cols[3].sprnt("%s", service.c_str());
  cols[4].sprnt("%s", attributes.c_str());
  CASSERT(qnumber(header_nvram) == 5);
}

inline vulns_chooser_t::vulns_chooser_t(const char *title_, bool ok,
                                        json_list_t vulns)
    : chooser_t(0, qnumber(widths_vulns), widths_vulns, header_vulns, title_),
      list() {
  CASSERT(qnumber(widths_vulns) == qnumber(header_vulns));
  build_list(ok, vulns);
}

void idaapi vulns_chooser_t::get_row(qstrvec_t *cols_, int *,
                                     chooser_item_attrs_t *, size_t n) const {
  ea_t ea = list[n];
  qstrvec_t &cols = *cols_;
  json item = chooser_vulns[n];
  std::string type = item["type"];
  cols[0].sprnt("%016" PRIX64, u64_addr(ea));
  cols[1].sprnt("%s", type.c_str());
  CASSERT(qnumber(header_vulns) == 2);
}

inline guids_chooser_t::guids_chooser_t(const char *title_, bool ok,
                                        json_list_t guids)
    : chooser_t(0, qnumber(widths_guids), widths_guids, header_guids, title_),
      list() {
  CASSERT(qnumber(widths_guids) == qnumber(header_guids));
  build_list(ok, guids);
}

void idaapi guids_chooser_t::get_row(qstrvec_t *cols_, int *,
                                     chooser_item_attrs_t *, size_t n) const {
  ea_t ea = list[n];
  qstrvec_t &cols = *cols_;
  json item = chooser_guids[n];
  std::string guid = item["guid"];
  std::string name = item["name"];
  cols[0].sprnt("%016" PRIX64, u64_addr(ea));
  cols[1].sprnt("%s", guid.c_str());
  cols[2].sprnt("%s", name.c_str());
  CASSERT(qnumber(header_guids) == 3);
}

inline m_protocols_chooser_t::m_protocols_chooser_t(const char *title_, bool ok,
                                                    json_list_t protocols,
                                                    std::string name_key_)
    : chooser_t(0, qnumber(widths_protocols), widths_protocols,
                header_protocols, title_),
      list() {
  CASSERT(qnumber(widths_protocols) == qnumber(header_protocols));
  name_key = name_key_;
  build_list(ok, protocols);
}

void idaapi m_protocols_chooser_t::get_row(qstrvec_t *cols_, int *,
                                           chooser_item_attrs_t *,
                                           size_t n) const {
  ea_t ea = list[n];
  qstrvec_t &cols = *cols_;
  json item = chooser_protocols[n];
  std::string name = item[name_key];
  std::string service = item["service"];
  std::string protGuid = item["guid"];
  std::string moduleName = item["module"];
  cols[0].sprnt("%016" PRIX64, u64_addr(ea));
  cols[1].sprnt("%s", protGuid.c_str());
  cols[2].sprnt("%s", name.c_str());
  cols[3].sprnt("%s", service.c_str());
  cols[4].sprnt("%s", moduleName.c_str());
  CASSERT(qnumber(header_protocols) == 5);
}

inline services_chooser_t::services_chooser_t(const char *title_, bool ok,
                                              json_list_t services)
    : chooser_t(0, qnumber(widths_s), widths_s, header_s, title_), list() {
  CASSERT(qnumber(widths_s) == qnumber(header_s));
  build_list(ok, services);
}

void idaapi services_chooser_t::get_row(qstrvec_t *cols_, int *,
                                        chooser_item_attrs_t *,
                                        size_t n) const {
  ea_t ea = list[n];
  qstrvec_t &cols = *cols_;
  json item = chooser_s[n];
  std::string service_name = item["service_name"];
  std::string table_name = item["table_name"];
  cols[0].sprnt("%016" PRIX64, u64_addr(ea));
  cols[1].sprnt("%s", service_name.c_str());
  cols[2].sprnt("%s", table_name.c_str());
  CASSERT(qnumber(header_s) == 3);
}

bool show_nvram(json_list_t nvram, qstring title) {
  bool ok;
  // open the window
  nvram_chooser_t *ch = new nvram_chooser_t(title.c_str(), ok, nvram);
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

bool show_vulns(json_list_t vulns, qstring title) {
  bool ok;
  // open the window
  vulns_chooser_t *ch = new vulns_chooser_t(title.c_str(), ok, vulns);
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

bool show_guids(json_list_t guids, qstring title) {
  bool ok;
  // open the window
  guids_chooser_t *ch = new guids_chooser_t(title.c_str(), ok, guids);
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

bool show_protocols(json_list_t protocols, qstring title) {
  bool ok;
  // open the window
  m_protocols_chooser_t *ch =
      new m_protocols_chooser_t(title.c_str(), ok, protocols, "prot_name");
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

bool show_ppis(json_list_t ppis, qstring title) {
  bool ok;
  // open the window
  m_protocols_chooser_t *ch =
      new m_protocols_chooser_t(title.c_str(), ok, ppis, "ppi_name");
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

bool show_services(json_list_t services, qstring title) {
  bool ok;
  // open the window
  services_chooser_t *ch = new services_chooser_t(title.c_str(), ok, services);
  // default cursor position is 0 (first row)
  ch->choose();
  return true;
}

//-------------------------------------------------------------------------
// action handler for protocols dependencies
struct protocols_deps_handler_t : public action_handler_t {
  virtual int idaapi activate(action_activation_ctx_t *ctx) {
    auto n = ctx->chooser_selection.at(0);
    json info = g_deps.m_protocols_chooser[n];

    if (info.is_null()) {
      return -1; // protocol not found
    }

    // get dependencies for protocol
    std::string guid = info["guid"];
    json d = g_deps.m_protocols_by_guids[guid];

    // print dependencies for current protocol in output window
    std::string s = d.dump(2);
    efi_utils::log("dependencies for protocol with GUID %s: %s\n", guid.c_str(),
                   s.c_str());

    return 0;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
    return AST_ENABLE_ALWAYS;
  }
};

static protocols_deps_handler_t protocols_deps_ah;
action_desc_t protocols_deps =
    ACTION_DESC_LITERAL("efiXplorer:dependencies", "Show dependencies",
                        &protocols_deps_ah, nullptr, nullptr, -1);

void attach_action_protocols_deps() {
  // attach action in protocols chooser
  TWidget *widget = find_widget("efiXplorer: protocols");
  if (widget == nullptr) {
    efi_utils::log("can not find protocols chooser\n");
    return;
  }
  register_action(protocols_deps);
  attach_action_to_popup(widget, nullptr, protocols_deps.name);
}

//-------------------------------------------------------------------------
// action handler for showing the sequence of modules execution
struct modules_seq_handler_t : public action_handler_t {
  virtual int idaapi activate(action_activation_ctx_t *ctx) {
    try {
      g_deps.build_modules_sequence();
    } catch (std::exception &e) {
      efi_utils::log("failed to build modules sequence: %s\n", e.what());
      return -1;
    }

    std::string s = g_deps.m_modules_sequence.dump(2);
    efi_utils::log("sequence of modules execution: %s\n", s.c_str());

    return 0;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
    return AST_ENABLE_ALWAYS;
  }
};

static modules_seq_handler_t modules_seq_ah;
action_desc_t modules_seq = ACTION_DESC_LITERAL(
    "efiXplorer:modules", "Show the sequence of modules execution",
    &modules_seq_ah, nullptr, nullptr, -1);

void attach_action_modules_seq() {
  // attach action in protocols chooser
  TWidget *widget = find_widget("efiXplorer: protocols");
  if (widget == nullptr) {
    efi_utils::log("can not find protocols chooser\n");
    return;
  }
  register_action(modules_seq);
  attach_action_to_popup(widget, nullptr, modules_seq.name);
}

//-------------------------------------------------------------------------
// Action handler (load efiXplorer analysis report)
struct action_handler_loadreport_t : public action_handler_t {
  virtual int idaapi activate(action_activation_ctx_t *ctx) {
    std::filesystem::path summary_path;
    char *file = ask_file(false, "*.json", "Load efiXplorer analysis report");
    if (file == nullptr) {
      efi_utils::log("analysis report file is not specified\n");
      return -1;
    }
    summary_path /= file;
    efi_utils::log("loading report from %s file\n", summary_path.c_str());

    json summary;
    try {
      std::ifstream in(summary_path);
      in >> summary;
    } catch (std::exception &e) {
      efi_utils::log("report file is invalid\n");
      return -1;
    }

    // initialise vuln types list
    string_list_t vuln_types{"smm_callout", "pei_get_variable_buffer_overflow",
                             "get_variable_buffer_overflow",
                             "smm_get_variable_buffer_overflow"};

    // show all choosers with data from report
    qstring title;

    try {
      auto protocols = summary["all_protocols"];
      if (!protocols.is_null()) { // show protocols
        title = "efiXplorer: protocols";
        show_protocols(protocols, title);
      }
      auto ppis = summary["all_ppis"];
      if (!ppis.is_null()) { // show PPIs
        title = "efiXplorer: PPIs";
        show_protocols(ppis, title);
      }
      auto services = summary["all_services"];
      if (!services.is_null()) { // show services
        title = "efiXplorer: services";
        show_services(services, title);
      }
      auto guids = summary["all_guids"];
      if (!guids.is_null()) { // show GUIDs
        title = "efiXplorer: GUIDs";
        show_guids(guids, title);
      }
      auto nvram = summary["m_nvram_variables"];
      if (!nvram.is_null()) { // show NVRAM
        title = "efiXplorer: NVRAM";
        show_nvram(nvram, title);
      }
      auto vulns = summary["vulns"];
      if (!vulns.is_null()) { // show vulns
        json_list_t vulns_res;
        for (auto vuln_type : vuln_types) {
          auto vuln_addr = vulns[vuln_type];
          if (vuln_addr.is_null()) {
            continue;
          }
          for (auto addr : vuln_addr) {
            json vuln;
            vuln["type"] = vuln_type;
            vuln["address"] = addr;
            vulns_res.push_back(vuln);
          }
        }
        if (vulns_res.size()) {
          title = "efiXplorer: vulns";
          show_vulns(vulns_res, title);
        }
      }

      g_deps.get_protocols_chooser(protocols);
      g_deps.get_protocols_by_guids(protocols);

      // save all protocols information to build dependencies
      attach_action_protocols_deps();
      attach_action_modules_seq();
    } catch (std::exception &e) {
      efi_utils::log("report file is invalid\n");
      return -1;
    }

    return 0;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
    return AST_ENABLE_ALWAYS;
  }
};

static action_handler_loadreport_t load_report_handler;

//-------------------------------------------------------------------------
// action to load efiXplorer analysis report
action_desc_t action_load_report =
    ACTION_DESC_LITERAL("efiXplorer:report", "efiXplorer analysis report...",
                        &load_report_handler, nullptr, nullptr, -1);
