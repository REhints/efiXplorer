// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "uefitool/common/LZMA/LzmaCompress.h"
#include "uefitool/common/LZMA/LzmaDecompress.h"
#include "uefitool/common/Tiano/EfiTianoCompress.h"
#include "uefitool/common/Tiano/EfiTianoDecompress.h"
#include "uefitool/common/basetypes.h"
#include "uefitool/common/ffs.h"
#include "uefitool/common/ffsparser.h"
#include "uefitool/common/ffsreport.h"
#include "uefitool/common/filesystem.h"
#include "uefitool/common/guiddatabase.h"
#include "uefitool/common/treeitem.h"
#include "uefitool/common/treemodel.h"
#include "uefitool/common/ustring.h"
#include "uefitool/version.h"

#include "nlohmann_json/json.hpp"
#include "uefitool/UEFIExtract/ffsdumper.h"
#include "uefitool/UEFIExtract/uefidump.h"

#include "../ldr/idaldr.h"

using nlohmann::json;

namespace efiloader {

class File {
public:
  void write(const qstring &dir) {
    if (module_name.empty()) {
      return;
    }
    // sanitize: extract basename to prevent path traversal
    qstring safe_name(module_name);
    const char *sep = strrchr(safe_name.c_str(), '/');
    if (!sep) {
      sep = strrchr(safe_name.c_str(), '\\');
    }
    if (sep) {
      safe_name = qstring(sep + 1);
    }
    if (safe_name.empty() || safe_name == "." || safe_name == "..") {
      return;
    }
    qstring image_path = dir + qstring("/") + safe_name;
    std::ofstream out;
    out.open(image_path.c_str(), std::ios::out | std::ios::binary);
    if (!out.is_open()) {
      msg("[efiXloader] failed to open %s for writing\n", image_path.c_str());
      return;
    }
    out.write(ubytes.constData(), ubytes.size());
    if (!out.good()) {
      msg("[efiXloader] failed to write %s\n", image_path.c_str());
      return;
    }
    out.close();
    dump_name.swap(image_path);
  }

  [[nodiscard]] bool is_ok() const {
    return !module_name.empty() && !module_guid.empty() && !module_kind.empty();
  }

  UByteArray ubytes;
  UByteArray uname;
  qstring dump_name;
  qstring module_guid;
  qstring module_kind;
  qstring module_name;
  bool is_pe = false;
  bool is_te = false;
  bool has_ui = false;
};

class Uefitool {
public:
  explicit Uefitool(bytevec_t &data) {
    UByteArray ubuffer(reinterpret_cast<const char *>(data.begin()),
                       data.size());
    FfsParser ffs(&model);
    if (ffs.parse(ubuffer)) {
      loader_failure("failed to parse data via UEFITool");
    }
    messages = ffs.getMessages();
  }

  void show_messages();
  [[nodiscard]] bool messages_occurs() const { return !messages.empty(); }
  void dump();
  void handle_raw_section(const UModelIndex &index);

  [[nodiscard]] bool is_file_index(const UModelIndex &index) const {
    return model.type(index) == Types::File;
  }

  void get_image_guid(qstring &image_guid, UModelIndex index);
  std::vector<std::string> parse_depex_section_body(const UModelIndex &index,
                                                    UString &parsed);
  std::vector<std::string> parse_apriori_raw_section(const UModelIndex &index);
  void get_deps(const UModelIndex &index, const std::string &key);
  void get_apriori(const UModelIndex &index, const std::string &key);
  void dump_jsons();
  void set_machine_type(const UByteArray &pe_body);

  json all_deps;
  json all_modules;
  std::vector<std::unique_ptr<efiloader::File>> files;

  TreeModel model;
  std::vector<std::pair<UString, UModelIndex>> messages;
  uint16_t machine_type = 0xffff;
  bool machine_type_initialised = false;

private:
  void extract_files(const UModelIndex &index);
  void process_section(const UModelIndex &index, int section_idx, File *file);

  [[nodiscard]] qstring get_kind(const UModelIndex &index) const {
    return fileTypeToUString(model.subtype(index.parent())).toLocal8Bit();
  }

  std::set<std::string> seen_guids;
  qstring output_dir;
};

} // namespace efiloader
