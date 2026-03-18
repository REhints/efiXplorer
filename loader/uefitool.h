// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <set>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif
#include <codecvt>
#include <filesystem>
#include <memory>
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

#include "fstream"
#include "nlohmann_json/json.hpp"
#include "uefitool/UEFIExtract/ffsdumper.h"
#include "uefitool/UEFIExtract/uefidump.h"

#include "ida_core.h"

using nlohmann::json;

enum FILE_SECTION_TYPE {
  PE_DEPENDENCY_SECTION = 0,
  PE_TE_IMAGE_SECTION = 1,
  UI_SECTION = 2,
  VERSION_SECTION = 3
};

namespace efiloader {
class File {
public:
  File() {}
  void set_data(char *data_in, uint32_t size_in) {
    module_name.qclear();
    bytes.resize(size_in);
    memcpy(&bytes[0], data_in, size_in);
  }
  void write() {
    qstring idb_path(get_path(PATH_TYPE_IDB));
    qstring images_path = idb_path + qstring(".efiloader");
#ifdef WIN32
    _mkdir(images_path.c_str());
#else
    mkdir(images_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
    if (!module_name.empty()) {
      qstring image_path =
          images_path + qstring("/") + qstring(module_name.c_str());
      std::ofstream file;
      file.open(image_path.c_str(), std::ios::out | std::ios::binary);
      file.write(ubytes.constData(), ubytes.size());
      file.close();
      dump_name.swap(image_path);
    }
  }
  bool is_ok() {
    return !module_name.empty() && !module_guid.empty() && !module_kind.empty();
  }

  UByteArray ubytes;
  UByteArray uname;
  bytevec_t bytes;
  char *data = nullptr;
  uint32_t size = 0;
  std::string name_utf8;
  std::string name_utf16;
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
    buffer = (const char *)&data[0];
    buffer_size = data.size();
    UByteArray ubuffer(buffer, buffer_size);
    FfsParser ffs(&model);
    if (ffs.parse(ubuffer)) {
      loader_failure("failed to parse data via UEFITool");
    }
    messages = ffs.getMessages();
  }
  ~Uefitool() {}
  void show_messages();
  bool messages_occurs() { return !messages.empty(); }
  void dump();
  void dump(const UModelIndex &index);
  void dump(const UModelIndex &index, int i, File *pe_file);
  void handle_raw_section(const UModelIndex &index);
  bool is_pe_index(const UModelIndex &index) {
    return model.rowCount(index) == 4;
  }
  bool is_file_index(const UModelIndex &index) {
    return model.type(index) == Types::File;
  }
  void get_unique_name(qstring &image_name);
  void get_image_guid(qstring &image_guid, UModelIndex index);
  std::vector<std::string> parse_depex_section_body(const UModelIndex &index,
                                                    UString &parsed);
  std::vector<std::string> parse_apriori_raw_section(const UModelIndex &index);
  void get_deps(UModelIndex index, std::string key);
  void get_apriori(UModelIndex index, std::string key);
  void dump_jsons();
  void set_machine_type(UByteArray pe_body);

  json all_deps;
  json all_modules;
  std::vector<std::unique_ptr<efiloader::File>> files;
  std::set<qstring> unique_names;

  TreeModel model;
  const char *buffer;
  uint32_t buffer_size;
  std::vector<std::pair<UString, UModelIndex>> messages;
  USTATUS err;
  uint16_t machine_type = 0xffff;
  bool machine_type_initialised = false;

private:
  qstring get_kind(const UModelIndex &index) {
    return fileTypeToUString(model.subtype(index.parent())).toLocal8Bit();
  }
};
} // namespace efiloader
