# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020-2026 Binarly

cmake_minimum_required(VERSION 3.10)

project(efiXloader)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(APPLE)
  # to build Mach-O universal binaries with 2 architectures
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch x86_64 -arch arm64")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -arch x86_64 -arch arm64")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wno-nullability-completeness -Wno-varargs")
endif()

if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
  add_compile_options(-fPIC -O3 -flto)
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

set(THIRD_PARTY_DIR "${PROJECT_SOURCE_DIR}/../third_party")
set(UEFITOOL_DIR "${THIRD_PARTY_DIR}/uefitool")

include_directories(${THIRD_PARTY_DIR})

file(
  GLOB
  uefitool_src
  "${UEFITOOL_DIR}/common/*.c"
  "${UEFITOOL_DIR}/common/*.cpp"
  "${UEFITOOL_DIR}/common/*.h"
  "${UEFITOOL_DIR}/common/brotli/common/*.c"
  "${UEFITOOL_DIR}/common/brotli/dec/*.c"
  "${UEFITOOL_DIR}/common/bstrlib/*.c"
  "${UEFITOOL_DIR}/common/bstrlib/*.cpp"
  "${UEFITOOL_DIR}/common/bstrlib/*.h"
  "${UEFITOOL_DIR}/common/digest/sha1.c"
  "${UEFITOOL_DIR}/common/digest/sha256.c"
  "${UEFITOOL_DIR}/common/digest/sha512.c"
  "${UEFITOOL_DIR}/common/digest/sm3.c"
  "${UEFITOOL_DIR}/common/generated/*.cpp"
  "${UEFITOOL_DIR}/common/generated/*.h"
  "${UEFITOOL_DIR}/common/kaitai/*.cpp"
  "${UEFITOOL_DIR}/common/kaitai/*.h"
  "${UEFITOOL_DIR}/common/LZMA/*.c"
  "${UEFITOOL_DIR}/common/LZMA/*.cpp"
  "${UEFITOOL_DIR}/common/LZMA/*.h"
  "${UEFITOOL_DIR}/common/LZMA/SDK/C/*.c"
  "${UEFITOOL_DIR}/common/LZMA/SDK/C/*.cpp"
  "${UEFITOOL_DIR}/common/LZMA/SDK/C/*.h"
  "${UEFITOOL_DIR}/common/Tiano/*.c"
  "${UEFITOOL_DIR}/common/Tiano/*.cpp"
  "${UEFITOOL_DIR}/common/Tiano/*.h"
  "${UEFITOOL_DIR}/common/zlib/*.c"
  "${UEFITOOL_DIR}/common/zlib/*.cpp"
  "${UEFITOOL_DIR}/common/zlib/*.h"
  "${UEFITOOL_DIR}/ffsdumper.cpp"
  "${UEFITOOL_DIR}/ffsdumper.h"
  "${UEFITOOL_DIR}/uefidump.cpp"
  "${UEFITOOL_DIR}/uefidump.h"
  "${UEFITOOL_DIR}/version.h")

# efiXloader sources
file(GLOB efiXloader_src "*.cc" "*.h")

add_ida_loader(efiXloader NOEA32 ${PROJECT_SOURCE_DIR}/efi_loader.cc)

set_ida_target_properties(efiXloader PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(efiXloader PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiXloader_lib NOEA32 ${efiXloader_src} ${uefitool_src}
                uefitool.cc uefitool.h)
ida_target_link_libraries(efiXloader efiXloader_lib)
