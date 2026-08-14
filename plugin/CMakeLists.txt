cmake_minimum_required(VERSION 3.10)

if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
  # to build Mach-O universal binaries with 2 architectures
  set(CMAKE_OSX_ARCHITECTURES
      "x86_64;arm64"
      CACHE STRING "" FORCE)
endif()

project(efiXplorer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wno-nullability-completeness -Wno-varargs")
endif()

if(NOT MSVC)
  set(lto_flag -flto)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(lto_flag -flto=auto)
  endif()
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations ${lto_flag}")
  add_compile_options(-fPIC -O3)
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)

find_package(IdaSdk REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(SYSTEM ${PROJECT_SOURCE_DIR}/../third_party/nlohmann_json)

# efiXplorer sources
set(efiXplorer_src
    "efi_defs.h"
    "efi_defs.cc"
    "efi_analysis.h"
    "efi_analysis_arm.cc"
    "efi_analysis_x86.cc"
    "efi_deps.cc"
    "efi_deps.h"
    "efi_global.cc"
    "efi_global.h"
    "efi_smm_utils.cc"
    "efi_smm_utils.h"
    "efi_ui.cc"
    "efi_ui.h"
    "efi_utils.cc"
    "efi_utils.h"
    "efixplorer.cc")

if(HexRaysSdk_ROOT_DIR)
  add_definitions(-DHEX_RAYS=1)
  set(HexRaysSdk_INCLUDE_DIRS ${HexRaysSdk_ROOT_DIR}/include)
  include_directories(SYSTEM ${HexRaysSdk_INCLUDE_DIRS})
  list(APPEND efiXplorer_src "efi_hexrays.cc" "efi_hexrays.h")
endif()

# remove NOEA32 to compile with SDK versions prior to idasdk90 as from IDA 90
# the EA32 is no longer required
add_ida_plugin(efiXplorer NOEA32 ${PROJECT_SOURCE_DIR}/efixplorer.cc)

set_ida_target_properties(efiXplorer PROPERTIES CXX_STANDARD 20)
ida_target_include_directories(efiXplorer SYSTEM PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(efiXplorer_lib NOEA32 ${efiXplorer_src})
ida_target_link_libraries(efiXplorer efiXplorer_lib)
