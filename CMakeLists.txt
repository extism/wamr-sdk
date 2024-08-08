cmake_minimum_required (VERSION 3.14)

if (NOT DEFINED CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

if(ESP_PLATFORM)
  include (${COMPONENT_DIR}/build-scripts/esp-idf/extism-wamr/CMakeLists.txt)
  return()
endif()


project(extism_wamr)
enable_testing()
project(extism_wamr VERSION 0.1)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
               "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h")

# Configure WAMR

if(NOT DEFINED WAMR_BUILD_TARGET)
  if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm64")
    set (WAMR_BUILD_TARGET "AARCH64")
  else()
    string(TOUPPER ${CMAKE_SYSTEM_PROCESSOR} WAMR_BUILD_TARGET)
  endif()
endif()

if(NOT DEFINED WAMR_BUILD_PLATFORM)
  string(TOLOWER ${CMAKE_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
elseif(${WAMR_BUILD_PLATFORM} MATCHES "esp-idf")
  string(TOLOWER ${CMAKE_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
  set(ESP_PLATFORM 1)
endif()

set (CMAKE_C_FLAGS_RELEASE "-O3")
set (CMAKE_C_FLAGS_DEBUG "-g")

if (NOT DEFINED WAMR_BUILD_INTERP)
set (WAMR_BUILD_INTERP 1)
endif()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
set (WAMR_BUILD_FAST_INTERP 1)
endif()

if (NOT DEFINED WAMR_BUILD_FAST_JIT)
set (WAMR_BUILD_FAST_JIT 0)
endif()

if (NOT DEFINED WAMR_BUILD_JIT)
set (WAMR_BUILD_JIT 0)
endif()


if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
set (WAMR_BUILD_LIBC_BUILTIN 1)
endif()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
set (WAMR_BUILD_LIBC_WASI 1)
endif()

if (NOT DEFINED WAMR_BUILD_TAIL_CALL)
set (WAMR_BUILD_TAIL_CALL 1)
endif()

if (NOT DEFINED WAMR_BUILD_GC)
set (WAMR_BUILD_GC 1)
endif()

if (NOT DEFINED WAMR_BUILD_REFERENCE_TYPES)
set (WAMR_BUILD_REFERENCE_TYPES 1)
endif()

# Multi-module is required
set (WAMR_BUILD_MULTI_MODULE 1)

set (WAMR_ROOT_DIR wasm-micro-runtime)


include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# extism_wamr

add_library (extism_wamr)
target_sources(extism_wamr PUBLIC 
  src/util.c
  src/kernel.c
  src/symbols.c
  src/extism.c
  src/libextism.c
  src/uuid4.c
  ${WAMR_RUNTIME_LIB_SOURCE}
)
target_link_libraries (extism_wamr PUBLIC m)
if(MSVC)
  target_compile_options(extism_wamr PRIVATE /W4 /WX)
else()
  target_compile_options(extism_wamr PRIVATE -Wall -Wextra)
endif()

# Install

set_target_properties(extism_wamr PROPERTIES OUTPUT_NAME "extism-wamr")
set_target_properties(extism_wamr PROPERTIES PUBLIC_HEADER "src/extism-wamr.h")

install(TARGETS extism_wamr
  LIBRARY DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)

add_executable(extism_wamr-exe bin/extism-wamr.c)
set_target_properties(extism_wamr-exe PROPERTIES OUTPUT_NAME "extism-wamr")
target_link_libraries(extism_wamr-exe extism_wamr)
add_test(
    NAME extism_wamr-exe 
    COMMAND extism_wamr-exe ${PROJECT_SOURCE_DIR}/wasm/count-vowels.wasm count_vowels aaa
)
install(TARGETS extism_wamr-exe
  RUNTIME DESTINATION "bin"
)



