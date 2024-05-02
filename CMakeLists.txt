cmake_minimum_required (VERSION 3.14)

set (WAMR_BUILD_PLATFORM "linux")
set (WAMR_BUILD_TARGET "X86_64")
set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_FAST_INTERP 1)
# set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_LIBC_WASI 1)
set (WAMR_BUILD_SIMD 1)
set (WAMR_BUILD_MULTI_MODULE 1)
set (WAMR_ROOT_DIR wasm-micro-runtime)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
add_library (extism-wamr STATIC kernel.c extism.c)

target_link_libraries (extism-wamr vmlib m)

add_executable(example example.c)
target_link_libraries(example extism-wamr)

set_target_properties(extism-wamr PROPERTIES PUBLIC_HEADER "extism-wamr.h")

install(TARGETS extism-wamr
  LIBRARY DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)
