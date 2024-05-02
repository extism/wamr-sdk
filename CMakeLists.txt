cmake_minimum_required (VERSION 3.14)
project(extism-wamr)

enable_testing()

set(CMAKE_C_STANDARD 11)

# Configure WAMR

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set (WAMR_BUILD_PLATFORM "linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set (WAMR_BUILD_PLATFORM "darwin")
endif()
set (WAMR_BUILD_TARGET "X86_64")
set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_FAST_INTERP 1)
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_LIBC_WASI 1)
set (WAMR_BUILD_TAIL_CALL 1)
set (WAMR_BUILD_MULTI_MODULE 1)
set (WAMPR_BUILD_GC 1)
# set (WAMR_BUILD_SIMD 1)
# set (WAMR_BUILD_AOT 1)
set (WAMR_ROOT_DIR wasm-micro-runtime)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

# extism-wamr
 
add_library (extism-wamr STATIC kernel.c extism.c)
target_link_libraries (extism-wamr vmlib m)

# Install

set_target_properties(extism-wamr PROPERTIES PUBLIC_HEADER "extism-wamr.h")

install(TARGETS extism-wamr
  LIBRARY DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)

add_executable(test-example example/example.c)
target_link_libraries(test-example extism-wamr)
add_test(
    NAME test-example 
    COMMAND test-example
)


