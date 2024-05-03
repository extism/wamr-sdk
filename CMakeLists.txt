cmake_minimum_required (VERSION 3.14)
project(extism-wamr)

enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

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
set (WAMR_BUILD_SIMD 1)
# set (WAMR_BUILD_AOT 1)
set (WAMR_ROOT_DIR wasm-micro-runtime)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

# extism-wamr
 
add_library (extism-wamr STATIC src/symbols.c src/kernel.c src/extism.c)
target_link_libraries (extism-wamr vmlib m)
if(MSVC)
  target_compile_options(extism-wamr PRIVATE /W4 /WX)
else()
  target_compile_options(extism-wamr PRIVATE -Wall -Wextra -Werror)
endif()

# Install

set_target_properties(extism-wamr PROPERTIES PUBLIC_HEADER "src/extism-wamr.h")

install(TARGETS extism-wamr
  LIBRARY DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)

add_executable(extism-wamr-exe bin/extism-wamr.c)
set_target_properties(extism-wamr-exe PROPERTIES OUTPUT_NAME "extism-wamr")
target_link_libraries(extism-wamr-exe extism-wamr)
add_test(
    NAME extism-wamr-exe 
    COMMAND extism-wamr-exe ${PROJECT_SOURCE_DIR}/wasm/count-vowels.wasm count_vowels aaa
)
install(TARGETS extism-wamr-exe
  RUNTIME DESTINATION "bin"
)



