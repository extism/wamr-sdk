#pragma once
#include "extism-wamr.h"

#include "../common/wasm_memory.h"
#include "wasm_export.h"
#include "wasm_runtime.h"
#include <lib_export.h>

#include <assert.h>

struct ExtismKernel {
  wasm_module_t module;
  wasm_module_inst_t instance;
  wasm_function_inst_t alloc;
  wasm_function_inst_t free;
  wasm_function_inst_t length;
  wasm_function_inst_t reset;
  wasm_function_inst_t input_offset;
  wasm_function_inst_t input_length;
  wasm_function_inst_t input_set;
  wasm_function_inst_t output_offset;
  wasm_function_inst_t output_length;
  wasm_function_inst_t output_set;
  wasm_function_inst_t error_set;
  wasm_function_inst_t error_get;
  wasm_function_inst_t load_u8;
  wasm_function_inst_t input_load_u8;
  wasm_function_inst_t store_u8;
  wasm_function_inst_t load_u64;
  wasm_function_inst_t input_load_u64;
  wasm_function_inst_t store_u64;
};

typedef struct ExtismPlugin {
  struct ExtismKernel kernel;
  wasm_module_t modules[EXTISM_MAX_LINKED_MODULES];
  wasm_module_t main;
  size_t module_count;
  wasm_exec_env_t exec;
  wasm_module_inst_t instance;
} ExtismPlugin;

void init_kernel(struct ExtismKernel *kernel);
void link_kernel(ExtismPlugin *plugin);
uint64_t k_alloc(wasm_exec_env_t env, uint64_t size);
void k_reset(wasm_exec_env_t env, uint64_t size);
void k_free(wasm_exec_env_t env, uint64_t offs);
uint64_t k_length(wasm_exec_env_t env, uint64_t offs);
void k_output_set(wasm_exec_env_t env, uint64_t offs, uint64_t length);
uint64_t k_output_length(wasm_exec_env_t env);
uint64_t k_output_offset(wasm_exec_env_t env);
void k_input_set(wasm_exec_env_t env, uint64_t offs, uint64_t length);
uint64_t k_input_length(wasm_exec_env_t env);
uint64_t k_input_offset(wasm_exec_env_t env);
uint32_t k_load_u8(wasm_exec_env_t env, uint64_t offs);
uint32_t k_input_load_u8(wasm_exec_env_t env, uint64_t offs);
uint64_t k_load_u64(wasm_exec_env_t env, uint64_t offs);
uint32_t k_input_load_u64(wasm_exec_env_t env, uint64_t offs);
void k_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch);
void k_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v);
uint64_t k_error_get(wasm_exec_env_t env);
void k_error_set(wasm_exec_env_t env, uint64_t offs);
