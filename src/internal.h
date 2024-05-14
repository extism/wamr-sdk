#pragma once
#include "extism-wamr.h"

#include "wasm_exec_env.h"
#include "wasm_native.h"

#include <assert.h>

struct ExtismKernel {
  wasm_module_t module;
  wasm_module_inst_t instance;
  wasm_function_inst_t alloc;
  wasm_function_inst_t free;
  wasm_function_inst_t length;
  wasm_function_inst_t length_unsafe;
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
  ExtismVar vars[EXTISM_MAX_CONFIG];
  size_t var_count;
  const ExtismManifest *manifest;
  struct ExtismKernel kernel;
  wasm_module_t modules[EXTISM_MAX_LINKED_MODULES];
  wasm_module_t main;
  size_t module_count;
  wasm_exec_env_t exec;
  wasm_module_inst_t instance;
} ExtismPlugin;

void init_kernel(struct ExtismKernel *kernel, const ExtismMemoryConfig *memory);
void link_kernel(ExtismPlugin *plugin);
uint64_t k_alloc(wasm_exec_env_t env, uint64_t size);
void k_reset(wasm_exec_env_t env);
void k_free(wasm_exec_env_t env, uint64_t offs);
uint64_t k_length(wasm_exec_env_t env, uint64_t offs);
uint64_t k_length_unsafe(wasm_exec_env_t env, uint64_t offs);
void k_output_set(wasm_exec_env_t env, uint64_t offs, uint64_t length);
uint64_t k_output_length(wasm_exec_env_t env);
uint64_t k_output_offset(wasm_exec_env_t env);
void k_input_set(wasm_exec_env_t env, uint64_t offs, uint64_t length);
uint64_t k_input_length(wasm_exec_env_t env);
uint64_t k_input_offset(wasm_exec_env_t env);
uint32_t k_load_u8(wasm_exec_env_t env, uint64_t offs);
uint32_t k_input_load_u8(wasm_exec_env_t env, uint64_t offs);
uint64_t k_load_u64(wasm_exec_env_t env, uint64_t offs);
uint64_t k_input_load_u64(wasm_exec_env_t env, uint64_t offs);
void k_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch);
void k_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v);
uint64_t k_error_get(wasm_exec_env_t env);
void k_error_set(wasm_exec_env_t env, uint64_t offs);
void k_log_warn(wasm_exec_env_t env, uint64_t msg);
void k_log_info(wasm_exec_env_t env, uint64_t msg);
void k_log_debug(wasm_exec_env_t env, uint64_t msg);
void k_log_error(wasm_exec_env_t env, uint64_t msg);
uint64_t k_config_get(wasm_exec_env_t env, uint64_t k);
uint64_t k_var_get(wasm_exec_env_t env, uint64_t k);
void k_var_set(wasm_exec_env_t env, uint64_t k, uint64_t v);
uint64_t k_http_request(wasm_exec_env_t env, uint64_t req, uint64_t body);
uint32_t k_http_status_code(wasm_exec_env_t env);

void plugin_set_error(ExtismPlugin *plugin, const char *s);
uint64_t plugin_alloc(ExtismPlugin *plugin, const void *s, size_t size);

#define WITH_KERNEL(plugin, x)                                                 \
  extism_plugin_use_kernel(plugin);                                            \
  x;                                                                           \
  extism_plugin_use_plugin(plugin);

struct Symbols {
  NativeSymbol *symbols;
  size_t length, capacity;
};

void init_symbols(struct Symbols *symbols, size_t total);
NativeSymbol *add_symbols(struct Symbols *s, const NativeSymbol *sym, size_t n);
void reset_symbols(struct Symbols *s);
