#pragma once

#include "wasm_c_api.h"

#include "wasm_export.h"
#include "wasm_runtime.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
  ExtismStatusOk,
  ExtismStatusErr,
  ExtismStatusErrNoWasm,
  ExtismStatusErrUndefined,
  ExtismStatusCallFailed,
} ExtismStatus;

#define EXTISM_MAX_LINKED_MODULES 8

typedef struct {
  uint8_t *data;
  size_t data_length;
} ExtismWasm;

typedef struct {
  ExtismWasm wasm[EXTISM_MAX_LINKED_MODULES];
  size_t wasm_count;
} ExtismManifest;

struct ExtismKernel {
  wasm_module_t module;
  wasm_module_inst_t instance;
  wasm_exec_env_t exec;
  wasm_function_inst_t alloc;
  wasm_function_inst_t free;
  wasm_function_inst_t length;
};

typedef struct {
  struct ExtismKernel kernel;
  wasm_module_t modules[EXTISM_MAX_LINKED_MODULES];
  size_t module_count;
  wasm_engine_t *engine;
  wasm_store_t *store;
  wasm_exec_env_t exec;
  wasm_module_inst_t instance;
} ExtismPlugin;

void extism_global_init();
void extism_global_cleanup();

ExtismStatus extism_plugin_init(ExtismPlugin *plugin,
                                const ExtismManifest *manifest);
void extism_plugin_cleanup(ExtismPlugin *plugin);
ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                uint8_t *input, size_t input_length);
uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length);
