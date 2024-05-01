#include "extism-wamr.h"

#include "extism-runtime.h"
#include "wasm-micro-runtime/core/iwasm/common/wasm_exec_env.h"
#include <wasm_export.h>

void extism_global_init() { wasm_runtime_init(); }

void extism_global_cleanup() { wasm_runtime_destroy(); }

static wasm_module_t load_extism_kernel() {
  char errormsg[2048];
  wasm_module_t module = wasm_runtime_load(
      extism_runtime_wasm, extism_runtime_wasm_len, errormsg, 2048);
  if (module == NULL) {
    // TODO: log error
    return NULL;
  }

  return module;
}

static void init_extism_kernel(struct ExtismKernel *kernel,
                               wasm_module_t module) {
  kernel->module = module;
  kernel->instance =
      wasm_runtime_instantiate(module, 4096, 65536 * 10, NULL, 0);
  kernel->exec = wasm_exec_env_create(kernel->instance, 4096);

#define KERNEL_FN(x)                                                           \
  kernel->x = wasm_runtime_lookup_function(kernel->instance, #x);

  // Kernel functions
  KERNEL_FN(alloc);
  KERNEL_FN(free);
  KERNEL_FN(length);
  // End kernel functions

#undef KERNEL_FN
}

ExtismStatus extism_plugin_init(ExtismPlugin *plugin,
                                const ExtismManifest *manifest) {

  // Setup engine and store
  plugin->engine = wasm_engine_new();
  plugin->store = wasm_store_new(plugin->engine);

  // Initialize kernel
  wasm_module_t kernel_mod = load_extism_kernel();
  init_extism_kernel(&plugin->kernel, kernel_mod);

  // TODO: load extism modules
  plugin->module_count = manifest->wasm_count;

  for (size_t i = 0; i < plugin->module_count; i++) {
    plugin->modules[i] = wasm_runtime_load(
        manifest->wasm[i].data, manifest->wasm[i].data_length, NULL, 0);
  }

  if (plugin->module_count > 0) {
    plugin->instance = wasm_runtime_instantiate(
        plugin->modules[plugin->module_count - 1], 4096, 65536 * 10, NULL, 0);
    plugin->exec = wasm_exec_env_create(plugin->instance, 4096);
  } else {
    plugin->instance = NULL;
    plugin->exec = NULL;
    return ExtismStatusErrNoWasm;
  }

  return ExtismStatusOk;
}

static void extism_kernel_cleanup(struct ExtismKernel *kernel) {
  wasm_exec_env_destroy(kernel->exec);
  wasm_runtime_deinstantiate(kernel->instance);
  wasm_runtime_unload(kernel->module);
}

void extism_plugin_cleanup(ExtismPlugin *plugin) {
  extism_kernel_cleanup(&plugin->kernel);

  for (size_t i = 0; i < plugin->module_count; i++) {
    wasm_runtime_unload(plugin->modules[i]);
  }

  if (plugin->exec) {
    wasm_exec_env_destroy(plugin->exec);
  }

  if (plugin->instance) {
    wasm_runtime_deinstantiate(plugin->instance);
  }

  wasm_engine_delete(plugin->engine);
}

ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                uint8_t *input, size_t input_length) {

  wasm_function_inst_t f =
      wasm_runtime_lookup_function(plugin->instance, func_name);
  if (f == NULL) {
    return ExtismStatusErrUndefined;
  }

  wasm_val_t params[] = {};
  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};

  if (!wasm_runtime_call_wasm_a(plugin->exec, f, 1, results, 0, params)) {
    return ExtismStatusCallFailed;
  }

  return ExtismStatusOk;
}

uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length) {
  *length = 0;
  return NULL;
}
