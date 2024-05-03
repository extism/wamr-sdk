#include "extism-wamr.h"
#include "internal.h"

#include <string.h>
#include <wasm_export.h>

static struct Symbols SYMBOLS = {.capacity = 0, .length = 0};

static ExtismStatus extism_plugin_init(ExtismPlugin *plugin,
                                       const ExtismManifest *manifest,
                                       char *errmsg, size_t errlen) {
  plugin->module_count = manifest->wasm_count;
  plugin->exec = NULL;
  plugin->instance = NULL;
  plugin->main = NULL;
  plugin->manifest = manifest;
  plugin->var_count = 0;

  // Initialize kernel
  init_kernel(&plugin->kernel, &manifest->memory);

#define FN(name, args)                                                         \
  {.symbol = #name,                                                            \
   .signature = args,                                                          \
   .func_ptr = k_##name,                                                       \
   .attachment = plugin}
  NativeSymbol kernel[] = {
      FN(alloc, "(I)I"),
      FN(free, "(I)"),
      FN(output_set, "(II)"),
      FN(output_length, "()I"),
      FN(output_offset, "()I"),
      FN(input_set, "(I, I)"),
      FN(input_length, "()I"),
      FN(input_offset, "()I"),
      FN(load_u8, "(I)i"),
      FN(input_load_u8, "(I)i"),
      FN(load_u64, "(I)I"),
      FN(input_load_u64, "(I)I"),
      FN(store_u8, "(Ii)"),
      FN(store_u64, "(II)"),
      FN(error_set, "(I)"),
      FN(error_get, "()I"),
      FN(length, "(I)I"),
      FN(reset, "()"),
      FN(log_info, "(I)"),
      FN(log_debug, "(I)"),
      FN(log_warn, "(I)"),
      FN(log_error, "(I)"),
      // TODO
      FN(config_get, "(I)I"),
      FN(var_get, "(I)I"),
      FN(var_set, "(II)"),
      FN(http_request, "(II)I"),
      FN(http_status_code, "()i"),
  };
#undef FN
  size_t nkernel = sizeof(kernel) / sizeof(NativeSymbol);

  wasm_runtime_register_natives(
      "extism:host/env", add_symbols(&SYMBOLS, kernel, nkernel), nkernel);

  for (size_t i = 0; i < plugin->module_count; i++) {
    bool name_is_null = manifest->wasm[i].name == NULL;
    bool name_is_main = (!name_is_null && strlen(manifest->wasm[i].name) == 4 &&
                         strncmp(manifest->wasm[i].name, "main", 4) == 0);
    if (!name_is_null && !name_is_main) {
      LoadArgs args;
      args.name = manifest->wasm[i].name;
      plugin->modules[i] =
          wasm_runtime_load_ex(manifest->wasm[i].data, manifest->wasm[i].length,
                               &args, errmsg, errlen);
    } else {
      plugin->modules[i] = wasm_runtime_load(
          manifest->wasm[i].data, manifest->wasm[i].length, errmsg, errlen);
      plugin->main = plugin->modules[i];
    }
  }

  if (plugin->main == NULL) {
    return ExtismStatusErrNoWasm;
  }

  plugin->instance = wasm_runtime_instantiate(
      plugin->main, (manifest->memory.stack_size) / 4 * 3,
      (manifest->memory.heap_size / 4) * 3, errmsg, errlen);

  plugin->exec =
      wasm_exec_env_create(plugin->instance, manifest->memory.stack_size);

  // wasm_function_inst_t initialize =
  //     wasm_runtime_lookup_function(plugin->instance, "_initialize");
  // if (initialize != NULL) {
  //   wasm_val_t params[] = {{.kind = WASM_I32, .of = {.i32 = 0}},
  //                          {.kind = WASM_I32, .of = {.i32 = 0}}};
  //   wasm_runtime_call_wasm_a(plugin->exec, initialize, 0, params, 0, params);
  // }

  // wasm_function_inst_t hs_init =
  //     wasm_runtime_lookup_function(plugin->instance, "hs_init");
  // if (hs_init != NULL) {
  //   wasm_val_t params[] = {{.kind = WASM_I32, .of = {.i32 = 0}},
  //                          {.kind = WASM_I32, .of = {.i32 = 0}}};
  //   wasm_runtime_call_wasm_a(plugin->exec, hs_init, 0, NULL, 2, params);
  // }

  // TODO: initialize WASI?

  return ExtismStatusOk;
}

ExtismPlugin *extism_plugin_new(const ExtismManifest *manifest, char *errmsg,
                                size_t errlen) {
  ExtismPlugin *plugin = os_malloc(sizeof(ExtismPlugin));
  if (extism_plugin_init(plugin, manifest, errmsg, errlen) != ExtismStatusOk) {
    extism_plugin_free(plugin);
    return NULL;
  }
  return plugin;
}

static void cleanup_kernel(struct ExtismKernel *kernel) {
  if (kernel->instance) {
    wasm_runtime_deinstantiate(kernel->instance);
  }
  if (kernel->module) {
    wasm_runtime_unload(kernel->module);
  }
}

static void extism_plugin_cleanup(ExtismPlugin *plugin) {
  if (plugin->exec) {
    wasm_exec_env_destroy(plugin->exec);
  }

  if (plugin->instance) {
    wasm_runtime_deinstantiate(plugin->instance);
  }

  for (size_t i = 0; i < plugin->module_count; i++) {
    wasm_runtime_unload(plugin->modules[i]);
  }

  cleanup_kernel(&plugin->kernel);
}

void extism_plugin_free(ExtismPlugin *plugin) {
  extism_plugin_cleanup(plugin);
  os_free(plugin);
}

uint64_t plugin_alloc(ExtismPlugin *plugin, const void *s, size_t size) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  extism_plugin_use_kernel(plugin);
  assert(wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.alloc, 1,
                                  results, 1, params));
  uint64_t offset = results[0].of.i64;
  if (offset == 0) {
    return 0;
  }

  if (s) {
    const size_t chunk_count = size >> 3;
    const uint64_t *i64_buffer = s;
    for (size_t chunk_idx = 0; chunk_idx < chunk_count; chunk_idx++) {
      wasm_val_t u64_params[] = {
          {.kind = WASM_I64, .of = {.i64 = offset + (chunk_idx << 3)}},
          {.kind = WASM_I64, .of = {.i64 = i64_buffer[chunk_idx]}}};
      assert(wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.store_u64, 0,
                                      NULL, 2, u64_params));
    }

    size_t remainder_offset = chunk_count << 3;
    const size_t remainder_end = remainder_offset + (size & 7);
    for (const uint8_t *u8_buffer = s; remainder_offset < remainder_end;
         remainder_offset++) {
      wasm_val_t u8_params[] = {
          {.kind = WASM_I64, .of = {.i64 = offset + remainder_offset}},
          {.kind = WASM_I32, .of = {.i32 = u8_buffer[remainder_offset]}}};
      assert(wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.store_u8, 0,
                                      NULL, 2, u8_params));
    }
  }

  extism_plugin_use_plugin(plugin);
  return offset;
}

static void plugin_set_input(ExtismPlugin *plugin, uint64_t offs,
                             size_t length) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.input_set,
                                       0, NULL, 2, params));
}

static uint64_t plugin_output_offset(ExtismPlugin *plugin) {
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  WITH_KERNEL(plugin, wasm_runtime_call_wasm_a(plugin->exec,
                                               plugin->kernel.output_offset, 1,
                                               results, 0, NULL));
  return results[0].of.i64;
}

static uint64_t plugin_output_length(ExtismPlugin *plugin) {
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  WITH_KERNEL(plugin, wasm_runtime_call_wasm_a(plugin->exec,
                                               plugin->kernel.output_length, 1,
                                               results, 0, NULL));
  return results[0].of.i64;
}

static uint64_t plugin_length(ExtismPlugin *plugin, uint64_t offs) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.length, 1,
                                       results, 1, params));
  return results[0].of.i64;
}

static uint64_t plugin_error(ExtismPlugin *plugin) {
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.error_get,
                                       1, results, 0, NULL));
  return results[0].of.i64;
}

void plugin_set_error(ExtismPlugin *plugin, const char *s) {
  uint64_t offs = plugin_alloc(plugin, s, strlen(s));
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.error_set,
                                       0, NULL, 1, params));
}

static void plugin_reset(ExtismPlugin *plugin) {
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.reset, 0,
                                       NULL, 0, NULL));
}

ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                void *input, size_t input_length) {

  wasm_function_inst_t f =
      wasm_runtime_lookup_function(plugin->instance, func_name);
  if (f == NULL) {
    plugin_set_error(plugin, "Function is undefined");
    return ExtismStatusErrUndefined;
  }

  plugin_reset(plugin);
  uint64_t input_offs = plugin_alloc(plugin, input, input_length);
  plugin_set_input(plugin, input_offs, input_length);

  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};

  uint32_t result_count = wasm_func_get_result_count(f, plugin->instance);
  extism_plugin_use_plugin(plugin);
  if (!wasm_runtime_call_wasm_a(plugin->exec, f, result_count, results, 0,
                                NULL)) {
    plugin_set_error(plugin, wasm_runtime_get_exception(plugin->instance));
    return ExtismStatusCallFailed;
  }

  return ExtismStatusOk;
}

ExtismStatus extism_plugin_exec(ExtismPlugin *plugin, const char *func_name,
                                void *input, size_t input_length, char **argv,
                                int argc) {
  wasm_runtime_set_wasi_args(plugin->main, NULL, 0, NULL, 0, NULL, 0, argv,
                             argc);
  return extism_plugin_call(plugin, func_name, input, input_length);
}

uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length) {
  if (length) {
    *length = plugin_output_length(plugin);
  }
  uint64_t offs = plugin_output_offset(plugin);
  return wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
}

const char *extism_plugin_error(ExtismPlugin *plugin, size_t *length) {
  uint64_t offs = plugin_error(plugin);
  if (offs == 0) {
    return NULL;
  }
  size_t errlen = plugin_length(plugin, offs);
  if (length) {
    *length = errlen;
  }
  return wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
}

void extism_host_function(const char *module, const char *name,
                          const char *signature, void *func, void *user_data) {
  NativeSymbol f;
  f.symbol = name;
  f.attachment = user_data;
  f.func_ptr = func;
  f.signature = signature;
  wasm_runtime_register_natives(module, add_symbols(&SYMBOLS, &f, 1), 1);
}

// Get host pointer
void *extism_plugin_memory(ExtismPlugin *plugin, uint64_t offs) {
  void *ptr = NULL;
  WITH_KERNEL(plugin, {
    ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
  });
  return ptr;
}

// Allocate Extism memory
uint64_t extism_plugin_memory_alloc(ExtismPlugin *plugin, void *data,
                                    size_t size) {
  return plugin_alloc(plugin, data, size);
}

// Get length of allocation in Extism memory
uint64_t extism_plugin_memory_length(ExtismPlugin *plugin, uint64_t offs) {
  return plugin_length(plugin, offs);
}

// Allocate Extism memory
void extism_plugin_memory_free(ExtismPlugin *plugin, uint64_t offs) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.length, 0,
                                       NULL, 1, params));
}

void extism_manifest_init(ExtismManifest *manifest, const ExtismWasm *wasm,
                          size_t nwasm, const ExtismConfig *config,
                          size_t nconfig, const ExtismMemoryConfig *memory) {
  if (memory) {
    manifest->memory.stack_size = memory->stack_size;
    manifest->memory.heap_size = memory->heap_size;
  } else {
    manifest->memory.stack_size = 8092;
    manifest->memory.heap_size = 65536 * 10;
  }

  assert(nwasm <= EXTISM_MAX_LINKED_MODULES);
  memcpy(manifest->wasm, wasm, nwasm * sizeof(ExtismWasm));
  manifest->wasm_count = nwasm;

  assert(nconfig <= EXTISM_MAX_CONFIG);
  memcpy(manifest->config, config, nconfig * sizeof(ExtismConfig));
  manifest->config_count = nconfig;
}

void extism_plugin_use_kernel(ExtismPlugin *plugin) {
  wasm_runtime_set_module_inst(plugin->exec, plugin->kernel.instance);
}

void extism_plugin_use_plugin(ExtismPlugin *plugin) {
  wasm_runtime_set_module_inst(plugin->exec, plugin->instance);
}

void extism_runtime_init() {
  init_symbols(&SYMBOLS, 64);
  wasm_runtime_init();
}

void extism_runtime_cleanup() {
  wasm_runtime_destroy();
  reset_symbols(&SYMBOLS);
}
