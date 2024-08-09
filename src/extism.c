#include "extism-wamr.h"
#include "internal.h"
#include "util.h"

#include <string.h>

// SYMBOLS contains the global runtime symbols, this is reset when
// `extism_runtime_free` is called
static _Thread_local NativeSymbol *SYMBOLS = NULL;

static _Thread_local uuid4_state_t STATE = 0;

static ExtismStatus init_plugin(ExtismPlugin *plugin, ExtismManifest *manifest,
                                char *errmsg, size_t errlen) {
  plugin->exec = NULL;
  plugin->instance = NULL;
  plugin->main = NULL;
  plugin->vars = array_new(sizeof(ExtismVar), 8);
  plugin->modules =
      array_new(sizeof(wasm_module_t), ARRAY_LENGTH(manifest->wasm));
  plugin->manifest = manifest;

  uuid4_gen(&STATE, &plugin->id);

  // Initialize kernel
  init_kernel(&plugin->kernel, &manifest->memory);

#define FN(name, args)                                                         \
  {.symbol = #name,                                                            \
   .signature = args,                                                          \
   .func_ptr = k_##name,                                                       \
   .attachment = calloc(1, sizeof(struct FuncInner))}
  NativeSymbol kernel[] = {
      FN(alloc, "(I)I"),           FN(free, "(I)"),
      FN(output_set, "(II)"),      FN(output_length, "()I"),
      FN(output_offset, "()I"),    FN(input_set, "(I, I)"),
      FN(input_length, "()I"),     FN(input_offset, "()I"),
      FN(load_u8, "(I)i"),         FN(input_load_u8, "(I)i"),
      FN(load_u64, "(I)I"),        FN(input_load_u64, "(I)I"),
      FN(store_u8, "(Ii)"),        FN(store_u64, "(II)"),
      FN(error_set, "(I)"),        FN(error_get, "()I"),
      FN(length, "(I)I"),          FN(reset, "()"),
      FN(log_info, "(I)"),         FN(log_debug, "(I)"),
      FN(log_warn, "(I)"),         FN(log_error, "(I)"),
      FN(config_get, "(I)I"),      FN(var_get, "(I)I"),
      FN(var_set, "(II)"),         FN(http_request, "(II)I"),
      FN(http_status_code, "()i"), FN(length_unsafe, "(I)I")};
#undef FN
  size_t nkernel = sizeof(kernel) / sizeof(NativeSymbol);

  wasm_runtime_register_natives(
      "extism:host/env", add_symbols(&SYMBOLS, kernel, nkernel), nkernel);

  for (size_t i = 0; i < ARRAY_CAPACITY(plugin->modules); i++) {
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

  plugin->instance =
      wasm_runtime_instantiate(plugin->main, manifest->memory.stack_size / 2,
                               manifest->memory.heap_size / 2, errmsg, errlen);
  if (plugin->instance == NULL) {
    puts(errmsg);
    return ExtismStatusErr;
  }

  plugin->exec =
      wasm_exec_env_create(plugin->instance, manifest->memory.stack_size);
  if (plugin->exec == NULL) {
    wasm_runtime_deinstantiate(plugin->instance);
    plugin->instance = NULL;
    return ExtismStatusErr;
  }

  // Initialize Haskell runtime
  wasm_function_inst_t hs_init =
      wasm_runtime_lookup_function(plugin->instance, "hs_init");
  if (hs_init != NULL) {
    wasm_val_t params[] = {{.kind = WASM_I32, .of = {.i32 = 0}},
                           {.kind = WASM_I32, .of = {.i32 = 0}}};
    wasm_runtime_call_wasm_a(plugin->exec, hs_init, 0, NULL, 2, params);
  }

  return ExtismStatusOk;
}

ExtismPlugin *extism_wamr_plugin_new(ExtismManifest *manifest, char *errmsg,
                                     size_t errlen) {
  ExtismPlugin *plugin = os_malloc(sizeof(ExtismPlugin));
  if (plugin == NULL) {
    return NULL;
  }
  if (init_plugin(plugin, manifest, errmsg, errlen) != ExtismStatusOk) {
    extism_wamr_plugin_free(plugin);
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

static void cleanup_plugin(ExtismPlugin *plugin) {
  if (plugin->exec) {
    wasm_function_inst_t hs_exit =
        wasm_runtime_lookup_function(plugin->instance, "hs_exit");
    if (hs_exit != NULL) {

      wasm_runtime_call_wasm_a(plugin->exec, hs_exit, 0, NULL, 0, NULL);
    }

    wasm_exec_env_destroy(plugin->exec);
  }

  if (plugin->instance) {
    wasm_runtime_deinstantiate(plugin->instance);
  }

  for (size_t i = 0; i < ARRAY_LENGTH(plugin->modules); i++) {
    wasm_runtime_unload(plugin->modules[i]);
  }
  array_free(plugin->modules);

  for (size_t i = 0; i < ARRAY_LENGTH(plugin->vars); i++) {
    os_free(plugin->vars[i].key);
    os_free(plugin->vars[i].value);
  }
  array_free(plugin->vars);

  cleanup_kernel(&plugin->kernel);
}

void extism_wamr_plugin_free(ExtismPlugin *plugin) {
  cleanup_plugin(plugin);
  os_free(plugin);
}

uint64_t plugin_alloc(ExtismPlugin *plugin, const void *s, size_t size) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  extism_wamr_plugin_use_kernel(plugin);
  assert(wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.alloc, 1,
                                  results, 1, params));
  uint64_t offset = results[0].of.i64;
  if (offset == 0) {
    return 0;
  }

  if (s) {
    memcpy(extism_wamr_plugin_memory(plugin, offset), s, size);
  }

  extism_wamr_plugin_use_plugin(plugin);
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
  uint64_t offs = plugin_alloc(plugin, s, strlen(s) + 1);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.error_set,
                                       0, NULL, 1, params));
}

void extism_wamr_plugin_reset(ExtismPlugin *plugin) {
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.reset, 0,
                                       NULL, 0, NULL));
}

int32_t extism_wamr_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                const void *input, size_t input_length) {
  return extism_wamr_plugin_call_with_host_context(plugin, func_name, input,
                                                   input_length, NULL);
}

int32_t extism_wamr_plugin_call_with_host_context(ExtismPlugin *plugin,
                                                  const char *func_name,
                                                  const void *input,
                                                  size_t input_length,
                                                  void *ctx) {
  wasm_function_inst_t f =
      wasm_runtime_lookup_function(plugin->instance, func_name);
  if (f == NULL) {
    plugin_set_error(plugin, "Function is undefined");
    return -1;
  }

  extism_wamr_plugin_reset(plugin);
  uint64_t input_offs = plugin_alloc(plugin, input, input_length);
  plugin_set_input(plugin, input_offs, input_length);

  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};

  uint32_t result_count = wasm_func_get_result_count(f, plugin->instance);

  wasm_global_inst_t host_ctx;
  if (wasm_runtime_get_export_global_inst(plugin->kernel.instance,
                                          "extism_context", &host_ctx)) {
    host_ctx.global_data = ctx;
  }

  extism_wamr_plugin_use_plugin(plugin);
  for (size_t i = 0; i < ARRAY_LENGTH(SYMBOLS); i++) {
    ((struct FuncInner *)(SYMBOLS[i].attachment))->plugin = plugin;
  }
  if (!wasm_runtime_call_wasm_a(plugin->exec, f, result_count, results, 0,
                                NULL)) {
    plugin_set_error(plugin, wasm_runtime_get_exception(plugin->instance));
    return ExtismStatusCallFailed;
  }

  return results[0].of.i32;
}

void *extism_wamr_plugin_host_context(ExtismPlugin *plugin) {
  wasm_global_inst_t host_ctx;
  if (wasm_runtime_get_export_global_inst(plugin->kernel.instance,
                                          "extism_context", &host_ctx)) {
    return host_ctx.global_data;
  }

  return NULL;
}

int32_t extism_wamr_plugin_call_wasi(ExtismPlugin *plugin,
                                     const char *func_name, const void *input,
                                     size_t input_length, char **argv, int argc,
                                     int stdinfd, int stdoutfd, int stderrfd) {
  wasm_runtime_set_wasi_args_ex(plugin->main, NULL, 0, NULL, 0, NULL, 0, argv,
                                argc, stdinfd, stdoutfd, stderrfd);
  return extism_wamr_plugin_call(plugin, func_name, input, input_length);
}

uint8_t *extism_wamr_plugin_output(ExtismPlugin *plugin, size_t *length) {
  if (length) {
    *length = plugin_output_length(plugin);
  }
  uint64_t offs = plugin_output_offset(plugin);
  return wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
}

const char *extism_wamr_plugin_error(ExtismPlugin *plugin, size_t *length) {
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

// Adds a function to `SYMBOLS`
void extism_wamr_host_function(const char *module, const char *name,
                               const char *signature, void *func,
                               void *user_data) {
  NativeSymbol f;
  f.symbol = name;
  f.attachment = calloc(1, sizeof(struct FuncInner));
  assert(f.attachment);
  ((struct FuncInner *)f.attachment)->user = user_data;
  f.func_ptr = func;
  f.signature = signature;
  wasm_runtime_register_natives(module, add_symbols(&SYMBOLS, &f, 1), 1);
}

// Get host pointer
void *extism_wamr_plugin_memory(ExtismPlugin *plugin, uint64_t offs) {
  void *ptr = NULL;
  WITH_KERNEL(plugin, {
    ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
  });
  return ptr;
}

// Allocate Extism memory
uint64_t extism_wamr_plugin_memory_alloc(ExtismPlugin *plugin, void *data,
                                         size_t size) {
  return plugin_alloc(plugin, data, size);
}

// Get length of allocation in Extism memory
uint64_t extism_wamr_plugin_memory_length(ExtismPlugin *plugin, uint64_t offs) {
  return plugin_length(plugin, offs);
}

// Allocate Extism memory
void extism_wamr_plugin_memory_free(ExtismPlugin *plugin, uint64_t offs) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  WITH_KERNEL(plugin,
              wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.length, 0,
                                       NULL, 1, params));
}

void extism_wamr_manifest_init(ExtismManifest *manifest, const ExtismWasm *wasm,
                               size_t nwasm, const ExtismConfig *config,
                               size_t nconfig,
                               const ExtismMemoryConfig *memory) {
  if (memory) {
    manifest->memory.stack_size = memory->stack_size;
    manifest->memory.heap_size = memory->heap_size;
  } else {
    manifest->memory.stack_size = 4096 * 2;
    manifest->memory.heap_size = 65536 * 10;
  }

  manifest->wasm = array_new(sizeof(ExtismWasm), nwasm);
  assert(manifest->wasm);
  for (size_t i = 0; i < nwasm; i++) {
    manifest->wasm = array_push(manifest->wasm, &wasm[i]);
  }

  manifest->config = array_new(sizeof(ExtismConfig), nconfig);
  assert(manifest->config);
  for (size_t i = 0; i < nconfig; i++) {
    manifest->config = array_push(manifest->config, &config[i]);
  }
}

void extism_wamr_manifest_cleanup(ExtismManifest *manifest) {
  if (manifest->config) {

    for (size_t i = 0; i < ARRAY_LENGTH(manifest->config); i++) {
      if (manifest->config[i].owned) {
        os_free(manifest->config[i].key);
        os_free(manifest->config[i].value);
      }
    }
    array_free(manifest->config);
  }

  if (manifest->wasm) {
    for (size_t i = 0; i < ARRAY_LENGTH(manifest->wasm); i++) {
      if (manifest->wasm->owned) {
        extism_wamr_wasm_cleanup(&manifest->wasm[i]);
      }
    }
    array_free(manifest->wasm);
  }
}

void extism_wamr_plugin_use_kernel(ExtismPlugin *plugin) {
  wasm_runtime_set_module_inst(plugin->exec, plugin->kernel.instance);
}

void extism_wamr_plugin_use_plugin(ExtismPlugin *plugin) {
  wasm_runtime_set_module_inst(plugin->exec, plugin->instance);
}

void extism_wamr_runtime_init() {
  init_symbols(&SYMBOLS, 32);
#ifdef ESP32
  RuntimeInitArgs init;
  memset(&init, 0, sizeof(RuntimeInitArgs));
  init.mem_alloc_type = Alloc_With_Allocator;
  init.mem_alloc_option.allocator.malloc_func = (void *)os_malloc;
  init.mem_alloc_option.allocator.realloc_func = (void *)os_realloc;
  init.mem_alloc_option.allocator.free_func = (void *)os_free;
  wasm_runtime_full_init(&init);
#else
  wasm_runtime_init();
#endif
}

void extism_wamr_runtime_cleanup() {
  wasm_runtime_destroy();
  reset_symbols(&SYMBOLS);
}

void *extism_wamr_exec_env_data(ExtismExecEnv *env) {
  struct FuncInner *inner =
      wasm_runtime_get_function_attachment((wasm_exec_env_t)env);
  return inner->user;
}

ExtismPlugin *extism_wamr_exec_env_plugin(ExtismExecEnv *env) {
  struct FuncInner *inner =
      wasm_runtime_get_function_attachment((wasm_exec_env_t)env);
  return inner->plugin;
}

ExtismStatus extism_wamr_wasm_load_file(ExtismWasm *wasm, const char *filename,
                                        const char *name) {
  size_t len = 0;
  uint8_t *data = read_file(filename, &len);
  if (data == NULL) {
    return ExtismStatusErr;
  }

  wasm->owned = true;
  wasm->data = data;
  wasm->length = len;
  wasm->name =
      name == NULL ? string_copy("main", 4) : string_copy(name, strlen(name));
  return ExtismStatusOk;
}
void extism_wamr_wasm_cleanup(ExtismWasm *wasm) {
  if (wasm->data) {
    os_free(wasm->data);
  }
  if (wasm->name) {
    os_free(wasm->name);
  }
}
