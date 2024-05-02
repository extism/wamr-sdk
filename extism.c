#include "internal.h"

#include <stdio.h>

void use_kernel(ExtismPlugin *plugin, wasm_exec_env_t env) {
  if (env == NULL) {
    env = plugin->exec;
  }
  wasm_runtime_set_module_inst(env, plugin->kernel.instance);
}

void use_plugin(ExtismPlugin *plugin, wasm_exec_env_t env) {
  if (env == NULL) {
    env = plugin->exec;
  }
  wasm_runtime_set_module_inst(env, plugin->instance);
}

void extism_runtime_init() { wasm_runtime_init(); }

static void extism_kernel_cleanup(struct ExtismKernel *kernel) {
  if (kernel->instance) {
    wasm_runtime_deinstantiate(kernel->instance);
  }
}

void extism_runtime_cleanup() { wasm_runtime_destroy(); }

static ExtismStatus extism_plugin_init(ExtismPlugin *plugin,
                                       const ExtismManifest *manifest,
                                       char *errmsg, size_t errlen) {
  plugin->module_count = manifest->wasm_count;
  plugin->exec = NULL;
  plugin->instance = NULL;
  plugin->main = NULL;

  // Initialize kernel
  init_kernel(&plugin->kernel);

#define FN(name, args)                                                         \
  {.symbol = #name,                                                            \
   .signature = args,                                                          \
   .func_ptr = k_##name,                                                       \
   .attachment = plugin}
  NativeSymbol kernel[] = {
      FN(alloc, "(I)I"),        FN(free, "(I)"),
      FN(output_set, "(II)"),   FN(output_length, "()I"),
      FN(output_offset, "()I"), FN(input_set, "(I, I)"),
      FN(input_length, "()I"),  FN(input_offset, "()I"),
      FN(load_u8, "(I)i"),      FN(input_load_u8, "(I)i"),
      FN(load_u64, "(I)I"),     FN(input_load_u64, "(I)I"),
      FN(store_u8, "(Ii)"),     FN(store_u64, "(II)"),
      FN(error_set, "(I)"),     FN(error_get, "()I"),
      FN(length, "(I)I"),       FN(reset, "()"),
  };
#undef FN
  size_t nkernel = sizeof(kernel) / sizeof(NativeSymbol);

  wasm_runtime_register_natives("extism:host/env", kernel, nkernel);

  for (size_t i = 0; i < plugin->module_count; i++) {
    if (manifest->wasm[i].name != NULL) {
      LoadArgs args;
      args.name = manifest->wasm[i].name;
      plugin->modules[i] = wasm_runtime_load_ex(manifest->wasm[i].data,
                                                manifest->wasm[i].data_length,
                                                &args, errmsg, errlen);
    } else {
      plugin->modules[i] =
          wasm_runtime_load(manifest->wasm[i].data,
                            manifest->wasm[i].data_length, errmsg, errlen);
      plugin->main = plugin->modules[i];
    }
  }

  if (plugin->main == NULL) {
    return ExtismStatusErrNoWasm;
  }

  // TODO: make memory settings configurable
  plugin->instance =
      wasm_runtime_instantiate(plugin->main, 4096, 65536 * 10, errmsg, errlen);
  plugin->exec = wasm_exec_env_create(plugin->instance, 4096);

  return ExtismStatusOk;
}

static void extism_plugin_cleanup(ExtismPlugin *plugin) {
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
}

ExtismPlugin *extism_plugin_new(const ExtismManifest *manifest, char *errmsg,
                                size_t errlen) {
  ExtismPlugin *plugin = os_malloc(sizeof(ExtismPlugin));
  if (extism_plugin_init(plugin, manifest, errmsg, errlen) != ExtismStatusOk) {
    return NULL;
  }
  return plugin;
}

void extism_plugin_free(ExtismPlugin *plugin) {
  extism_plugin_cleanup(plugin);
  os_free(plugin);
}

static uint64_t kernel_alloc(ExtismPlugin *plugin, const void *s, size_t size) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, NULL);
  assert(wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.alloc, 1,
                                  results, 1, params));
  uint64_t offset = results[0].of.i64;

  for (size_t i = 0; i < size; i++) {
    wasm_val_t params[] = {
        {.kind = WASM_I64, .of = {.i64 = offset + i}},
        {.kind = WASM_I32, .of = {.i32 = ((uint8_t *)s)[i]}}};
    if (!wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.store_u8, 0,
                                  NULL, 2, params)) {
      return ExtismStatusCallFailed;
    }
  }
  use_plugin(plugin, NULL);
  return offset;
}

static void kernel_set_input(ExtismPlugin *plugin, uint64_t offs,
                             size_t length) {
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  use_kernel(plugin, NULL);
  wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.input_set, 0, NULL, 2,
                           params);
  use_plugin(plugin, NULL);
}

static uint64_t kernel_output_offset(ExtismPlugin *plugin) {
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, NULL);
  wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.output_offset, 1,
                           results, 0, NULL);
  use_plugin(plugin, NULL);
  return results[0].of.i64;
}

static uint64_t kernel_output_length(ExtismPlugin *plugin) {
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, NULL);
  wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.output_length, 1,
                           results, 0, NULL);
  use_plugin(plugin, NULL);
  return results[0].of.i64;
}

static void kernel_reset(ExtismPlugin *plugin) {
  use_kernel(plugin, NULL);
  wasm_runtime_call_wasm_a(plugin->exec, plugin->kernel.reset, 0, NULL, 0,
                           NULL);

  use_plugin(plugin, NULL);
}

ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                void *input, size_t input_length) {

  wasm_function_inst_t f =
      wasm_runtime_lookup_function(plugin->instance, func_name);
  if (f == NULL) {
    return ExtismStatusErrUndefined;
  }

  kernel_reset(plugin);
  uint64_t input_offs = kernel_alloc(plugin, input, input_length);
  kernel_set_input(plugin, input_offs, input_length);

  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};

  puts("AAA");
  uint32_t result_count = wasm_func_get_result_count(f, plugin->instance);
  use_plugin(plugin, NULL);
  if (!wasm_runtime_call_wasm_a(plugin->exec, f, result_count, results, 0,
                                NULL)) {
    return ExtismStatusCallFailed;
  }
  puts("BBB");

  return ExtismStatusOk;
}

uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length) {
  if (length) {
    *length = kernel_output_length(plugin);
  }
  uint64_t offs = kernel_output_offset(plugin);
  printf("OFFS=%ld\n", offs);
  return wasm_runtime_addr_app_to_native(plugin->kernel.instance, offs);
}
