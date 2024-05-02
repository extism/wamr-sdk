#include "extism-wamr.h"

#include "wasm_runtime.h"

#include "extism-runtime.h"
#include <lib_export.h>
#include <wasm_export.h>

#include <stdio.h>

static void use_kernel(ExtismPlugin *plugin, wasm_exec_env_t env) {
  if (env == NULL) {
    env = plugin->exec;
  }
  wasm_runtime_set_module_inst(env, plugin->kernel.instance);
}

static void use_plugin(ExtismPlugin *plugin, wasm_exec_env_t env) {
  if (env == NULL) {
    env = plugin->exec;
  }
  wasm_runtime_set_module_inst(env, plugin->instance);
}

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
  // TODO: base the memory kernel size off of the total memory size once that
  // becomes configurable
  kernel->module = module;
  kernel->instance =
      wasm_runtime_instantiate(module, 4096, 65536 * 10, NULL, 0);

#define KERNEL_FN(x)                                                           \
  kernel->x = wasm_runtime_lookup_function(kernel->instance, #x);

  // Kernel functions
  KERNEL_FN(alloc);
  KERNEL_FN(free);
  KERNEL_FN(length);
  KERNEL_FN(reset);
  KERNEL_FN(input_set);
  KERNEL_FN(input_offset);
  KERNEL_FN(input_length);
  KERNEL_FN(output_offset);
  KERNEL_FN(output_length);
  KERNEL_FN(output_set);
  KERNEL_FN(error_get);
  KERNEL_FN(error_set);
  KERNEL_FN(load_u8);
  KERNEL_FN(input_load_u8);
  KERNEL_FN(store_u8);
  KERNEL_FN(load_u64);
  KERNEL_FN(input_load_u64);
  KERNEL_FN(store_u64);
  // End kernel functions

#undef KERNEL_FN
}

void extism_runtime_init() { wasm_runtime_init(); }

static void extism_kernel_cleanup(struct ExtismKernel *kernel) {
  if (kernel->instance) {
    wasm_runtime_deinstantiate(kernel->instance);
  }
}

void extism_runtime_cleanup() { wasm_runtime_destroy(); }

static uint64_t native_alloc(wasm_exec_env_t env, uint64_t size) {
  puts("FN: ALLOC");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->alloc, 1, results, 1, params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static void native_reset(wasm_exec_env_t env, uint64_t size) {
  puts("FN: RESET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->reset, 0, NULL, 0, NULL));
  use_plugin(plugin, env);
}

static void native_free(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: FREE");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->free, 0, NULL, 1, params));
  use_plugin(plugin, env);
}

static uint64_t native_length(wasm_exec_env_t env, uint64_t offs) {

  puts("FN: LENGTH");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->length, 1, results, 1, params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static void native_output_set(wasm_exec_env_t env, uint64_t offs,
                              uint64_t length) {
  puts("FN: OUTPUT_SET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_set, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

static uint64_t native_output_length(wasm_exec_env_t env) {
  puts("FN: OUTPUT_LENGTH");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results, 0,
                                  NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static uint64_t native_output_offset(wasm_exec_env_t env) {
  puts("FN: OUTPUT_OFFSET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};

  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results, 0,
                                  NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static void native_input_set(wasm_exec_env_t env, uint64_t offs,
                             uint64_t length) {
  puts("FN: INPUT_SET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->input_set, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

static uint64_t native_input_length(wasm_exec_env_t env) {
  puts("FN: INPUT_LENGTH");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  if (!wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0,
                                NULL)) {
    puts(wasm_runtime_get_exception(kernel->instance));
    return 0;
  }
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static uint64_t native_input_offset(wasm_exec_env_t env) {
  puts("FN: INPUT_OFFSET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(
      wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0, NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static uint32_t native_load_u8(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: LOAD_U8");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};
  use_kernel(plugin, env);
  if (!wasm_runtime_call_wasm_a(env, kernel->load_u8, 1, results, 1, params)) {
    puts(wasm_runtime_get_exception(kernel->instance));
    return 0;
  }
  use_plugin(plugin, env);
  return results[0].of.i32;
}

static uint32_t native_input_load_u8(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: INPUT_LOAD_U8");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};
  use_kernel(plugin, env);
  if (!wasm_runtime_call_wasm_a(env, kernel->input_load_u8, 1, results, 1,
                                params)) {
    puts(wasm_runtime_get_exception(kernel->instance));
    return 0;
  }
  use_plugin(plugin, env);
  return results[0].of.i32;
}

static uint64_t native_load_u64(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: LOAD_U64");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(
      wasm_runtime_call_wasm_a(env, kernel->load_u64, 1, results, 1, params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static uint32_t native_input_load_u64(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: INPUT_LOAD_U64");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->input_load_u64, 1, results, 1,
                                  params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static void native_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch) {
  puts("FN: STORE_U8");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I32, .of = {.i32 = ch}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->store_u8, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

static void native_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v) {
  puts("FN: STORE_U64");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = v}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->store_u64, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

static uint64_t native_error_get(wasm_exec_env_t env) {
  puts("FN: ERROR_GET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->error_get, 1, results, 0, NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

static void native_error_set(wasm_exec_env_t env, uint64_t offs) {
  puts("FN: ERROR_SET");
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->error_get, 0, NULL, 1, params));
  use_plugin(plugin, env);
}

ExtismStatus extism_plugin_init(ExtismPlugin *plugin,
                                const ExtismManifest *manifest) {
  char errmsg[1024];

  // Setup engine and store
  plugin->engine = wasm_engine_new();
  plugin->store = wasm_store_new(plugin->engine);

  plugin->module_count = manifest->wasm_count;
  plugin->exec = NULL;
  plugin->instance = NULL;
  plugin->main = NULL;

  // Initialize kernel
  wasm_module_t kernel_mod = load_extism_kernel();
  init_extism_kernel(&plugin->kernel, kernel_mod);

#define FN(name, args)                                                         \
  {.symbol = #name,                                                            \
   .signature = args,                                                          \
   .func_ptr = native_##name,                                                  \
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
      FN(length, "(I)I"),
  };
#undef FN

  size_t nkernel = 17;

  wasm_runtime_register_natives("extism:host/env", kernel, nkernel);

  for (size_t i = 0; i < plugin->module_count; i++) {
    if (i < plugin->module_count - 1) {
      LoadArgs args;
      args.name = manifest->wasm[i].name;
      plugin->modules[i] = wasm_runtime_load_ex(manifest->wasm[i].data,
                                                manifest->wasm[i].data_length,
                                                &args, errmsg, 1024);
    } else {
      plugin->modules[i] = wasm_runtime_load(
          manifest->wasm[i].data, manifest->wasm[i].data_length, errmsg, 1024);
      plugin->main = plugin->modules[i];
    }
  }

  if (plugin->main == NULL) {
    return ExtismStatusErrNoWasm;
  }

  // TODO: make memory settings configurable
  plugin->instance =
      wasm_runtime_instantiate(plugin->main, 4096, 65536 * 10, errmsg, 1024);
  plugin->exec = wasm_exec_env_create(plugin->instance, 4096);

  return ExtismStatusOk;
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
