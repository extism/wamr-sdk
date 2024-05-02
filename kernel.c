#include "internal.h"

#include "extism-runtime.h"
#include "lib_export.h"

#include <assert.h>
#include <stdio.h>

void use_kernel(ExtismPlugin *plugin, wasm_exec_env_t env);
void use_plugin(ExtismPlugin *plugin, wasm_exec_env_t env);

uint64_t k_alloc(wasm_exec_env_t env, uint64_t size) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->alloc, 1, results, 1, params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

void k_reset(wasm_exec_env_t env, uint64_t size) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->reset, 0, NULL, 0, NULL));
  use_plugin(plugin, env);
}

void k_free(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->free, 0, NULL, 1, params));
  use_plugin(plugin, env);
}

uint64_t k_length(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->length, 1, results, 1, params));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

void k_output_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_set, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

uint64_t k_output_length(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results, 0,
                                  NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

uint64_t k_output_offset(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};

  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results, 0,
                                  NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

void k_input_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->input_set, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

uint64_t k_input_length(wasm_exec_env_t env) {
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

uint64_t k_input_offset(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(
      wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0, NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

uint32_t k_load_u8(wasm_exec_env_t env, uint64_t offs) {
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

uint32_t k_input_load_u8(wasm_exec_env_t env, uint64_t offs) {
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

uint64_t k_load_u64(wasm_exec_env_t env, uint64_t offs) {
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

uint32_t k_input_load_u64(wasm_exec_env_t env, uint64_t offs) {
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

void k_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I32, .of = {.i32 = ch}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->store_u8, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

void k_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = v}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->store_u64, 0, NULL, 2, params));
  use_plugin(plugin, env);
}

uint64_t k_error_get(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->error_get, 1, results, 0, NULL));
  use_plugin(plugin, env);
  return results[0].of.i64;
}

void k_error_set(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  use_kernel(plugin, env);
  assert(wasm_runtime_call_wasm_a(env, kernel->error_get, 0, NULL, 1, params));
  use_plugin(plugin, env);
}

static wasm_module_t load_extism_kernel() {
  char errormsg[2048];
  wasm_module_t module = wasm_runtime_load(
      extism_runtime_wasm, extism_runtime_wasm_len, errormsg, 2048);
  if (module == NULL) {
    // TODO: log error
    puts(errormsg);
    return NULL;
  }

  return module;
}

void init_kernel(struct ExtismKernel *kernel) {
  kernel->module = load_extism_kernel();
  // TODO: base the memory kernel size off of the total memory size once that
  // becomes configurable
  kernel->instance =
      wasm_runtime_instantiate(kernel->module, 4096, 65536 * 10, NULL, 0);

  // Kernel functions
#define KERNEL_FN(x)                                                           \
  kernel->x = wasm_runtime_lookup_function(kernel->instance, #x);              \
  assert(kernel->x);

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

void link_kernel(ExtismPlugin *plugin) {
  // Link kernel functions into environment
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
}
