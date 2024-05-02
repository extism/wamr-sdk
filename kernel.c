#include "internal.h"

#include "extism-runtime.h"
#include "lib_export.h"

#include <stdio.h>
#include <wasm_export.h>

// KERNEL_CALL depends on `plugin` and `kernel` variables
#define KERNEL_CALL(x)                                                         \
  WITH_KERNEL(plugin, {                                                        \
    if (!x) {                                                                  \
      const char *s = wasm_runtime_get_exception(kernel->instance);            \
      plugin_set_error(plugin, s);                                             \
      extism_plugin_use_plugin(plugin);                                        \
      wasm_runtime_set_exception(plugin->instance, s);                         \
      wasm_runtime_terminate(plugin->instance);                                \
    }                                                                          \
  })

uint64_t k_alloc(wasm_exec_env_t env, uint64_t size) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->alloc, 1, results, 1, params));
  return results[0].of.i64;
}

void k_reset(wasm_exec_env_t env, uint64_t size) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->reset, 0, NULL, 0, NULL));
}

void k_free(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->free, 0, NULL, 1, params));
}

uint64_t k_length(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->length, 1, results, 1, params));
  return results[0].of.i64;
}

void k_output_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->output_set, 0, NULL, 2, params));
}

uint64_t k_output_length(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results,
                                       0, NULL));
  return results[0].of.i64;
}

uint64_t k_output_offset(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results,
                                       0, NULL));
  return results[0].of.i64;
}

void k_input_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_set, 0, NULL, 2, params));
}

uint64_t k_input_length(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0, NULL));
  return results[0].of.i64;
}

uint64_t k_input_offset(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0, NULL));
  return results[0].of.i64;
}

uint32_t k_load_u8(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->load_u8, 1, results, 1, params));
  return results[0].of.i32;
}

uint32_t k_input_load_u8(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I32, .of = {.i32 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->input_load_u8, 1, results,
                                       1, params));
  return results[0].of.i32;
}

uint64_t k_load_u64(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->load_u64, 1, results, 1, params));
  return results[0].of.i64;
}

uint32_t k_input_load_u64(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->input_load_u64, 1, results,
                                       1, params));
  return results[0].of.i64;
}

void k_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I32, .of = {.i32 = ch}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->store_u8, 0, NULL, 2, params));
}

void k_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = v}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->store_u64, 0, NULL, 2, params));
}

uint64_t k_error_get(wasm_exec_env_t env) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->error_get, 1, results, 0, NULL));
  return results[0].of.i64;
}

void k_error_set(wasm_exec_env_t env, uint64_t offs) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  struct ExtismKernel *kernel = &plugin->kernel;
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->error_get, 0, NULL, 1, params));
}

uint64_t k_config_get(wasm_exec_env_t env, uint64_t k) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  wasm_runtime_set_exception(plugin->instance,
                             "extism:host/env::config_get not implemented");
  wasm_runtime_terminate(plugin->instance);
  return 0;
}
uint64_t k_var_get(wasm_exec_env_t env, uint64_t k) {

  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  wasm_runtime_set_exception(plugin->instance,
                             "extism:host/env::var_get not implemented");
  wasm_runtime_terminate(plugin->instance);
  return 0;
}
void k_var_set(wasm_exec_env_t env, uint64_t k, uint64_t v) {

  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  wasm_runtime_set_exception(plugin->instance,
                             "extism:host/env::var_set not implemented");
  wasm_runtime_terminate(plugin->instance);
}
uint64_t k_http_request(wasm_exec_env_t env, uint64_t req, uint64_t body) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  wasm_runtime_set_exception(plugin->instance,
                             "extism:host/env::http_request not implemented");
  wasm_runtime_terminate(plugin->instance);
  return 0;
}
uint32_t k_http_status_code(wasm_exec_env_t env) {

  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  wasm_runtime_set_exception(
      plugin->instance, "extism:host/env::http_status_code not implemented");
  wasm_runtime_terminate(plugin->instance);
  return 0;
}

#define LOG_FN(name, prefix)                                                   \
  void k_log_##name(wasm_exec_env_t env, uint64_t msg) {                       \
    ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);          \
    uint64_t len = k_length(env, msg);                                         \
    void *ptr;                                                                 \
    WITH_KERNEL(plugin, {                                                      \
      ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, msg);     \
    });                                                                        \
    fputs(prefix ": ", stderr);                                                \
    fwrite(ptr, len, 1, stderr);                                               \
    fputs("\n", stderr);                                                       \
  }

LOG_FN(info, "INFO");
LOG_FN(warn, "WARN");
LOG_FN(debug, "DEBUG");
LOG_FN(error, "ERROR");

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

void *extism_host_function_data(ExtismExecEnv *env) {
  return wasm_runtime_get_function_attachment((wasm_exec_env_t)env);
}
