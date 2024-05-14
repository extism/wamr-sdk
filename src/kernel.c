#include "internal.h"

#include "extism-runtime.h"
#include "lib_export.h"

#include <stdio.h>
#include <wasm_export.h>

#if defined(__arm__) || defined(__aarch64__)
static uint64_t read_u64(const void *ptr) {
  union {
    uint64_t n;
    char data[8];
  } tmp;
  const char *cp = (const char *)ptr;
  tmp.data[0] = *cp++;
  tmp.data[1] = *cp++;
  tmp.data[2] = *cp++;
  tmp.data[3] = *cp++;
  tmp.data[4] = *cp++;
  tmp.data[5] = *cp++;
  tmp.data[6] = *cp++;
  tmp.data[7] = *cp;
  return tmp.n;
}
static void write_u64(void *ptr, uint64_t x) {
  union {
    uint64_t n;
    char data[8];
  } tmp;
  tmp.n = x;
  char *cp = (char *)ptr;
  *cp++ = tmp.data[0];
  *cp++ = tmp.data[1];
  *cp++ = tmp.data[2];
  *cp++ = tmp.data[3];
  *cp++ = tmp.data[4];
  *cp++ = tmp.data[5];
  *cp++ = tmp.data[6];
  *cp++ = tmp.data[7];
}
#else
static uint64_t read_u64(const void *x) { return *(uint64_t *)x; }
static void write_u64(void *ptr, uint64_t x) { *(uint64_t *)ptr = x; }
#endif

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

#define KERNEL_INIT(p, k)                                                      \
  ExtismPlugin *p = wasm_runtime_get_function_attachment(env);                 \
  struct ExtismKernel *k = &p->kernel;

uint64_t k_alloc(wasm_exec_env_t env, uint64_t size) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = size}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->alloc, 1, results, 1, params));
  return results[0].of.i64;
}

void k_reset(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->reset, 0, NULL, 0, NULL));
}

void k_free(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->free, 0, NULL, 1, params));
}

uint64_t k_length(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->length, 1, results, 1, params));
  return results[0].of.i64;
}

uint64_t k_length_unsafe(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->length_unsafe, 1, results,
                                       1, params));
  return results[0].of.i64;
}

void k_output_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->output_set, 0, NULL, 2, params));
}

uint64_t k_output_length(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->output_length, 1, results,
                                       0, NULL));
  return results[0].of.i64;
}

uint64_t k_output_offset(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(wasm_runtime_call_wasm_a(env, kernel->output_offset, 1, results,
                                       0, NULL));
  return results[0].of.i64;
}

void k_input_set(wasm_exec_env_t env, uint64_t offs, uint64_t length) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}},
                         {.kind = WASM_I64, .of = {.i64 = length}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_set, 0, NULL, 2, params));
}

uint64_t k_input_length(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_length, 1, results, 0, NULL));
  return results[0].of.i64;
}

uint64_t k_input_offset(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->input_offset, 1, results, 0, NULL));
  return results[0].of.i64;
}

uint32_t k_load_u8(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, offs);
  return ptr[0];
}

uint32_t k_input_load_u8(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  uint64_t x = k_input_offset(env);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, x + offs);
  return ptr[0];
}

uint64_t k_load_u64(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, offs);
  return read_u64(ptr);
}

uint64_t k_input_load_u64(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  uint64_t input_offs = k_input_offset(env);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, input_offs + offs);
  return read_u64(ptr);
}

void k_store_u8(wasm_exec_env_t env, uint64_t offs, uint32_t ch) {
  KERNEL_INIT(plugin, kernel);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, offs);
  ptr[0] = (uint8_t)ch;
}

void k_store_u64(wasm_exec_env_t env, uint64_t offs, uint64_t v) {
  KERNEL_INIT(plugin, kernel);
  (void)kernel;
  uint8_t *ptr = extism_plugin_memory(plugin, offs);
  write_u64(ptr, v);
}

uint64_t k_error_get(wasm_exec_env_t env) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->error_get, 1, results, 0, NULL));
  return results[0].of.i64;
}

void k_error_set(wasm_exec_env_t env, uint64_t offs) {
  KERNEL_INIT(plugin, kernel);
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = offs}}};
  KERNEL_CALL(
      wasm_runtime_call_wasm_a(env, kernel->error_set, 0, NULL, 1, params));
}

uint64_t k_config_get(wasm_exec_env_t env, uint64_t k) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  uint64_t len = k_length(env, k);
  if (len == 0) {
    return 0;
  }

  void *ptr;
  WITH_KERNEL(plugin, {
    ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, k);
  });

  for (size_t i = 0; i < plugin->manifest->config_count; i++) {
    if (strlen(plugin->manifest->config[i].key) == len &&
        strncmp(plugin->manifest->config[i].key, ptr, len) == 0) {
      return plugin_alloc(plugin, plugin->manifest->config[i].value,
                          strlen(plugin->manifest->config[i].value));
    }
  }

  return 0;
}
uint64_t k_var_get(wasm_exec_env_t env, uint64_t k) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  uint64_t len = k_length(env, k);
  if (len == 0) {
    return 0;
  }

  void *ptr;
  WITH_KERNEL(plugin, {
    ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, k);
  });

  for (size_t i = 0; i < plugin->var_count; i++) {
    if (strlen(plugin->vars[i].key) == len &&
        strncmp(plugin->vars[i].key, ptr, len) == 0) {
      return plugin_alloc(plugin, plugin->vars[i].value,
                          plugin->vars[i].length);
    }
  }

  return 0;
}
void k_var_set(wasm_exec_env_t env, uint64_t k, uint64_t v) {
  ExtismPlugin *plugin = wasm_runtime_get_function_attachment(env);
  uint64_t klen = k_length(env, k);
  if (klen == 0) {
    return;
  }

  uint64_t vlen = k_length(env, v);
  if (vlen == 0) {
    return;
  }

  void *ptr, *vptr;
  WITH_KERNEL(plugin, {
    ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, k);
    vptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, v);
  });

  for (size_t i = 0; i < plugin->var_count; i++) {
    if (strlen(plugin->vars[i].key) == klen &&
        strncmp(plugin->vars[i].key, ptr, klen) == 0) {
      if (plugin->vars[i].length != vlen) {
        os_free(plugin->vars[i].value);
        plugin->vars[i].value = os_malloc(vlen);
      }
      memcpy(plugin->vars[i].value, vptr, vlen);
      plugin->vars[i].length = vlen;
      return;
    }
  }

  if (plugin->var_count < EXTISM_MAX_CONFIG) {
    plugin->vars[plugin->var_count].key = os_malloc(klen + 1);
    memcpy(plugin->vars[plugin->var_count].key, ptr, klen);
    plugin->vars[plugin->var_count].key[klen] = '\0';
    plugin->vars[plugin->var_count].value = os_malloc(vlen);
    memcpy(plugin->vars[plugin->var_count].value, vptr, vlen);
    plugin->vars[plugin->var_count].length = vlen;
    plugin->var_count += 1;
  } else {
    wasm_runtime_set_exception(plugin->instance, "Variable store is full");
    wasm_runtime_terminate(plugin->instance);
  }
}
uint64_t k_http_request(wasm_exec_env_t env, uint64_t req, uint64_t body) {
  (void)req;
  (void)body;
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
    if (len == 0)                                                              \
      return;                                                                  \
    void *ptr;                                                                 \
    WITH_KERNEL(plugin, {                                                      \
      ptr = wasm_runtime_addr_app_to_native(plugin->kernel.instance, msg);     \
    });                                                                        \
    fputs(prefix ": ", stderr);                                                \
    fwrite(ptr, len, 1, stderr);                                               \
    fputs("\n", stderr);                                                       \
  }

LOG_FN(info, "INFO")
LOG_FN(warn, "WARN")
LOG_FN(debug, "DEBUG")
LOG_FN(error, "ERROR")

static wasm_module_t load_extism_kernel(char errormsg[128]) {
  wasm_module_t module = wasm_runtime_load(
      extism_runtime_wasm, extism_runtime_wasm_len, errormsg, 128);
  if (module == NULL) {
    // TODO: log error
    puts(errormsg);
    return NULL;
  }

  return module;
}

void init_kernel(struct ExtismKernel *kernel,
                 const ExtismMemoryConfig *memory) {
  assert(kernel);
  char errormsg[128];
  kernel->module = load_extism_kernel(errormsg);
  assert(kernel->module);

  kernel->instance =
      wasm_runtime_instantiate(kernel->module, memory->stack_size / 2,
                               memory->stack_size / 2, errormsg, 128);
  if (kernel->instance == NULL) {
    puts(errormsg);
    exit(1);
  }
  assert(kernel->instance);

  // Kernel functions
#define KERNEL_FN(x)                                                           \
  kernel->x = wasm_runtime_lookup_function(kernel->instance, #x);              \
  assert(kernel->x);

  KERNEL_FN(alloc);
  KERNEL_FN(free);
  KERNEL_FN(length);
  KERNEL_FN(length_unsafe);
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
#undef KERNEL_FN
  // End kernel functions
}
