#include "extism-wamr.h"
#include <wasm_export.h>

#include <stdio.h>

int main(void) {
  extism_global_init();

  ExtismManifest manifest = {.wasm = {NULL}, .wasm_count = 0};

  ExtismPlugin plugin;
  extism_plugin_init(&plugin, &manifest);

  wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = 999}}};
  wasm_runtime_call_wasm_a(plugin.kernel.exec, plugin.kernel.alloc, 1, results,
                           1, params);
  params[0].of.i64 = results[0].of.i64;
  wasm_runtime_call_wasm_a(plugin.kernel.exec, plugin.kernel.length, 1, results,
                           1, params);

  printf("%ld\n", results[0].of.i64);

  extism_plugin_cleanup(&plugin);
  extism_global_cleanup();
  return 0;
}
