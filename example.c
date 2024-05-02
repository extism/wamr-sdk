#include "extism-wamr.h"
#include <wasm_export.h>

#include <stdio.h>

#include "plugin.h"

int main(void) {
  extism_runtime_init();

  ExtismManifest manifest = {.wasm = {{
                                 .data = ___wasm,
                                 .data_length = ___wasm_len,
                                 .name = NULL,
                             }},
                             .wasm_count = 1};

  ExtismPlugin plugin;
  extism_plugin_init(&plugin, &manifest);

  puts("CALLING");
  extism_plugin_call(&plugin, "count_vowels", "abc", 3);

  // wasm_val_t results[] = {{.kind = WASM_I64, .of = {.i64 = 0}}};
  // wasm_val_t params[] = {{.kind = WASM_I64, .of = {.i64 = 999}}};
  // wasm_runtime_call_wasm_a(plugin.kernel->exec, plugin.kernel->alloc, 1,
  //                          results, 1, params);
  // params[0].of.i64 = results[0].of.i64;
  // wasm_runtime_call_wasm_a(plugin.kernel->exec, plugin.kernel->length, 1,
  //                          results, 1, params);

  size_t len = 0;
  extism_plugin_output(&plugin, &len);
  printf("%ld\n", len);

  extism_plugin_cleanup(&plugin);
  extism_runtime_cleanup();
  return 0;
}
