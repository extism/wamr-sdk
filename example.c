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

  size_t len = 0;
  uint8_t *output = extism_plugin_output(&plugin, &len);
  printf("%ld\n", len);
  fwrite(output, len, 1, stdout);
  fputc('\n', stdout);

  extism_plugin_cleanup(&plugin);
  extism_runtime_cleanup();
  return 0;
}
