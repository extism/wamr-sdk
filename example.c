#include "extism-wamr.h"

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

  ExtismPlugin *plugin = extism_plugin_new(&manifest, NULL, 0);

  puts("CALLING");
  extism_plugin_call(plugin, "count_vowels", "abc", 3);

  size_t len = 0;
  uint8_t *output = extism_plugin_output(plugin, &len);
  printf("%ld\n", len);
  fwrite(output, len, 1, stdout);
  fputc('\n', stdout);

  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  return 0;
}
