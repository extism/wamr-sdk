#include "extism-wamr.h"

#include <stdio.h>

#include "plugin.h"

int main(void) {
  size_t len = 0;
  ExtismStatus status;
  extism_runtime_init();

  ExtismManifest manifest = {.wasm = {{
                                 .data = ___wasm,
                                 .data_length = ___wasm_len,
                                 .name = NULL,
                             }},
                             .wasm_count = 1};

  puts("INIT");
  ExtismPlugin *plugin = extism_plugin_new(&manifest, NULL, 0);

  puts("CALLING");
  if ((status = extism_plugin_call(plugin, "count_vowels", "abc", 3)) !=
      ExtismStatusOk) {
    const char *s = extism_plugin_error(plugin, &len);
    fprintf(stderr, "ERROR(%d): ", status);
    fwrite(s, len, 1, stderr);
    fputc('\n', stderr);
  } else {
    uint8_t *output = extism_plugin_output(plugin, &len);
    printf("Output length=%ld\n", len);
    fwrite(output, len, 1, stdout);
    fputc('\n', stdout);
  }

  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  return 0;
}
