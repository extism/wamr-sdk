#include "../extism-wamr.h"

#include <stdio.h>

#include "plugin.h"

int main(void) {
  size_t len = 0;
  char errbuf[1024];

  // Initialize the runtime, this must be done before a plugin can be created
  extism_runtime_init();

  // Specify the modules to be loaded, setting `name` to `NULL` marks a module
  // at the main module
  ExtismManifest manifest = {.wasm = {{
                                 .data = ___wasm,
                                 .length = ___wasm_len,
                                 .name = NULL,
                             }},
                             .wasm_count = 1};

  // Create the plugin
  ExtismPlugin *plugin = extism_plugin_new(&manifest, errbuf, 1024);
  if (plugin == NULL) {
    fputs("ERROR: ", stderr);
    fputs(errbuf, stderr);
    fputs("\n", stderr);
    return 1;
  }

  // Call `count_vowels` function
  ExtismStatus status;
  if ((status = extism_plugin_call(plugin, "count_vowels", "abc", 3)) !=
      ExtismStatusOk) {
    // Print error if it fails
    const char *s = extism_plugin_error(plugin, &len);
    fprintf(stderr, "ERROR(%d): ", status);
    fwrite(s, len, 1, stderr);
    fputc('\n', stderr);
  } else {
    // Otherwise print the output
    uint8_t *output = extism_plugin_output(plugin, &len);
    printf("Output length=%ld\n", len);
    fwrite(output, len, 1, stdout);
    fputc('\n', stdout);
  }

  // Cleanup
  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  return 0;
}
