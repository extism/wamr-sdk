#include "../src/extism-wamr.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t *read_file(const char *filename, size_t *len) {

  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) {
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  size_t length = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  uint8_t *data = malloc(length);
  if (data == NULL) {
    fclose(fp);
    return NULL;
  }

  assert(fread(data, 1, length, fp) == length);
  fclose(fp);

  *len = length;
  return data;
}

uint64_t host_reflect(ExtismExecEnv *env, uint64_t x) { return x; }

int main(int argc, char *argv[]) {
  size_t len = 0, datalen = 0;
  char errbuf[1024];

  // Setup loop
  const char *env = getenv("EXTISM_WAMR_LOOP");
  int loop = atoi(env == NULL ? "1" : env);

  const char *num_pages = getenv("EXTISM_WAMR_HEAP_PAGES");
  int pages = atoi(num_pages == NULL ? "10" : num_pages);

  ExtismStatus status;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <wasm file> <function name> <input>", argv[0]);
    return 1;
  }

  uint8_t *data = read_file(argv[1], &datalen);
  if (data == NULL) {
    return 2;
  }

  // Initialize the runtime, this must be done before a plugin can be created
  extism_runtime_init();

  // Specify the modules to be loaded, setting `name` to `NULL` marks a module
  // at the main module
  ExtismWasm wasm = {
      .data = data,
      .length = datalen,
      .name = NULL,
  };
  ExtismManifest manifest;
  ExtismMemoryConfig mem;
  mem.stack_size = 8192;
  mem.heap_size = 65536 * pages;
  extism_manifest_init(&manifest, &wasm, 1, NULL, 0, &mem);

  // Host functions
  extism_host_function("extism:host/user", "host_reflect", "(I)I", host_reflect,
                       NULL);

  // Create the plugin
  ExtismPlugin *plugin = extism_plugin_new(&manifest, errbuf, 1024);
  if (plugin == NULL) {
    fputs("ERROR: ", stderr);
    fputs(errbuf, stderr);
    fputs("\n", stderr);
    free(data);
    extism_runtime_cleanup();
    return 1;
  }

  const char *input = argc > 3 ? argv[3] : "";
  size_t input_len = argc > 3 ? strlen(argv[3]) : 0;

  for (int i = 0; i < loop; i++) {
    // Call a function
    if ((status = extism_plugin_call(plugin, argv[2], (const void *)input,
                                     input_len)) != ExtismStatusOk) {
      // Print error if it fails
      const char *s = extism_plugin_error(plugin, &len);
      fprintf(stderr, "ERROR(%d): ", status);
      fwrite(s, len, 1, stderr);
      fputc('\n', stderr);
    } else {
      // Otherwise print the output
      uint8_t *output = extism_plugin_output(plugin, &len);
      if (len > 0) {
        fwrite(output, len, 1, stdout);
        fputc('\n', stdout);
      }
    }
  }

  // Cleanup
  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  free(data);
  return 0;
}
