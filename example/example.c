#include "../extism-wamr.h"

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

  if (argc < 4) {
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
  ExtismManifest manifest;
  ExtismWasm wasm = {
      .data = data,
      .length = datalen,
      .name = NULL,
  };
  extism_manifest_init(&manifest, &wasm, 1, NULL, 0);

  extism_host_function("extism:host/user", "host_reflect", "(I)I", host_reflect,
                       NULL);

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

  for (size_t i = 0; i < 10; i++) {
    if ((status = extism_plugin_call(plugin, argv[2], argv[3],
                                     strlen(argv[3]))) != ExtismStatusOk) {
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
  }

  // Cleanup
  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  return 0;
}
