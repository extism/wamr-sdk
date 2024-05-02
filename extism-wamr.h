#ifndef _EXTISM_WAMR_H
#define _EXTISM_WAMR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  ExtismStatusOk,
  ExtismStatusErr,
  ExtismStatusErrNoWasm,
  ExtismStatusErrUndefined,
  ExtismStatusCallFailed,
} ExtismStatus;

#define EXTISM_MAX_LINKED_MODULES 8

typedef struct {
  char *name;
  uint8_t *data;
  size_t length;
} ExtismWasm;

typedef struct {
  ExtismWasm wasm[EXTISM_MAX_LINKED_MODULES];
  size_t wasm_count;
} ExtismManifest;

struct ExtismKernel;
typedef struct ExtismPlugin ExtismPlugin;

void extism_runtime_init();
void extism_runtime_cleanup();

ExtismPlugin *extism_plugin_new(const ExtismManifest *manifest, char *errbuf,
                                size_t errlen);
void extism_plugin_free(ExtismPlugin *plugin);
ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                void *input, size_t input_length);
void extism_host_function(const char *module, const char *name,
                          const char *signature, void *func, void *user_data);
uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length);
const char *extism_plugin_error(ExtismPlugin *plugin, size_t *length);
#endif // _EXTISM_WAMR_H
