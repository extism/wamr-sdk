#ifndef _EXTISM_WAMR_H
#define _EXTISM_WAMR_H

#include <stddef.h>
#include <stdint.h>

// Status type
typedef enum {
  ExtismStatusOk,
  ExtismStatusErr,
  ExtismStatusErrNoWasm,
  ExtismStatusErrUndefined,
  ExtismStatusCallFailed,
} ExtismStatus;

// Determines the maximum number of modules that can be specified in a manifest
// at once
#define EXTISM_MAX_LINKED_MODULES 8

// `ExtismWasm` is used to specify Wasm data when creating plugins
typedef struct {
  // Module name
  char *name;
  // Wasm module
  uint8_t *data;
  // Data length
  size_t length;
} ExtismWasm;

typedef struct {
  // Wasm modules
  ExtismWasm wasm[EXTISM_MAX_LINKED_MODULES];
  // Number of modules
  size_t wasm_count;
} ExtismManifest;

struct ExtismKernel;
typedef struct ExtismPlugin ExtismPlugin;

struct ExtismExecEnv;
typedef struct ExtismExecEnv ExtismExecEnv;

// Initiailze runtime, this must be called before anything else
void extism_runtime_init();

// Cleanup runtime initialized with `extism_runtime_init`
void extism_runtime_cleanup();

// Create a new plugin from a manifest, the `errbuf` is used to access any error
// messages returned by WAMR
ExtismPlugin *extism_plugin_new(const ExtismManifest *manifest, char *errbuf,
                                size_t errlen);

// Free a plugin
void extism_plugin_free(ExtismPlugin *plugin);

// Call a function with the given input
ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                void *input, size_t input_length);

uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length);
const char *extism_plugin_error(ExtismPlugin *plugin, size_t *length);

// Register a host function with the runtime
void extism_host_function(const char *module, const char *name,
                          const char *signature, void *func, void *user_data);

// Get user-data from host functions
void *extism_host_function_data(ExtismExecEnv *env);

void extism_plugin_use_kernel(ExtismPlugin *plugin);
void extism_plugin_use_plugin(ExtismPlugin *plugin);

#endif // _EXTISM_WAMR_H
