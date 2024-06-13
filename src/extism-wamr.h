#ifndef _EXTISM_WAMR_H
#define _EXTISM_WAMR_H

#include <stddef.h>
#include <stdint.h>

// Extism plugin
typedef struct ExtismPlugin ExtismPlugin;

// Extism execution environment, this should be used as the first argument when
// defining a host function
typedef struct ExtismExecEnv ExtismExecEnv;

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
#define EXTISM_MAX_LINKED_MODULES 4

// Maximum number of config values
#define EXTISM_MAX_CONFIG 16

// `ExtismWasm` is used to specify Wasm data when creating plugins
typedef struct {
  // Module name
  char *name;
  // Wasm module
  uint8_t *data;
  // Data length
  size_t length;
} ExtismWasm;

// `ExtismConfig` is used  to store a key/value pair that can be accessed using
// `extism_config_get` from inside a plugin
typedef struct {
  const char *key;
  const char *value;
} ExtismConfig;

// `ExtismVar` is used to store a key/value pair that can be accessed using
// `extism_var_get` and updated using `extism_var_set` from inside a plugin
typedef struct {
  char *key;
  char *value;
  size_t length;
} ExtismVar;

// `ExtismMemoryConfig` can be used to specify the amount of memory a plugin
// should be given access to
typedef struct {
  uint32_t stack_size;
  size_t heap_size;
} ExtismMemoryConfig;

// `ExtismManifest` is used configure which Wasm module should be loaded
typedef struct {
  // Wasm modules
  ExtismWasm wasm[EXTISM_MAX_LINKED_MODULES];
  ExtismConfig config[EXTISM_MAX_CONFIG];
  // Number of modules, an config items used
  size_t wasm_count, config_count;
  // Memory config
  ExtismMemoryConfig memory;
} ExtismManifest;

// Initializes an `ExtismManifest` value
void extism_manifest_init(ExtismManifest *manifest, const ExtismWasm *wasm,
                          size_t nwasm, const ExtismConfig *config,
                          size_t nconfig, const ExtismMemoryConfig *memory);

// Initiailze runtime, this must be called before anything else and only one
// runtime can be initialized at a time
void extism_runtime_init();

// Cleanup runtime initialized with `extism_runtime_init`, this cleans up
// associated memory and unloads any host functions
void extism_runtime_cleanup();

// Create a new plugin from a manifest, the `errbuf` is used to access any error
// messages returned by WAMR
ExtismPlugin *extism_plugin_new(const ExtismManifest *manifest, char *errbuf,
                                size_t errlen);

// Free a plugin
void extism_plugin_free(ExtismPlugin *plugin);

// Call a function with the given input
ExtismStatus extism_plugin_call(ExtismPlugin *plugin, const char *func_name,
                                const void *input, size_t input_length);

// Similar to `extism_plugin_call` but allows passing WASI arguments/stdio
ExtismStatus extism_plugin_call_wasi(ExtismPlugin *plugin,
                                     const char *func_name, const void *input,
                                     size_t input_length, char **argv, int argc,
                                     int stdinfd, int stdoutfd, int stderrfd);

// Call a function with the given input and host context
ExtismStatus extism_plugin_call_with_host_context(ExtismPlugin *plugin,
                                                  const char *func_name,
                                                  const void *input,
                                                  size_t input_length,
                                                  void *ctx);

// Get the output of a plugin
uint8_t *extism_plugin_output(ExtismPlugin *plugin, size_t *length);

// Get the error result of a plugin
const char *extism_plugin_error(ExtismPlugin *plugin, size_t *length);

// Register a host function with the runtime
void extism_host_function(const char *module, const char *name,
                          const char *signature, void *func, void *user_data);

// A pointer to the start of an allocation in Extism memory
typedef uint64_t ExtismHandle;

// Get host pointer given an Extism memory offset
void *extism_plugin_memory(ExtismPlugin *plugin, ExtismHandle offs);

// Allocate Extism memory
ExtismHandle extism_plugin_memory_alloc(ExtismPlugin *plugin, void *data,
                                        size_t size);

// Get length of allocation in Extism memory
uint64_t extism_plugin_memory_length(ExtismPlugin *plugin, ExtismHandle offs);

// Allocate Extism memory
void extism_plugin_memory_free(ExtismPlugin *plugin, ExtismHandle offs);

// Get user-data from inside host functions
void *extism_host_function_data(ExtismExecEnv *env);

// Get host context from inside a host function
void *extism_host_context(ExtismExecEnv *env);

// These functions are used to switch context between the kernel and plugin
// modules in host functions, these shouldn't be needed in most cases.
void extism_plugin_use_kernel(ExtismPlugin *);
void extism_plugin_use_plugin(ExtismPlugin *);

#endif // _EXTISM_WAMR_H
