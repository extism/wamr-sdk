# WAMR SDK

A lightweight [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) backend for Extism

Supports a limited set of features compared to [extism/extism](https://github.com/extism/extism):

- Linking multiple Wasm modules
- Host functions
- Memory limits

## Building

Requires:
- CMake
- C compiler

```bash
mkdir build
cd build
cmake ..
make
```

or:

```bash
make
```

## Getting started

- `extism_runtime_init` should always be called before creating any plugins, and there
  is only a single global runtime that host functions can be loaded into
- The plugins listed in `ExtismManifest` that depend on other Wasm modules must have all 
  dependencies listed first in the manifest with module names specified.

### Creating and calling a plugin

```c
#include <stdio.h>
#include <stdlib.h>
#include <extism-wamr.h>

// Read a file from disk - an implementation of `read_file` can be found 
// in `bin/extism-wamr.c`
uint8_t *read_file(const char *, size_t *);

// Return the input as-is
uint64_t host_reflect(ExtismExecEnv *env, uint64_t x) { return x; }

// Run an Extism plugin and print the output
ExtismStatus run_wasm(const char *wasm_file, const char *func_name, const char *input, size_t input_len){
  char errbuf[1024];
  size_t datalen = 0, len = 0;
  uint8_t *data = read_file(wasm_file, &datalen);
  if (data == NULL) {
    return ExtismStatusErr;
  }

  // Initialize the runtime, this must be done before anything else 
  extism_runtime_init();

  // Specify the modules to be loaded, setting `name` to `NULL` marks a module
  // at the main module
  ExtismWasm wasm = {
      .data = data,
      .length = datalen,
      .name = NULL,
  };
  ExtismManifest manifest;
  extism_manifest_init(&manifest, &wasm, 1, NULL, 0, NULL);

  // Define a host function
  extism_host_function("extism:host/user", "host_reflect", "(I)I", host_reflect,
                       NULL);

  // Create the plugin instance
  ExtismPlugin *plugin = extism_plugin_new(&manifest, errbuf, 1024);
  if (plugin == NULL) {
    fputs("ERROR: ", stderr);
    fputs(errbuf, stderr);
    fputs("\n", stderr);
    free(data);
    extism_runtime_cleanup();
    return ExtismStatusErr;
  }

  // Call `func_name`
  if ((status = extism_plugin_call(plugin, func_name, (const void *)input,
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

  // Cleanup
  extism_plugin_free(plugin);
  extism_runtime_cleanup();
  free(data);
  return ExtismStatusOk;
}

```

