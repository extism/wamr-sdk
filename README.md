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

or just:

```bash
make
```

## Example

See [extism-wamr.c](bin/extism-wamr.c)

## Notes

- `extism_runtime_init` should always be called before creating any plugins, and there
  is only a single global runtime that host functions can be loaded into
- The plugins listed in `ExtismManifest` that depend on other Wasm modules must have all 
  dependencies listed first in the manifest with module names specified.
