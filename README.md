# extism-wamr

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
