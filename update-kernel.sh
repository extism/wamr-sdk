#!/usr/bin/env bash
curl -L -O https://github.com/extism/extism/raw/main/runtime/src/extism-runtime.wasm
xxd -i extism-runtime.wasm > src/extism-runtime.h 
