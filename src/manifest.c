#include "cJSON.h"
#include "extism-wamr.h"
#include "util.h"

#include <stdbool.h>

static bool parse_wasm(ExtismManifest *manifest, cJSON *wasm) {
  cJSON *path = cJSON_GetObjectItem(wasm, "path");
  if (path) {
    if (!cJSON_IsString(path)) {
      return false;
    }
    cJSON *name = cJSON_GetObjectItem(wasm, "name");

    ExtismWasm w;
    if (extism_wamr_wasm_load_file(&w, cJSON_GetStringValue(path),
                                   cJSON_GetStringValue(name)) !=
        ExtismStatusOk) {
      return false;
    }

    manifest->wasm = array_push(manifest->wasm, &w);
    return true;
  }
  return false;
}

bool extism_wamr_manifest_parse(ExtismManifest *manifest, const void *s,
                                size_t len) {
  bool status = true;
  cJSON *j = cJSON_ParseWithLength(s, len);
  if (j == NULL || !cJSON_IsObject(j)) {
    status = false;
    goto end;
  }

  cJSON *wasm_items = cJSON_GetObjectItem(j, "wasm");
  if (!cJSON_IsArray(wasm_items)) {
    return false;
  }

  int nitems = cJSON_GetArraySize(wasm_items);
  for (int i = 0; i < nitems; i++) {
    parse_wasm(manifest, cJSON_GetArrayItem(wasm_items, i));
  }

  extism_wamr_manifest_init(manifest, NULL, 0, NULL, 0, NULL);

end:
  if (j) {
    cJSON_Delete(j);
  }
  return status;
}
