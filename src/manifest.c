#include "cJSON.h"
#include "extism-wamr.h"
#include "util.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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

static bool parse_config(ExtismManifest *manifest, cJSON *config) {
  if (!cJSON_IsObject(config)) {
    return false;
  }

  for (cJSON *item = config->child; item != NULL; item = item->next) {
    const char *name = item->string;
    if (!cJSON_IsString(item)) {
      return false;
    }

    ExtismConfig c = {
        .owned = true,
        .key = string_copy(name, strlen(name)),
        .value = string_copy(item->valuestring, strlen(item->valuestring))};
    manifest->config = array_push(manifest->config, &c);
  }
  return true;
}

bool extism_wamr_manifest_parse(ExtismManifest *manifest, const void *s,
                                size_t len) {
  extism_wamr_manifest_init(manifest, NULL, 0, NULL, 0, NULL);

  bool status = true;
  cJSON *j = cJSON_ParseWithLength(s, len);
  if (j == NULL || !cJSON_IsObject(j)) {
    puts("A");
    status = false;
    goto end;
  }

  cJSON *wasm_items = cJSON_GetObjectItem(j, "wasm");
  if (!cJSON_IsArray(wasm_items)) {
    puts("B");
    status = false;
    goto end;
  }

  int nitems = cJSON_GetArraySize(wasm_items);
  for (int i = 0; i < nitems; i++) {
    if (!parse_wasm(manifest, cJSON_GetArrayItem(wasm_items, i))) {
      puts("C");
      status = false;
      goto end;
    }
  }

  cJSON *config = cJSON_GetObjectItem(j, "config");
  if (config) {
    if (!parse_config(manifest, config)) {
      puts("D");
      status = false;
      goto end;
    }
  }

end:
  if (j) {
    cJSON_Delete(j);
  }
  return status;
}
