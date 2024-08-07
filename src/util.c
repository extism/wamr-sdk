
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

bool string_equal(const char *a, size_t aLen, const char *b, size_t bLen) {
  if (aLen != bLen) {
    return false;
  }

  return strncmp(a, b, aLen) == 0;
}

char *string_copy(const char *s, size_t len) {
  if (s == NULL) {
    return NULL;
  }

  char *out = malloc(len + 1);
  if (out == NULL) {
    return NULL;
  }

  memcpy(out, s, len);
  out[len] = '\0';

  return out;
}

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

void *array_new(size_t itemSize, size_t capacity) {
  ArrayHeader *hdr = malloc(sizeof(ArrayHeader) + (itemSize * capacity));
  if (hdr == NULL) {
    return NULL;
  }
  hdr->itemSize = itemSize;
  hdr->capacity = capacity;
  hdr->length = 0;

  return (void *)(hdr->ptr);
}

void *array_resize(void *arr, size_t newCapacity) {
  size_t itemSize = ARRAY_ITEM_SIZE(arr);
  ArrayHeader *hdr = realloc(ARRAY_HEADER(arr),
                             sizeof(ArrayHeader) + (itemSize * newCapacity));
  if (hdr == NULL) {
    return NULL;
  }
  hdr->capacity = newCapacity;
  if (hdr->length > newCapacity) {
    hdr->length = newCapacity;
  }
  return hdr->ptr;
}

void *array_push_resize_by(void *arr, const void *item, size_t n) {
  void *out = arr;
  size_t length = ARRAY_LENGTH(arr);
  size_t capacity = ARRAY_CAPACITY(arr);
  size_t itemSize = ARRAY_ITEM_SIZE(arr);

  if (length + 1 >= capacity) {
    out = array_resize(arr, capacity + n);
    if (out == NULL) {
      return NULL;
    }
  }

  memcpy(out + (length * itemSize), item, ARRAY_ITEM_SIZE(out));
  ARRAY_HEADER(out)->length += 1;
  return out;
}

void *array_push(void *arr, const void *item) {
  return array_push_resize_by(arr, item, 16);
}

void *array_push_front(void *arr, const void *item) {
  arr = array_push_resize_by(arr, item, 16);
  if (arr == NULL) {
    return NULL;
  }

  memcpy(arr + ARRAY_ITEM_SIZE(arr), arr,
         ARRAY_ITEM_SIZE(arr) * ARRAY_LENGTH(arr));
  memcpy(arr, item, ARRAY_ITEM_SIZE(arr));
  return arr;
}

bool array_pop(void *arr, void *dest) {
  ArrayHeader *hdr = ARRAY_HEADER(arr);
  if (hdr->length == 0) {
    return false;
  }

  memcpy(dest, arr + (hdr->length - 1), hdr->itemSize);
  hdr->length -= 1;
  return true;
}

void array_free(void *arr) { free(ARRAY_HEADER(arr)); }

void array_iter(void *arr, bool (*f)(size_t index, void *ptr, void *userdata),
                void *userdata) {
  for (size_t i = 0; i < ARRAY_LENGTH(arr); i++) {
    f(i, arr + i, userdata);
  }
}
