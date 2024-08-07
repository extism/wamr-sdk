#ifndef __EXTISM_UTIL_H
#define __EXTISM_UTIL_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define IF_NULL(x) if ((x) == NULL)

bool string_equal(const char *a, size_t aLen, const char *b, size_t bLen);
char *string_copy(const char *s, size_t len);
uint8_t *read_file(const char *filename, size_t *len);

typedef struct {
  size_t capacity, length, itemSize;
  uint8_t ptr[0];
} ArrayHeader;

#define ARRAY_HEADER(x) ((ArrayHeader *)((uint8_t *)(x) - sizeof(ArrayHeader)))
#define ARRAY_LENGTH(x) ((x) == NULL ? 0 : ARRAY_HEADER(x)->length)
#define ARRAY_CAPACITY(x) ((x) == NULL ? 0 : ARRAY_HEADER(x)->capacity)
#define ARRAY_ITEM_SIZE(x) ((x) == NULL ? 0 : ARRAY_HEADER(x)->itemSize)

void *array_new(size_t itemSize, size_t capacity);
void *array_resize(void *arr, size_t newSize);
void *array_push(void *arr, const void *item);
void *array_push_resize_by(void *arr, const void *item, size_t n);
void *array_push_front(void *arr, const void *item);
bool array_pop(void *arr, void *dest);
void array_free(void *arr);
void array_iter(void *arr, bool (*f)(size_t index, void *ptr, void *userdata),
                void *userdata);

#endif
