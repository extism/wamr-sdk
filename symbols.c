#include "internal.h"
#include <stdlib.h>

void symbols_init(struct Symbols *symbols, size_t total) {
  if (symbols->capacity != 0) {
    symbols->length = 0;
    return;
  }
  symbols->symbols = os_malloc(total * sizeof(NativeSymbol));
  symbols->capacity = total;
  symbols->length = 0;
}

NativeSymbol *symbols_add(struct Symbols *s, const NativeSymbol *sym) {
  if (s->length == s->capacity) {
    void *ptr =
        reallocarray(s->symbols, s->capacity + 16, sizeof(NativeSymbol));
    assert(ptr);
    s->symbols = ptr;
  }
  memcpy(&s->symbols[s->length], sym, sizeof(NativeSymbol));
  s->length += 1;
  return &s->symbols[s->length - 1];
}

void symbols_reset(struct Symbols *s) {
  os_free(s->symbols);
  s->length = 0;
  s->capacity = 0;
}
