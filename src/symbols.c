#include "internal.h"
#include <stdlib.h>

void init_symbols(struct Symbols *sym, size_t total) {
  if (sym->capacity != 0 && sym->symbols != NULL) {
    sym->length = 0;
    if (sym->capacity >= total) {
      return;
    }
    free(sym->symbols);
  }

  sym->symbols = os_malloc(total * sizeof(NativeSymbol));
  assert(sym->symbols);
  sym->capacity = total;
  sym->length = 0;
}

NativeSymbol *add_symbols(struct Symbols *s, const NativeSymbol *sym,
                          size_t n) {
  if (s->length == s->capacity) {
    void *ptr =
        reallocarray(s->symbols, s->capacity + (n * 2), sizeof(NativeSymbol));
    assert(ptr);
    s->symbols = ptr;
  }
  memcpy(&s->symbols[s->length], sym, sizeof(NativeSymbol) * n);
  s->length += n;
  return &s->symbols[s->length - n];
}

void reset_symbols(struct Symbols *s) {
  os_free(s->symbols);
  s->symbols = NULL;
  s->length = 0;
  s->capacity = 0;
}
