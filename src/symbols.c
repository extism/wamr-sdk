#include "internal.h"
#include <stdlib.h>

void init_symbols(NativeSymbol **sym, size_t total) {
  if (sym == NULL) {
    return;
  }

  NativeSymbol *tmp = *sym;
  if (tmp != NULL && ARRAY_CAPACITY(tmp) != 0) {
    array_free(tmp);
  }

  tmp = array_new(sizeof(NativeSymbol), total);
  assert(tmp);
  *sym = tmp;
}

NativeSymbol *add_symbols(NativeSymbol **st, const NativeSymbol *sym,
                          size_t n) {
  if (st == NULL) {
    return NULL;
  }
  NativeSymbol *s = *st;
  for (size_t i = 0; i < n; i++) {
    s = array_push(s, &sym[i]);
  }
  *st = s;
  return &s[ARRAY_LENGTH(s) - n];
}

void reset_symbols(NativeSymbol **s) {
  if (s == NULL)
    return;

  for (size_t i = 0; i < ARRAY_LENGTH((*s)); i++) {
    free((*s)[i].attachment);
  }

  array_free(*s);
  *s = NULL;
}
