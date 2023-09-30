#pragma  once

#include_next <stdlib.h> // IWYU pragma: keep
#include <stddef.h>

extern void *malloc(size_t size);
extern void free(void *ptr);
