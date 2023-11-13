#ifndef MYALLOC_H_
#define MYALLOC_H_

#include <stddef.h>
#include <stdio.h>

void *my_malloc(size_t size);
void my_free(void *ptr);
void *my_calloc(size_t count, size_t size);
void *my_realloc(void *ptr, size_t size);
void my_memdump(FILE* file, size_t off, size_t size);

#endif  // MYALLOC_H_
