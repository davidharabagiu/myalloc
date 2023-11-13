#include "myalloc.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdalign.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

#define MEM_SIZE 1024 * 1024

typedef struct header {
    alignas(16)
    size_t size;
    struct header *prev;
    struct header *next;
    bool is_free;
} header_t;

static uint8_t mem[MEM_SIZE];
static uint8_t* mem_ptr = mem;
static header_t *head = NULL;
static header_t *tail = NULL;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void *set_mem_ptr(ptrdiff_t off) {
    uint8_t *new_ptr = mem_ptr + off;
    if (new_ptr > mem + sizeof(mem) || new_ptr < mem) {
        return NULL;
    }
    void *ret = mem_ptr;
    mem_ptr = new_ptr;
    return ret;
}

static header_t *get_first_free_block(size_t size) {
    for (header_t *crt = head; crt; crt = crt->next) {
        if (crt->is_free && crt->size >= size) {
            crt->is_free = false;
            return crt;
        }
    }
    return NULL;
}

static header_t *allocate_new_block(size_t size) {
    void *block = set_mem_ptr(sizeof(header_t) + size);
    if (!block) {
        return NULL;
    }

    header_t* hdr = (header_t *)block;
    hdr->size = size;
    hdr->is_free = false;
    hdr->prev = tail;
    hdr->next = NULL;

    if (!head) {
        head = hdr;
    }
    if (tail) {
        tail->next = hdr;
    }
    tail = hdr;

    return hdr;
}

void *my_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    pthread_mutex_lock(&mutex);
    
    header_t* hdr = get_first_free_block(size);
    if (!hdr) {
        hdr = allocate_new_block(size);
    }

    pthread_mutex_unlock(&mutex);

    return hdr ? hdr + 1 : hdr;
}

void my_free(void *ptr) {
    if (!ptr) {
        return;
    }

    header_t *hdr = (header_t *)ptr - 1;
    
    pthread_mutex_lock(&mutex);

    hdr->is_free = true;

    header_t *prev = hdr->prev;
    header_t *next = hdr->next;
    if (prev && prev->is_free) {
        prev->size += sizeof(header_t) + hdr->size;
        prev->next = hdr->next;
        if (tail == hdr) {
            tail = prev;
        }
        hdr = prev;
    }
    if (next && next->is_free) {
        hdr->size += sizeof(header_t) + next->size;
        hdr->next = next->next;
        if (tail == next) {
            tail = hdr;
        }
    }

    if (tail == hdr) {
        if (head == tail) {
            head = tail = NULL;
        } else {
            tail = hdr->prev;
            tail->next = NULL;
        }
        set_mem_ptr(-sizeof(header_t) - hdr->size);
    }

    pthread_mutex_unlock(&mutex);
}

void *my_calloc(size_t count, size_t size) {
    if (count == 0 || size == 0) {
        return NULL;
    }

    size_t total = count * size;
    if (size != total / count) {
        return NULL;
    }
    
    void *block = malloc(total);
    if (!block) {
        return NULL;
    }

    memset(block, 0, total);
    return block;
}

void *my_realloc(void *ptr, size_t size) {
    bool is_mutex_acquired = false;
    void *ret = NULL;

    if (!ptr || size == 0) {
        ret = malloc(size);
        goto done;
    }

    header_t *hdr = (header_t *)ptr - 1;
    if (hdr->size >= size) {
        ret = ptr;
        goto done;
    }

    pthread_mutex_lock(&mutex);
    is_mutex_acquired = true;
    if (hdr == tail) {
        size_t diff = size - hdr->size;
        if (!set_mem_ptr(diff)) {
            ret = NULL;
            goto done;
        }
        hdr->size = size;
        ret = ptr;
        goto done;
    }
    pthread_mutex_unlock(&mutex);
    is_mutex_acquired = false;

    ret = malloc(size);
    if (ret) {
        memcpy(ret, ptr, hdr->size);
        free(ptr);
    }

done:
    if (is_mutex_acquired) {
        pthread_mutex_unlock(&mutex);
    }
    
    return ret;
}

void my_memdump(FILE* file, size_t off, size_t size) {
    static const int cols_per_row = 16;

    if (!file || size == 0) {
        return;
    }

    pthread_mutex_lock(&mutex);

    size_t off_end = off + size;
    if (off_end > mem_ptr - mem) {
        off_end = mem_ptr - mem;
    }
    if (off >= off_end) {
        goto done;
    }

    for (size_t i = off; i < off_end; i += cols_per_row) {
        fprintf(
            file,
            "%0*tX | ",
            (int)sizeof(void *) * 2,
            (intptr_t)&mem[i]
        );

        ptrdiff_t j = 0;
        for (j = 0; j < cols_per_row && i + j < off_end; ++j) {
            fprintf(
                file,
                "%02hhx ",
                mem[i + j]
            );
        }

        fprintf(file, "%*s|  ", (int)((cols_per_row - j) * 3), "");

        for (j = 0; j < cols_per_row && i + j < off_end; ++j) {
            char c = (char)mem[i + j];
            fprintf(
                file,
                "%c%c",
                isgraph(c) ? c : '.',
                j == cols_per_row - 1 ? '\n' : ' '
            );
        }

        if (j < cols_per_row) {
            fprintf(file, "\n");
        }
    }

done:
    pthread_mutex_unlock(&mutex);
}
