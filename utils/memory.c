#include <stdlib.h>
#include <unistd.h>
#include "utils/memory.h"

union ts_alian {
    size_t v1;
    void *v2;
    double v3;
};

#define ALIGNMENT sizeof(union ts_alian)

#define OUTPTR(x) ((char *)(x) + ALIGNMENT)
#define INPTR(x) ((char *)(x) - ALIGNMENT)

static size_t total_size = 0;

void *__ts_malloc(size_t size) {
    void *pori = malloc(size + ALIGNMENT);
    if (!pori) return pori;
    *(size_t *)pori = size;
    //FIXME thread-safe
    total_size += size;
    return OUTPTR(pori);
}

void *__ts_realloc(void *p, size_t size) {
    // TODO
    return p;
}

void __ts_free(void *p) {
    if (!p) return;
    void *pori = INPTR(p);
    //FIXME thread-safe
    total_size -= *((size_t *)pori);
    free(pori);
}

size_t ts_mem_leak_size() { return total_size; }

