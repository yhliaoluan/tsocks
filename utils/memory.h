#ifndef _TS_MEMORY_H_
#define _TS_MEMORY_H_
#include <unistd.h>
#include <stdlib.h>
#include "utils/log.h"

struct ts_buf {
    void *buffer;
    size_t size;
};

void *__ts_malloc(size_t size);
void *__ts_realloc(void *p, size_t size);
void __ts_free(void *p);

void ts_realloc_buf(struct ts_buf *buf, size_t size);
void ts_alloc_buf(struct ts_buf *buf, size_t size);
void ts_free_buf(struct ts_buf *buf);

size_t ts_get_total_size();

#ifdef TS_DETECT_MEM_LEAK
#define ts_malloc __ts_malloc
#define ts_realloc __ts_realloc
#define ts_free __ts_free
#else
#define ts_malloc malloc
#define ts_realloc realloc
#define ts_free free
#endif

#endif
