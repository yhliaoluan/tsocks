#ifndef _TS_MEMORY_H_
#define _TS_MEMORY_H_
#include "ts_config.h"
#include <unistd.h>
#include <stdlib.h>
#include "log.h"

void *__ts_malloc(size_t size);
void *__ts_realloc(void *p, size_t size);
void __ts_free(void *p);

size_t ts_mem_size();

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
