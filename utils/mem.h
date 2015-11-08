#ifndef _TS_MEM_H_
#define _TS_MEM_H_
#include <unistd.h>

struct ts_buf {
    void *buffer;
    uint32_t size;
};

static inline void ts_alloc(struct ts_buf *buf, uint32_t size) {
    if (buf->size < size) {
        buf->buffer = realloc(buf->buffer, size);
        buf->size = size;
    }
}

static inline void ts_free(struct ts_buf *buf) {
    free(buf->buffer);
    buf->buffer = (void *) 0;
    buf->size = 0;
}

#endif
