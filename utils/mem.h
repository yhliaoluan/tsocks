#ifndef _TS_MEM_H_
#define _TS_MEM_H_
#include <unistd.h>
#include "utils/log.h"

struct ts_buf {
    void *buffer;
    size_t size;
};

#define PAD(a, p) (((a)+(p-1))&~(p-1))

static inline void ts_realloc(struct ts_buf *buf, size_t size) {
    if (buf->size < size) {
        ts_log_d("realloc from %u to %u", buf->size, PAD(size, 64));
        buf->buffer = realloc(buf->buffer, PAD(size, 64));
        buf->size = PAD(size, 64);
    }
}

static inline void ts_alloc(struct ts_buf *buf, size_t size) {
    if (buf->size < size) {
        ts_log_d("realloc from %u to %u", buf->size, PAD(size, 64));
        void *old_buf = buf->buffer;
        buf->buffer = malloc(PAD(size, 64));
        memcpy(buf->buffer, old_buf, buf->size);
        free(old_buf);
        buf->size = PAD(size, 64);
    }
}

static inline void ts_free(struct ts_buf *buf) {
    free(buf->buffer);
    buf->buffer = (void *) 0;
    buf->size = 0;
}

#endif
