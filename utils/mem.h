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
        if (buf->buffer) {
            buf->size = PAD(size, 64);
        } else {
            buf->size = 0;
        }
    }
}

static inline void ts_alloc(struct ts_buf *buf, size_t size) {
    if (buf->size < size) {
        ts_log_d("realloc from %u to %u", buf->size, PAD(size, 64));
        void *old_buf = buf->buffer;
        buf->buffer = malloc(PAD(size, 64));
        if (buf->buffer) {
            memcpy(buf->buffer, old_buf, buf->size);
            buf->size = PAD(size, 64);
        } else {
            buf->size = 0;
        }
        free(old_buf);
    }
}

static inline void ts_free(struct ts_buf *buf) {
    free(buf->buffer);
    buf->buffer = (void *) 0;
    buf->size = 0;
}

#endif
