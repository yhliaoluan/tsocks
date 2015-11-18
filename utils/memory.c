#include <stdlib.h>
#include <unistd.h>
#include "utils/memory.h"

#define PAD(a, p) (((a)+(p-1))&~(p-1))

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

size_t ts_get_total_size() { return total_size; }

void ts_realloc_buf(struct ts_buf *buf, size_t size) {
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

void ts_alloc_buf(struct ts_buf *buf, size_t size) {
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

void ts_free_buf(struct ts_buf *buf) {
    free(buf->buffer);
    buf->buffer = (void *) 0;
    buf->size = 0;
}


