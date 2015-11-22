#include <stdlib.h>
#include <string.h>
#include "utils/io.h"
#include "utils/log.h"
#include "utils/utils.h"
#include "utils/memory.h"

#define PAD(a, p) (((a)+(p-1))&~(p-1))
#define PAD_SIZE 64

static size_t ts_stream_remain(struct ts_stream *stream) {
    return stream->size - stream->pos;
}

int ts_buf_grow(struct ts_buf *buf, size_t size) {
    if (buf->size < size) {
        void *old_buf = buf->buffer;
        buf->buffer = ts_malloc(PAD(size, PAD_SIZE));
        if (buf->buffer) {
            memcpy(buf->buffer, old_buf, buf->size);
            buf->size = PAD(size, PAD_SIZE);
        } else {
            ts_log_e("malloc %u size memory failed.", PAD(size, PAD_SIZE));
            buf->size = 0;
            return -1;
        }
        ts_free(old_buf);
    }
    return 0;
}

void ts_buf_free(struct ts_buf *buf) {
    ts_free(buf->buffer);
    buf->buffer = (void *) 0;
    buf->size = 0;
}

struct ts_stream *ts_stream_new(size_t capacity) {
    struct ts_stream *stream = ts_malloc(sizeof(struct ts_stream));
    memset(stream, 0, sizeof(struct ts_stream));
    if (ts_buf_grow(&stream->buf, capacity) < 0) {
        return NULL;
    }
    stream->size = 0;
    stream->pos = 0;
    return stream;
}

int ts_stream_seek(struct ts_stream *stream, ssize_t len, int where) {
    if (where == TS_SEEK_SET) {
        stream->pos = len;
    } else if (where == TS_SEEK_CUR) {
        stream->pos += len;
    } else if (where == TS_SEEK_END) {
        stream->pos = stream->size + len;
    }
    return 0;
}

ssize_t ts_stream_write(struct ts_stream *stream, void *buf, size_t size) {
    if (stream->buf.size < stream->pos + size) {
        if (ts_buf_grow(&stream->buf, stream->pos + size) < 0) {
            return -1;
        }
    }
    memcpy(stream->buf.buffer + stream->pos, buf, size);
    stream->pos += size;
    stream->size = max(stream->size, stream->pos);
    return size;
}

ssize_t ts_stream_read(struct ts_stream *stream, void *buf, size_t size) {
    size = min(size, ts_stream_remain(stream));
    memcpy(buf, stream->buf.buffer + stream->pos, size);
    stream->pos += size;
    return size;
}

void ts_stream_free(struct ts_stream *stream) {
    ts_buf_free(&stream->buf);
    ts_free(stream);
}

