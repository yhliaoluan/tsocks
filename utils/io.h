#ifndef _TS_IO_H_
#define _TS_IO_H_

#include <unistd.h>

struct ts_buf {
    void *buffer;
    size_t size;
};

struct ts_stream {
    struct ts_buf buf;
    size_t size; // buffer size wait for reading/writing
    size_t pos; // buffer current position
};

#define TS_SEEK_SET 0
#define TS_SEEK_CUR 1
#define TS_SEEK_END 2

int ts_buf_grow(struct ts_buf *buf, size_t size);
void ts_buf_free(struct ts_buf *buf);
struct ts_stream *ts_stream_new(size_t capacity);

// write from current pos, if size greater than remaining buffer, the buffer will grow.
ssize_t ts_stream_write(struct ts_stream *stream, void *buf, size_t size);

//read to buf from current buf, return actual bytes.
ssize_t ts_stream_read(struct ts_stream *stream, void *buf, size_t size);

//seek from beginning
int ts_stream_seek(struct ts_stream *stream, ssize_t len, int where);

void ts_stream_free(struct ts_stream *stream);

#endif
