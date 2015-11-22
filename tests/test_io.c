#include <stdlib.h>
#include <stdio.h>
#include "utils/io.h"
#include "utils/debug.h"
#include "utils/memory.h"

int main(int argc, char **argv) {
    struct ts_stream *stream = ts_stream_new(128);
    ts_assert_true(stream);
    ts_assert_true(stream->size == 0);
    ts_assert_true(stream->pos == 0);
    ts_assert_true(stream->buf.size >= 128);

    ts_assert_true(ts_stream_write(stream, "Hello", 5) == 5);
    ts_assert_true(stream->size == 5);
    ts_assert_true(stream->pos == 5);
    ts_assert_true(ts_stream_seek(stream, 0, TS_SEEK_SET) == 0);
    ts_assert_true(stream->size == 5);
    ts_assert_true(stream->pos == 0);
    char buf[128] = {0};
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 5);
    ts_assert_true(strcmp(buf, "Hello") == 0);
    ts_assert_true(stream->size == 5);
    ts_assert_true(stream->pos == 5);

    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 0);
    ts_assert_true(ts_stream_seek(stream, 0, TS_SEEK_SET) == 0);
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 5);
    ts_assert_true(ts_stream_write(stream, " World", 6) == 6);
    ts_assert_true(ts_stream_seek(stream, 0, TS_SEEK_SET) == 0);
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 11);
    ts_assert_true(strcmp(buf, "Hello World") == 0);
    ts_assert_true(ts_stream_seek(stream, -5, TS_SEEK_CUR) == 0);
    memset(buf, 0, sizeof(buf));
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 5);
    ts_assert_true(strcmp(buf, "World") == 0);

    ts_stream_free(stream);
    ts_assert_true(ts_mem_leak_size() == 0);
    return 0;
}
