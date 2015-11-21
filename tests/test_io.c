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

    ts_assert_true(ts_stream_write(stream, "Hello", 5) >= 0);
    ts_assert_true(stream->size == 5);
    ts_assert_true(stream->pos == 0);

    char buf[10] = {0};
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 5);
    ts_assert_true(strcmp(buf, "Hello") == 0);
    ts_assert_true(stream->size == 5);
    ts_assert_true(stream->pos == 5);

    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 0);
    ts_assert_true(ts_stream_seek(stream, 0, TS_SEEK_SET) == 0);
    ts_assert_true(ts_stream_read(stream, buf, sizeof(buf)) == 5);

    ts_stream_free(stream);
    ts_assert_true(ts_mem_leak_size() == 0);
    return 0;
}
