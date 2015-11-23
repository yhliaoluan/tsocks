#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <event2/event.h>
#include <fcntl.h>
#include "io.h"
#include "log.h"

struct ts_sock {
    int fd;
    struct ts_stream *input;
    struct ts_stream *output;
    struct ts_sock *peer;
    struct event *ev;
};

static int ts_socket_nonblock(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void ts_close_sock(struct ts_sock *sock) {
    if (sock) {
        event_free(sock->ev);
        shutdown(sock->fd, 2);
        ts_stream_free(sock->input);
        ts_stream_free(sock->output);
        ts_free(sock);
        ts_log_d("%d closed", sock->fd);
    }
}

static struct ts_sock *ts_sock_new(int fd) {
    struct ts_sock *sock = ts_malloc(sizeof(struct ts_sock));
    if (!sock) goto failed;
    memset(sock, 0, sizeof(struct ts_sock));
    sock->fd = fd;
    struct ts_stream *input = ts_stream_new(1024);
    struct ts_stream *output = ts_stream_new(1024);
    if (!input || !output) goto failed;

    return sock;

failed:
    ts_close_sock(sock);
    return NULL;
}

#endif
