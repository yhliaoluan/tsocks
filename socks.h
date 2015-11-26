#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include "io.h"
#include "log.h"

#define TS_STREAM_BUF_SIZE 4096

struct ts_sock {
    int fd;
    struct ts_stream *input;
    struct ts_stream *output;
};

struct ts_session {
    struct ts_sock *client;
    struct ts_sock *remote;
    struct event *ctor;
    struct event *rtoc;
};

static int ts_socket_nonblock(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void ts_close_sock(struct ts_sock *sock) {
    if (sock) {
        ts_log_d("%d will be closed", sock->fd);
        shutdown(sock->fd, 2);
        ts_stream_free(sock->input);
        ts_stream_free(sock->output);
        ts_free(sock);
    }
}

static struct ts_sock *ts_sock_new(int fd) {
    struct ts_sock *sock = ts_malloc(sizeof(struct ts_sock));
    if (!sock) goto failed;
    memset(sock, 0, sizeof(struct ts_sock));
    sock->fd = fd;
    sock->input = ts_stream_new(TS_STREAM_BUF_SIZE);
    sock->output = ts_stream_new(TS_STREAM_BUF_SIZE);
    if (!sock->input || !sock->output) goto failed;

    return sock;

failed:
    ts_close_sock(sock);
    return NULL;
}

static ssize_t ts_sock_recv2peer(struct ts_sock *sock, struct ts_sock *peer) {
    struct ts_buf *buf = &peer->output->buf;
    ssize_t size = recv(sock->fd, buf->buffer, buf->size, 0);
    peer->output->size = size;
    peer->output->pos = 0;
    return size;
}

static int ts_create_tcp_sock(unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        sys_err("create socket failed.");
    }
    ts_log_d("tcp listener socket fd:%d", fd);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        sys_err("bind failed.");
    }

    if (listen(fd, 10) < 0) {
        sys_err("listen failed.");
    }

    if (ts_socket_nonblock(fd) < 0) {
        sys_err("set non-blocking error.");
    }

    return fd;
}

void ts_session_close(struct ts_session *session) {
    if (session) {
        ts_close_sock(session->client);
        event_free(session->ctor);
        ts_close_sock(session->remote);
        event_free(session->rtoc);
        ts_free(session);
    }
}

#endif
