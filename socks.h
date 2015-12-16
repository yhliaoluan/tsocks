#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_

#include "ts_config.h"

#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <errno.h>
#include "io.h"
#include "log.h"
#include "crypto.h"

#define TS_STREAM_BUF_SIZE 8192

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
    struct ts_crypto_ctx *crypto;
    void *ctx;
};

struct ts_server_ctx {
    struct ts_server_opt config;
    struct event_base *base;
    struct evdns_base *dnsbase;
};

static int ts_socket_nonblock(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void ts_close_sock(struct ts_sock *sock) {
    if (sock) {
        ts_log_d("%d will be closed.", sock->fd);
        close(sock->fd);
        ts_stream_free(sock->input);
        ts_stream_free(sock->output);
        ts_free(sock);
    }
}

static struct ts_sock *ts_sock_new(int fd) {
    struct ts_sock *sock = ts_malloc(sizeof(struct ts_sock));
    if (!sock) goto failed;
    ts_log_d("create sock %d.", fd);
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

static ssize_t ts_recv_append(int fd, struct ts_stream *stream, size_t len) {
    if (ts_stream_ensure_size(stream, stream->size + len) < 0) {
        return -1;
    }
    ssize_t size = recv(fd, stream->buf.buffer + stream->size, len, 0);
    stream->size += size;
    return size;
}

static ssize_t ts_recv(int fd, struct ts_stream *stream, size_t len) {
    ssize_t size = recv(fd, stream->buf.buffer, len, 0);
    stream->size = size;
    stream->pos = 0;
    return size;
}

static ssize_t ts_recv2stream(int fd, struct ts_stream *stream) {
    return ts_recv(fd, stream, stream->buf.size);
}

static void ts_stream_decrypt(struct ts_stream *stream,
    struct ts_crypto_ctx *crypto) {

    ts_crypto_decrypt(crypto, stream->buf.buffer, stream->buf.buffer, stream->size);
}

static void ts_stream_encrypt(struct ts_stream *stream,
    struct ts_crypto_ctx *crypto) {

    ts_crypto_encrypt(crypto, stream->buf.buffer, stream->buf.buffer, stream->size);
}

static void ts_stream_print(struct ts_stream *stream) {
    ts_print_bin_as_hex((unsigned char *)stream->buf.buffer, stream->size);
}

static void ts_stream_print_text(struct ts_stream *stream) {
    if (ts_log_enabled(TS_LOG_VERBOSE)) {
        ((char *)stream->buf.buffer)[stream->size] = 0;
        printf("%s\n", (char *)stream->buf.buffer);
    }
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

static struct ts_sock *ts_conn(struct sockaddr *addr, size_t size) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ts_log_e("socket failed");
        goto failed;
    }

    if (ts_socket_nonblock(fd) < 0) {
        ts_log_e("fd %d set nonblock failed", fd);
        goto failed;
    }

    if (connect(fd, addr, size) < 0 &&
        errno != EINPROGRESS) {

        ts_log_e("connect failed, errno:%d", errno);
        goto failed;
    }

    return ts_sock_new(fd);

failed:
    if (fd > 0) close(fd);
    return NULL;
}

static void _ts_session_close(struct ts_session *session) {
    if (session) {
        ts_close_sock(session->client);
        if (session->ctor) event_free(session->ctor);
        ts_close_sock(session->remote);
        if (session->rtoc) event_free(session->rtoc);
        ts_crypto_free(session->crypto);
        ts_free(session);
    }
}

#define ts_session_close(session) \
    do {\
        ts_log_d("close session from %s:%d", __FILENAME__, __LINE__);\
        _ts_session_close(session);\
    } while (0)

static struct event *ts_reassign_ev(struct event *ev, evutil_socket_t fd, short what,
    void (*cb) (evutil_socket_t, short, void *), void *args) {

    struct event *new_ev = event_new(event_get_base(ev), fd, what, cb, args);
    if (!new_ev) return NULL;
    event_free(ev);
    if (event_add(new_ev, NULL) < 0) return NULL;
    return new_ev;
}

static ssize_t ts_flush_once(struct ts_sock *sock) {
    ssize_t sent = send(sock->fd, sock->output->buf.buffer + sock->output->pos,
        sock->output->size - sock->output->pos, 0);
    if (sent > 0) {
        sock->output->pos += sent;
        assert(sock->output->pos <= sock->output->size);
        ts_log_d("after sending to %d, size:%u, pos:%u", sock->fd,
            sock->output->size, sock->output->pos);
    }
    return sent;
}

#endif
