#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include "log.h"
#include "opt.h"
#include "debug.h"
#include "memory.h"
#include "utils.h"
#include "socks.h"

struct ts_local_ctx {
    struct ts_local_opt config;
    struct event_base *base;
};

static void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg);
static void ts_relay_rtoc_write(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_WRITE);

    if (ts_flush_once(session->client) <= 0) {
        ts_log_d("flush to %d failed", session->client->fd);
        goto failed;
    }

    if (session->client->output->pos == session->client->output->size) {
        session->rtoc = ts_reassign_ev(session->rtoc, session->remote->fd, EV_READ,
            ts_relay_rtoc_read, session);
        assert(session->rtoc);
    } else {
        session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
            ts_relay_rtoc_write, session);
        assert(session->rtoc);
    }

    return;

failed:
    ts_session_close(session);
}

static void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_READ);

    if (ts_recv2stream(session->remote->fd, session->client->output) <= 0) {
        goto failed;
    }
    ts_stream_decrypt(session->client->output, session->crypto);

    ts_log_d("receive %u bytes from remote:%d", session->client->output->size,
        session->remote->fd);
    ts_stream_print(session->client->output);
    session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
        ts_relay_rtoc_write, session);
    assert(session->rtoc);
    return;

failed:
    ts_session_close(session);
}

static void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg);
static void ts_relay_ctor_write(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    if (ts_flush_once(session->remote) <= 0) {
        ts_log_d("flush to %d failed", session->remote->fd);
        goto failed;
    }

    if (session->remote->output->pos == session->remote->output->size) {
        session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
            ts_relay_ctor_read, session);
        assert(session->ctor);
    } else {
        session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
            ts_relay_ctor_write, session);
        assert(session->ctor);
    }

    return;

failed:
    ts_session_close(session);
}

static void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    if (ts_recv2stream(session->client->fd, session->remote->output) <= 0) {
        goto failed;
    }
    ts_stream_encrypt(session->remote->output, session->crypto);

    ts_log_d("receive %u bytes from client:%d", session->remote->output->size,
        session->client->fd);
    ts_stream_print(session->remote->output);
    session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
        ts_relay_ctor_write, session);
    assert(session->ctor);
    return;

failed:
    ts_session_close(session);
}

static void ts_conn_remote(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
        ts_relay_ctor_read, session);
    assert(session->ctor);

    session->rtoc = event_new(event_get_base(session->ctor), session->remote->fd,
        EV_READ, ts_relay_rtoc_read, session);

    if (event_add(session->rtoc, NULL) < 0) {
        ts_session_close(session);
    }
}

static void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);
    int client = accept(fd, (struct sockaddr *) &addr, &size);

    if (client < 0) {
        sys_err("accept error. %s (%d) size:%u", strerror(errno), errno, size);
    }

    if (ts_socket_nonblock(client) < 0) {
        sys_err("fcntl error.");
    }

    ts_log_d("accept client %d from %s:%u", client,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    struct ts_session *session = ts_malloc(sizeof(struct ts_session));
    memset(session, 0, sizeof(struct ts_session));
    session->client = ts_sock_new(client);

    struct ts_local_ctx *ctx = arg;

    struct sockaddr_in remote;
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = htonl(ctx->config.remote_ipv4);
    remote.sin_port = htons(ctx->config.remote_port);

    session->remote = ts_conn((struct sockaddr *)&remote, sizeof(remote));
    session->crypto = ts_crypto_new(ctx->config.crypto_method, ctx->config.key,
        ctx->config.key_size);

    if (!session->client || !session->remote) {
        goto failed;
    }

    session->ctor = event_new(ctx->base, session->remote->fd,
        EV_WRITE, ts_conn_remote, session);

    if (event_add(session->ctor, NULL) < 0) {
        ts_session_close(session);
    }

    return;

failed:
    ts_session_close(session);
}

static void ts_sigint(evutil_socket_t fd, short what, void *arg) {
    event_base_loopbreak((struct event_base *) arg);
}

int main(int argc, char **argv) {
    struct ts_local_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ts_parse_local_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    int fd = ts_create_tcp_sock(ctx.config.port);
    struct event_base *base = event_base_new();
    if (!base) {
        sys_err("create event_base failed.");
    }

    ctx.base = base;

    struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, ts_tcp_accept, &ctx);
    if (event_add(ev, NULL) < 0) {
        sys_err("add event failed");
    }

    struct event *evsigint = evsignal_new(base, SIGINT, ts_sigint, base);
    if (event_add(evsigint, NULL) < 0) {
        sys_err("add event failed");
    }
    
    event_base_dispatch(base);
    event_free(ev);
    event_base_free(base);

    size_t mem = ts_mem_size();
    ts_log_i("remain memory: %u bytes", mem);
    exit(0);
}

