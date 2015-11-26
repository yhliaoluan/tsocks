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

static void ts_conn_remote(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    session->rtoc = ts_reassign_ev(session->rtoc, session->remote->fd, EV_READ,
        ts_relay_rtoc_read, session);
    assert(session->rtoc);

    session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
        ts_relay_ctor_read, session);
    assert(session->ctor);
}

static void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);
    int client = accept(fd, (struct sockaddr *) &addr, &size);

    if (client < 0) {
        sys_err("accept error.");
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
    session->remote = ts_conn_ipv4(ntohl(ctx->config.remote_ipv4),
        ntohs(ctx->config.remote_port));

    if (!session->client || !session->remote) goto failed;

    session->ctor = event_new(ctx->base, session->remote->fd,
        EV_WRITE, ts_conn_remote, session);

    if (event_add(session->ctor, NULL) < 0) {
        ts_session_close(session);
    }

failed:
    ts_session_close(session);
}

static void ts_sigint(evutil_socket_t fd, short what, void *arg) {
    event_base_loopbreak((struct event_base *) arg);
}

int main(int argc, char **argv) {
    struct ts_local_ctx ctx;

    ts_parse_local_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_log_i("use config: log_level:%s, port:%u, remote ip:%s, port:%u",
        ts_level2str(ctx.config.log_level),
        ctx.config.port,
        inet_ntoa(*(struct in_addr *)(&ctx.config.remote_ipv4)),
        ctx.config.remote_port);
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
    assert(mem == 0);
    exit(0);
}

