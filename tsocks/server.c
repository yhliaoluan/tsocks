#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include "log.h"
#include "opt.h"
#include "debug.h"
#include "memory.h"
#include "utils.h"
#include "socks5.h"
#include "ss.h"

void ts_request_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    struct ts_sock *client = session->client;
    int size = ts_recv2stream(client->fd, client->input);
    if (size <= 0) goto failed;

    ts_stream_decrypt(client->input, session->crypto);
    ts_stream_print(client->input);
    unsigned char *buf = client->input->buf.buffer;
    if (buf[0] == 5) {
        // begin of socks v5 negotiation
        ts_socks5_relay(session);
    } else if (buf[0] == 1 || buf[0] == 3) {
        ts_ss_relay(session);
    } else {
        ts_log_w("unknown protocal. %d", buf[0]);
        goto failed;
    }

    return;
failed:
    ts_session_close(session);
}

void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
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

    struct ts_server_ctx *ctx = arg;
    struct ts_session *session = ts_malloc(sizeof(struct ts_session));
    memset(session, 0, sizeof(struct ts_session));

    session->client = ts_sock_new(client);
    session->ctor = event_new(ctx->base, client,
        EV_READ, ts_request_method, session);
    session->crypto = ts_crypto_new(ctx->config.crypto_method, ctx->config.key,
        ctx->config.key_size);
    session->ctx = ctx;

    if (event_add(session->ctor, NULL) < 0) {
        ts_session_close(session);
    }
}

void ts_sigint(evutil_socket_t fd, short what, void *arg) {
    event_base_loopbreak((struct event_base *) arg);
}

int main(int argc, char **argv) {
    struct ts_server_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ts_parse_server_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    int fd = ts_create_tcp_sock(ctx.config.port);
    struct event_base *base = event_base_new();
    if (!base) {
        sys_err("create event_base failed.");
    }

    struct evdns_base *dnsbase = evdns_base_new(base, 1);
    if (!dnsbase) {
        sys_err("create evdns_base failed.");
    }

    ctx.base = base;
    ctx.dnsbase = dnsbase;

    struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, ts_tcp_accept, &ctx);
    if (event_add(ev, NULL) < 0) {
        sys_err("add event failed");
    }

    struct event *evsigint = evsignal_new(base, SIGINT, ts_sigint, base);
    if (event_add(evsigint, NULL) < 0) {
        sys_err("add signal event failed");
    }
    
    event_base_dispatch(base);

    event_free(ev);
    event_free(evsigint);
    evdns_base_free(dnsbase, 0);
    event_base_free(base);

    size_t mem = ts_mem_size();
    ts_log_i("memory: %u bytes", mem);

    exit(0);
}

