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
#include "socks.h"
#include "socks5.h"

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
    ts_stream_encrypt(session->client->output, session->crypto);

    ts_log_d("REMOTE to CLIENT %u bytes", session->client->output->size);
    ts_stream_print_text(session->client->output);
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
    ts_stream_decrypt(session->remote->output, session->crypto);

    ts_log_d("CLIENT to REMOTE %u bytes", session->remote->output->size);
    ts_stream_print_text(session->remote->output);
    session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
        ts_relay_ctor_write, session);
    assert(session->ctor);
    return;

failed:
    ts_session_close(session);
}

static void ts_remote_conn_ready(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;

    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    size_t remain = session->client->input->size - session->client->input->pos;
    if (remain > 0) {
        ts_stream_write(session->remote->output,
            session->client->input->buf.buffer + session->client->input->pos, remain);
        ts_stream_seek(session->remote->output, 0, TS_SEEK_SET);
        session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
            ts_relay_ctor_write, session);
        assert(session->ctor);
    } else {
        session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
            ts_relay_ctor_read, session);
        assert(session->ctor);
    }

    session->rtoc = event_new(event_get_base(session->ctor), session->remote->fd,
        EV_READ, ts_relay_rtoc_read, session);
    if (event_add(session->rtoc, NULL) < 0) {
        ts_session_close(session);
    }
}

static void ts_conn_sockaddr(struct sockaddr *addr, size_t size, struct ts_session *session) {

    session->remote = ts_conn(addr, size);

    if (session->remote) {
        ts_log_d("client %d to remote %d", session->client->fd,
            session->remote->fd);
        session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
            ts_remote_conn_ready, session);
        assert(session->ctor);
    } else {
        ts_log_e("create peer failed");
        ts_session_close(session);
    }
}

static void ts_dns_resolved(int errcode, struct evutil_addrinfo *addr, void *ptr) {

    struct ts_session *session = ptr;
    if (errcode) {
        ts_log_e("dns resolve failed");
        goto failed;
    }

    ts_conn_sockaddr(addr->ai_addr, addr->ai_addrlen, session);
    evutil_freeaddrinfo(addr);

    return;
failed:
    ts_session_close(session);
}

static void ts_conn_host(const char *hostname, unsigned short port, struct ts_session *session) {
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    /* Unless we specify a socktype, we'll get at least two entries for
     * each address: one for TCP and one for UDP. That's not what we
     * want. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char port_buf[6];
    evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);
    /* We will run a non-blocking dns resolve */
    struct ts_server_ctx *ctx = session->ctx;
    ts_log_d("start to resolve host %s", hostname);
    evdns_getaddrinfo(ctx->dnsbase, hostname, port_buf,
        &hints, ts_dns_resolved, session);
}

static void ts_conn_ipv4(unsigned long ip, unsigned short port,
    struct ts_session *session) {

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    ts_conn_sockaddr((struct sockaddr *)&addr, sizeof(addr), session);
}

static void ts_socks5_go(const unsigned char *buf, struct ts_session *session) {
    char host[256] = { 0 };
    if (buf[0] == 3) {
        memcpy(host, &buf[2], buf[1]);
        ts_conn_host(host, ntohs(*(unsigned short *)&buf[2 + buf[1]]), session);
    } else if (buf[0] == 1) {
        // ipv4
        ts_conn_ipv4(ntohl(*(unsigned long *)&buf[1]),
            ntohs(*(unsigned short *)&buf[5]), session);
    } else {
        ts_log_w("ipv6 currently not support");
    }
}

void ts_ss_relay(struct ts_session *session) {
    unsigned char buf[512];
    assert(session->client->input->pos == 0);
    assert(session->client->input->size > 0);
    if (ts_stream_read(session->client->input, buf, 1) <= 0) {
        goto failed;
    }
    if (buf[0] == 1) {
        if (ts_stream_read(session->client->input, buf + 1, 6) <= 0) {
            goto failed;
        }
    } else if (buf[0] == 3) {
        if (ts_stream_read(session->client->input, buf + 1, 3) <= 0) goto failed;
        if (ts_stream_read(session->client->input, buf + 4, buf[1]) <= 0) goto failed;
    } else {
        goto failed;
    }
    ts_socks5_go(buf, session);

    return;
failed:
    ts_session_close(session);
}
