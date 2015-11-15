#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include "utils/log.h"
#include "utils/mem.h"
#include "utils/socks.h"
#include "utils/utils.h"

struct ts_sock_ctx *ts_add_fd(struct ts_socks *socks, int fd, int e, sock_read r, sock_write w) {
    if (socks->capfds == socks->nfds) {
        socks->capfds = max(socks->capfds * 2, 16);

        ts_log_d("resize capability to %u", socks->capfds);
        struct pollfd *oldfds = socks->fds;
        socks->fds = malloc(sizeof(struct pollfd) * socks->capfds);
        memcpy(socks->fds, oldfds, sizeof(struct pollfd) * socks->nfds);
        free(oldfds);

        struct ts_sock_ctx *oldsocks = socks->socks;
        socks->socks = malloc(sizeof(struct ts_sock_ctx) * socks->capfds);
        memcpy(socks->socks, oldsocks, sizeof(struct ts_sock_ctx) * socks->nfds);
        free(oldsocks);
    }

    memset(&socks->fds[socks->nfds], 0, sizeof(struct pollfd));
    socks->fds[socks->nfds].fd = fd;
    socks->fds[socks->nfds].events = e;
    socks->fds[socks->nfds].revents = 0;

    struct ts_sock_ctx *sock = &socks->socks[socks->nfds];
    memset(sock, 0, sizeof(struct ts_sock_ctx));
    sock->fd = &socks->fds[socks->nfds];
    sock->read = r;
    sock->write = w;
    socks->nfds++;
    ts_log_d("added sock %d, events %d, current count is %u", fd, e, socks->nfds);
    return sock;
}

size_t ts_remove_fd_by_index(struct ts_socks *socks, int index) {
    shutdown(socks->fds[index].fd, 2);
    ts_free(&socks->socks[index].buffer);
    socks->fds[index] = socks->fds[socks->nfds - 1];
    socks->socks[index] = socks->socks[socks->nfds - 1];
    socks->nfds--;
    return socks->nfds;
}
