
#include <libxl4bus/low_level.h>

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>

static int in_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int);
static void print_out(const char *);

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;

#if 0
    ll_cfg.realloc = realloc;
    ll_cfg.malloc = malloc;
    ll_cfg.free = free;
#else
    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = print_out;
#endif

    xl4bus_init_ll(&ll_cfg);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in b_addr;
    memset(&b_addr, 0, sizeof(b_addr));
    b_addr.sin_family = AF_INET;
    b_addr.sin_port = htons(9133);
    b_addr.sin_addr.s_addr = INADDR_ANY;

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
    }
#endif

    if (bind(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        perror("bind");
        return 1;
    }

    if (listen(fd, 5)) {
        perror("listen");
        return 1;
    }

    while (1) {

        socklen_t b_addr_len = sizeof(b_addr);
        int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
        if (fd2 < 0) {
            perror("accept");
            return 1;
        }

        xl4bus_connection_t * conn = malloc(sizeof(xl4bus_connection_t));
        if (!conn) {
            perror("malloc");
            return 1;
        }

        memset(conn, 0, sizeof(xl4bus_connection_t));

        conn->on_message = in_message;
        conn->fd = fd2;

        conn->set_poll = set_poll;

        pthread_t nt;

        if (pthread_create(&nt, 0, run_conn, conn)) {
            perror("pthread_create");
            return 1;
        }

    }
}

void * run_conn(void * _arg) {

    xl4bus_connection_t * conn = (xl4bus_connection_t*)_arg;

    struct pollfd pfd;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = conn->fd;

    conn->custom = &pfd;

    if (xl4bus_init_connection(conn) == E_XL4BUS_OK) {

        int timeout = -1;

        while (1) {

            int rc = poll(&pfd, 1, timeout);
            if (rc < 0) {
                perror("poll");
                break;
            }

            int flags = 0;
            if (pfd.revents & (POLLIN | POLLPRI)) {
                flags = XL4BUS_POLL_READ;
            } else if (pfd.revents & POLLOUT) {
                flags |= XL4BUS_POLL_WRITE;
            } else if (pfd.revents & (POLLHUP | POLLNVAL)) {
                flags |= XL4BUS_POLL_ERR;
            }

            if (xl4bus_process_connection(conn, conn->fd, flags, &timeout) != E_XL4BUS_OK) {
                break;
            }

        }

    }

    printf("Shutting down connection %d\n", conn->fd);
    shutdown(conn->fd, SHUT_RDWR);
    close(conn->fd);
    free(conn);

    return 0;

}

int set_poll(xl4bus_connection_t * conn, int flg) {

    struct pollfd * pfd = conn->custom;
    pfd->events = 0;
    if (flg & XL4BUS_POLL_READ) {
        pfd->events = POLLIN;
    }
    if (flg & XL4BUS_POLL_WRITE) {
        pfd->events |= POLLOUT;
    }
    return E_XL4BUS_OK;

}

int in_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    printf("hooray, a message!\n");
    return E_XL4BUS_OK;

}

void print_out(const char * msg) {

    printf("%s\n", msg);

}
