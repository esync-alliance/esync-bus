
#include "lib/common.h"

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

#include <libxl4bus/low_level.h>

static int on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int, int);

int debug = 1;

typedef struct {
    struct pollfd pfd;
    int timeout;
} my_info_t;

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

    if (xl4bus_init_ll(&ll_cfg)) {
        printf("failed to init xl4bus");
        return 1;
    }

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

    xl4bus_identity_t my_id;

    if (load_test_x509_creds(&my_id, "ll-server", argv[0])) {
        printf("can't load test server credentials at .../pki/ll-server");
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
        memcpy(&conn->identity, &my_id, sizeof(xl4bus_identity_t));

        conn->on_message = on_message;
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

    my_info_t myt;

    memset(&myt, 0, sizeof(myt));
    myt.pfd.fd = conn->fd;

    conn->custom = &myt.pfd;

    if (xl4bus_init_connection(conn) == E_XL4BUS_OK) {

        while (1) {

            int rc = poll(&myt.pfd, 1, myt.timeout);
            if (rc < 0) {
                perror("poll");
                break;
            }

            int flags = 0;
            if (myt.pfd.revents & (POLLIN | POLLPRI)) {
                flags = XL4BUS_POLL_READ;
            } else if (myt.pfd.revents & POLLOUT) {
                flags |= XL4BUS_POLL_WRITE;
            } else if (myt.pfd.revents & (POLLHUP | POLLNVAL)) {
                flags |= XL4BUS_POLL_ERR;
            }

            myt.timeout = -1;

            if (xl4bus_process_connection(conn, conn->fd, flags) != E_XL4BUS_OK) {
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

int set_poll(xl4bus_connection_t * conn, int fd, int flg) {

    my_info_t * myt = conn->custom;

    if (fd == XL4BUS_POLL_TIMEOUT_MS) {
        myt->timeout = pick_timeout(myt->timeout, flg);
        return E_XL4BUS_OK;
    }

    myt->pfd.events = 0;
    if (flg & XL4BUS_POLL_READ) {
        myt->pfd.events = POLLIN;
    }
    if (flg & XL4BUS_POLL_WRITE) {
        myt->pfd.events |= POLLOUT;
    }
    return E_XL4BUS_OK;

}

int on_message(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg) {

    printf("hooray, a message, encrypted=%d!\n", msg->uses_encryption);

    xl4bus_ll_message_t * x_msg;
    x_msg = f_malloc(sizeof(xl4bus_ll_message_t));

    x_msg->data = f_strdup("none of your business");
    x_msg->data_len = strlen(x_msg->data) + 1;
    x_msg->content_type = "application/none.your.business";

    x_msg->stream_id = msg->stream_id;
    x_msg->is_reply = 1;

    xl4bus_send_ll_message(conn, x_msg, 0, 0);

    return E_XL4BUS_OK;

}

