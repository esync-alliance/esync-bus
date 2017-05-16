
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
#include <jansson.h>

static void in_message(xl4bus_connection_t *, xl4bus_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int);

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;

#if 0
    ll_cfg.realloc = realloc;
    ll_cfg.malloc = malloc;
    ll_cfg.free = free;
#else
    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
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

    if (connect(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        perror("connect");
        return 1;
    }

    while (1) {

        xl4bus_connection_t * conn = malloc(sizeof(xl4bus_connection_t));
        if (!conn) {
            perror("malloc");
            return 1;
        }

        memset(conn, 0, sizeof(xl4bus_connection_t));

        struct pollfd pfd;

        conn->ll_message = in_message;
        conn->fd = fd;
        conn->custom = &pfd;
        conn->set_poll = set_poll;

        int err;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = conn->fd;

        if ((err = xl4bus_init_connection(conn)) == E_XL4BUS_OK) {

            xl4bus_message_t msg;
            memset(&msg, 0, sizeof(xl4bus_message_t));

            json_t * j = json_object();
            json_object_set_new(j, "playing", json_string("hooky"));

            msg.form = XL4BPF_JSON;
            msg.json = json_dumps(j, JSON_COMPACT);
            // msg.json = (char*)json_object_get_string(j);

            if ((err = xl4bus_send_message(conn, &msg, 0)) != E_XL4BUS_OK) {
                printf("failed to send a message : %s\n", xl4bus_strerr(err));
            }

            json_decref(j);
            free(msg.json);

            while (1) {

                int rc = poll(&pfd, 1, -1);
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

                if ((err = xl4bus_process_connection(conn, flags)) != E_XL4BUS_OK) {
                    printf("failed to maintain the connection : %s\n", xl4bus_strerr(err));
                    break;
                }

            }

        } else {
            printf("failed to initialize a connection : %s\n", xl4bus_strerr(err));
        }

        printf("Shutting down connection %d\n", conn->fd);
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
        free(conn);

        return 0;

    }
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

void in_message(xl4bus_connection_t * conn, xl4bus_message_t * msg) {

    printf("hooray, a message!\n");

}
