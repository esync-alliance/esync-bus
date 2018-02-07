
#include <lib/common.h>

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <jansson.h>
#include <time.h>

#include <libxl4bus/low_level.h>

static int on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int, int);
static void on_sent_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, void * ref, int err);

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
        printf("failed to init xl4bus\n");
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

    if (connect(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        perror("connect");
        return 1;
    }

    xl4bus_identity_t my_id;
    if (load_test_x509_creds(&my_id, "ll-client", argv[0])) {
        printf("can't load test server credentials at .../pki/ll-server");
        return 1;
    }

    while (1) {

        xl4bus_connection_t * conn = malloc(sizeof(xl4bus_connection_t));
        if (!conn) {
            perror("malloc");
            return 1;
        }

        memset(conn, 0, sizeof(xl4bus_connection_t));

        memcpy(&conn->identity, &my_id, sizeof(xl4bus_identity_t));

        my_info_t myt;

        conn->on_message = on_message;
        conn->fd = fd;
        conn->custom = &myt.pfd;
        conn->set_poll = set_poll;
        conn->on_sent_message = on_sent_message;

        int err;

        memset(&myt, 0, sizeof(myt));
        myt.pfd.fd = conn->fd;

        if ((err = xl4bus_init_connection(conn)) == E_XL4BUS_OK) {

            time_t next_message = 0;
            // uint16_t stream = 0;
            int reply = 0;

            while (1) {

                struct timespec ts;

                if (clock_gettime(CLOCK_REALTIME, &ts)) {

                    perror("clock_gettime");
                    break;

                }

                if (ts.tv_sec >= next_message) {

                    xl4bus_ll_message_t msg;
                    memset(&msg, 0, sizeof(xl4bus_ll_message_t));

                    json_t * j = json_object();
                    json_object_set_new(j, "playing", json_string("hooky"));

                    msg.data = json_dumps(j, JSON_COMPACT);
                    msg.data_len = strlen(msg.data) + 1;
                    msg.content_type = "application/grass.hopper";
                    // msg.stream_id = 0;
                    // stream += 2;
                    // msg.json = (char*)json_object_get_string(j);
                    if (reply) {
                        msg.is_reply = 1;
                    } else {
                        reply = 1;
                    }

                    if ((err = xl4bus_send_ll_message(conn, &msg, 0, 0)) != E_XL4BUS_OK) {
                        printf("failed to send a message : %s\n", xl4bus_strerr(err));
                    }

                    json_decref(j);

                    // 5 second delay
                    next_message = ts.tv_sec + 5;

                }

                int timeout = pick_timeout((int) ((next_message - ts.tv_sec) * 1000), myt.timeout);

                int rc = poll(&myt.pfd, 1, timeout);
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

                if ((err = xl4bus_process_connection(conn, conn->fd, flags)) != E_XL4BUS_OK) {
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

int on_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    printf("hooray, a message, encrypted=%d!\n", msg->was_encrypted);
    return E_XL4BUS_OK;

}

void on_sent_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, void * ref, int err) {

    free((void *) msg->data);

}
