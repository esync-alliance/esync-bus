#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "tests.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <signal.h>
#include "uthash.h"

int debug = 1;

typedef struct {

    int timeout;
    xl4bus_connection_t * conn;
    const char * name;
    int marker;
    int is_server;

} my_info_t;

typedef struct {

    int fd;
    my_info_t * ci;
    UT_hash_handle hh;

} my_fd_info_t;

typedef enum {

    TP_OPEN_STREAM,
    TP_WAIT_FOR_STREAM_TIMEOUT,
    TP_QUIT

} test_phase_t;

static void init_conn(xl4bus_connection_t *, my_info_t *, int, int);
static int stream_closed(struct xl4bus_connection *, uint16_t stream, xl4bus_stream_close_reason_t);
static int set_poll(xl4bus_connection_t * conn, int fd, int flg);
static int on_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg);
static void run_by_poll(struct epoll_event *);
static void run_by_timeout(uint64_t before_poll, my_info_t *);
static void alarm_reached(int sig);
static void die_in(uint64_t millis, const char *);

static int epoll_fd;
static my_fd_info_t * all_descriptors = 0;
static test_phase_t test_phase = TP_OPEN_STREAM;
static const char * alarm_reason = 0;
static my_info_t srv_conn_info;
static my_info_t clt_conn_info;

int main(int argc, char **argv) {

    xl4bus_ll_cfg_t ll_cfg;

    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = test_print_out;

    iXL4(xl4bus_init_ll(&ll_cfg), "");

    int pair[2];
    iSYS(socketpair(PF_UNIX, SOCK_STREAM, 0, pair), "");

    iSYS_M1(epoll_fd = epoll_create1(0), "");

    xl4bus_connection_t srv_conn;
    xl4bus_connection_t clt_conn;

    init_conn(&srv_conn, &srv_conn_info, pair[0], 0);
    init_conn(&clt_conn, &clt_conn_info, pair[1], 1);

    xl4bus_ll_message_t msg;
    signal(SIGALRM, alarm_reached);

    while (1) {

        if (test_phase == TP_OPEN_STREAM) {
            memset(&msg, 0, sizeof(xl4bus_ll_message_t));
            msg.data = "{}";
            msg.data_len = 3;
            msg.content_type = "application/json";
            msg.timeout_ms = 1000;
            iXL4(xl4bus_get_next_outgoing_stream(&clt_conn, &msg.stream_id), "");
            iXL4(xl4bus_send_ll_message(&clt_conn, &msg, 0, 0), "");
            test_phase = TP_WAIT_FOR_STREAM_TIMEOUT;
            // let's give us 1.1 seconds
            die_in(1100, "stream did not timeout in time");
            srv_conn_info.marker = 0;
            clt_conn_info.marker = 0;
        } else if (test_phase == TP_QUIT) {
            return 0;
        }

        struct epoll_event events[2];
        int count;
        uint64_t time_before = msvalue();
        iSYS_M1(count = epoll_wait(epoll_fd, events, 2, pick_timeout(srv_conn_info.timeout, clt_conn_info.timeout)), "");
        for (int i=0; i<count; i++) {
            run_by_poll(&events[i]);
        }
        run_by_timeout(time_before, &srv_conn_info);
        run_by_timeout(time_before, &clt_conn_info);

    }

    return 0;

}

static void run_by_timeout(uint64_t before_poll, my_info_t * ci) {

    if (ci->timeout < 0) { return; }

    uint64_t time_now = msvalue();
    if (time_now < before_poll) { return; }

    time_now -= before_poll; // that's how much elapsed.
    if (ci->timeout <= time_now) {
        // the timeout is blown
        ci->timeout = -1;
        iDBG("Processing %s by timeout", ci->name);

        xl4bus_process_connection(ci->conn, -1, 0);
    } else {
        ci->timeout -= time_now;
    }

}

static void run_by_poll(struct epoll_event *epe) {

    my_fd_info_t * fdi = epe->data.ptr;
    my_info_t * ci = fdi->ci;
    ci->timeout = -1;
    int flags = 0;
    if (epe->events & EPOLLIN) {
        flags |= XL4BUS_POLL_READ;
    }
    if (epe->events & EPOLLOUT) {
        flags |= XL4BUS_POLL_WRITE;
    }
    if (epe->events & (EPOLLERR|EPOLLHUP)) {
        flags |= XL4BUS_POLL_ERR;
    }

    iDBG("Processing %s descriptor %d, flags %x", ci->name, fdi->fd, flags);

    xl4bus_process_connection(ci->conn, fdi->fd, flags);

}

void init_conn(xl4bus_connection_t * c, my_info_t * ci, int fd, int is_client) {

    memset(c, 0, sizeof(xl4bus_connection_t));
    memset(ci, 0, sizeof(my_info_t));

    load_test_data_x509_creds(&c->identity, "timeout");

    c->on_stream_closure = stream_closed;
    c->on_message = on_message;
    c->fd = fd;
    // conn->custom = &myt.pfd;
    c->set_poll = set_poll;
    // conn->on_sent_message = on_sent_message;
    c->custom = ci;
    ci->conn = c;
    if (is_client) {
        c->is_client = 1;
        ci->name = "client";
    } else {
        ci->name = "server";
    }
    ci->is_server = !is_client;

    iXL4(xl4bus_init_connection(c), "");

}

int set_poll(xl4bus_connection_t * conn, int fd, int flg) {

    // my_info_t * myt = conn->custom;

    my_info_t * ci = conn->custom;

    if (fd == XL4BUS_POLL_TIMEOUT_MS) {

        ci->timeout = pick_timeout(ci->timeout, flg);

        iDBG("%s timeout set with %d = %d", ci->name, flg, ci->timeout);

    } else {

        iDBG("%s fd %d - set poll %x", ci->name, fd, flg);

        uint32_t new_flags = 0;
        if (flg & XL4BUS_POLL_READ) {
            new_flags |= EPOLLIN;
        }
        if (flg & XL4BUS_POLL_WRITE) {
            new_flags |= EPOLLOUT;
        }

        my_fd_info_t * fdi;
        HASH_FIND_INT(all_descriptors, &fd, fdi);

        if (!new_flags) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, (struct epoll_event *) 1);
            if (fdi) {
                HASH_DEL(all_descriptors, fdi);
                free(fdi);
            }
        } else {
            if (!fdi) {
                fdi = calloc(sizeof(my_fd_info_t), 1);
                fdi->ci = ci;
                fdi->fd = fd;
                HASH_ADD_INT(all_descriptors, fd, fdi);
            }
            struct epoll_event ee = {.events = new_flags, .data = {.ptr = fdi}};
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ee)) {
                iSYS(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ee), "");
            }
        }

    }

    return E_XL4BUS_OK;

}

int on_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    my_info_t * ci = conn->custom;

    iDBG("hooray, a message through %s.%d, encrypted=%d!",
            ci->name, msg->stream_id, msg->was_encrypted);
    msg->timeout_ms = 1000;

    return E_XL4BUS_OK;

}

int stream_closed(struct xl4bus_connection * conn, uint16_t stream, xl4bus_stream_close_reason_t reason) {

    my_info_t * ci = conn->custom;
    iDBG("Stream %s.%d closed because %d", ci->name, stream, reason);
    if (test_phase == TP_WAIT_FOR_STREAM_TIMEOUT) {
        ci->marker = 1;
        if (srv_conn_info.marker && clt_conn_info.marker) {
            die_in(0, 0);
            test_phase = TP_QUIT;
        }
    }

}

void alarm_reached(int sig) {
    iERR("Alarm reached prematurely : %s", alarm_reason);
}

void die_in(uint64_t millis, const char * reason) {

    if (getenv("NO_ALARM")) {
        return;
    }

    struct itimerval death_clock;
    memset(&death_clock, 0, sizeof(struct itimerval));
    death_clock.it_value.tv_sec = (time_t)(millis / 1000);
    death_clock.it_value.tv_usec = (time_t)((millis % 1000) * 1000);
    setitimer(ITIMER_REAL, &death_clock, 0);
    alarm_reason = reason;

}
