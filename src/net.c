
#include "internal.h"
#include "porting.h"

int check_conn_io(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    // we always want to read.
    int flags = XL4BUS_POLL_READ;

    if (i_conn->out_queue) {
        flags += XL4BUS_POLL_WRITE;
    }

    return conn->set_poll(conn, flags);

}

int xl4bus_process_connection(xl4bus_connection_t * conn, int flags) {

    int err = E_XL4BUS_OK;

    do {

        if (flags & XL4BUS_POLL_ERR) {
            // $TODO: we should read the error from the socket.
            // $TODO: report a correct error.
            err = E_XL4BUS_SYS;
            break;
        }

        connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

        if (flags & XL4BUS_POLL_WRITE) {

            while (i_conn->out_queue) {

                ssize_t res = pf_send(conn->fd, i_conn->out_queue->data, i_conn->out_queue->len);
                if (res < 0) {
                    int s_err = pf_get_errno();
                    if (s_err == EINTR) { continue; }
                    if (s_err == EWOULDBLOCK) {
                        break;
                    }
                    err = E_XL4BUS_SYS;
                    break;
                }

                if (res == i_conn->out_queue->len) {
                    cfg.free(i_conn->out_queue->data);
                    chunk_t * next = i_conn->out_queue->next;
                    cfg.free(i_conn->out_queue);
                    i_conn->out_queue = next;
                } else {
                    // res can only be less than what we attempted to write.
                    memmove(i_conn->out_queue->data, i_conn->out_queue->data + res,
                            i_conn->out_queue->len -= res);
                    // $TODO: should we shrink data memory block? reallocing
                    // is generally expensive, and we probably
                    // are not hoarding too much memory here, so let's not.
                }

            }

            if (err != E_XL4BUS_OK) { break; }

        }

        if (flags & XL4BUS_POLL_READ) {

#define RDP(when, where, len) {\
    if ((when)) {\
        size_t _len = (len); \
        while (_len) { \
            ssize_t res = pf_recv(conn->fd, where, _len); \
            if (res < 0) { \
                int x_err = pf_get_errno(); \
                if (x_err == EINTR) { continue; } \
                if (x_err == EWOULDBLOCK) { break; } \
                err = E_XL4BUS_SYS; \
                break; \
            } \
            if (!res) { \
                /* EOF is never expected */ \
                err = E_XL4BUS_EOF; \
                break; \
            } \
            /* res > 0 here */ \
            i_conn->current_frame.total_read += res; \
            _len -= res; \
        } \
        if (err != E_XL4BUS_OK) { break; } \
    } \
} \
do {} while(0)

            while (1) {
                RDP(!i_conn->current_frame.total_read, &i_conn->current_frame.byte0, 1);

            }

        }

        err = check_conn_io(conn);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (err != E_XL4BUS_OK) {
        xl4bus_shutdown_connection(conn);
    }

    return err;

}
