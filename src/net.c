
#include "internal.h"

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

    if (flags & XL4BUS_POLL_ERR) {
        // $TODO: we should read the error from the socket.
        xl4bus_shutdown_connection(conn);
        // $TODO: report a correct error.
        return E_XL4BUS_SYS;
    }

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    if (flags & XL4BUS_POLL_WRITE) {

        while (i_conn->out_queue) {



        }

    }

}