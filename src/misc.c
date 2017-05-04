
#include "internal.h"
#include "porting.h"

xl4bus_ll_cfg_t cfg;

int xl4bus_init_ll(xl4bus_ll_cfg_t * in_cfg) {
    memcpy(&cfg, in_cfg, sizeof(xl4bus_ll_cfg_t));
    return 0;
}

int xl4bus_init_connection(xl4bus_connection_t * conn) {

    int err;

    do {

        connection_internal_t * i_conn =
                cfg.malloc(sizeof(connection_internal_t));
        if (!i_conn) {
            err = E_XL4BUS_MEMORY;
            break;
        }

        conn->_private = i_conn;
        if (pf_set_nonblocking(conn->fd)) {
            err = E_XL4BUS_SYS;
            break;
        }

        err = check_conn_io(conn);

    } while(0);

    if (err != E_XL4BUS_OK) {
        xl4bus_shutdown_connection(conn);
    }

    return err;

}
