
#include "internal.h"

xl4bus_ll_cfg_t cfg;

int xl4bus_init_ll(xl4bus_ll_cfg_t * in_cfg) {

    memcpy(&cfg, in_cfg, sizeof(xl4bus_ll_cfg_t));
    return 0;

}


int xl4bus_init_connection(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = cfg.malloc(sizeof(connection_internal_t));
    if (!i_conn) { return E_XL4BUS_MEMORY; }

    conn->_private = i_conn;

    return check_conn_io(conn);

}
