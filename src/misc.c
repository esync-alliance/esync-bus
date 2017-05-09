
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

int consume_dbuf(dbuf_t * into, dbuf_t * from, int do_free) {

    // quick paths
    if (do_free) {

        int do_copy = 0;

        if (!into->len) {
            free(into->data);
            do_copy = 1;
        } else if (!into->data) {
            do_copy = 1;
        }

        if (do_copy) {
            // data is not allocated, we don't have to care about anything else.
            memcpy(into, from, sizeof(dbuf_t));
            free(from->data);
            memset(from, 0, sizeof(dbuf_t));
            return 0;
        }
    }

    size_t need_len = from->len + into->len;
    ssize_t delta = need_len - into->cap;
    if (delta > 0) {
        void * x = cfg.realloc(into->data, need_len);
        if (!x) { return 1; }
        into->data = x;
        into->cap = need_len;
    }
    memcpy(into->data + into->len, from->data, from->len);
    return 0;

}

int add_to_dbuf(dbuf_t * into, void * from, size_t from_len) {

    size_t need = from_len + into->len;
    if (need > into->cap) {
        void * aux = cfg.realloc(into->data, need);
        if (!aux) { return 1; }
        into->data = aux;
        into->cap = need;
    }
    memcpy(into->data + into->len, from, from_len);
    into->len += from_len;
    return 0;

}