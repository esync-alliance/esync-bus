#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include <libxl4bus/low_level.h>
#include "config.h"

typedef struct dbuf {
    uint8_t * data;
    size_t len;
    size_t cap;
} dbuf_t;

typedef struct chunk {
    uint8_t * data;
    size_t len;
    struct chunk_t * next;
} chunk_t;

typedef struct connection_internal {

    chunk_t * out_queue;

} connection_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
int check_conn_io(xl4bus_connection_t*);

#endif
