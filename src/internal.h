#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include <libxl4bus/low_level.h>
#include "config.h"

#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c) cfg.free(c)

#include "uthash.h"

#define FRAME_TYPE_MASK 0x7
#define FRAME_TYPE_NORMAL 0x0
#define FRAME_TYPE_CTEST 0x1
#define FRAME_TYPE_SABORT 0x2

typedef struct dbuf {
    uint8_t * data;
    size_t len;
    size_t cap;
} dbuf_t;

typedef struct chunk {
    uint8_t * data;
    size_t len;
    struct chunk * next;
} chunk_t;

typedef struct frame {

    size_t total_read;
    uint8_t byte0;
    union {
        struct {
            uint8_t len_converted;
            uint8_t len_bytes[3];
        };
        uint32_t frame_len;
    };

} frame_t;

typedef struct stream {

    UT_hash_handle hh;
    uint16_t stream_id;
    dbuf_t incoming_message;
    uint16_t next_msg_id;

} stream_t;

typedef struct connection_internal {
    chunk_t * out_queue;
    frame_t current_frame;
    dbuf_t frame_data;
} connection_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
int check_conn_io(xl4bus_connection_t*);

/* misc.c */
int consume_dbuf(dbuf_t * into, dbuf_t * from, int do_free);


#endif
