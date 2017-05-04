#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include <libxl4bus/low_level.h>
#include "config.h"

#define FRAME_TYPE_MASK 0x7
#define FRAME_TYPE_NORMAL 0x1
#define FRAME_TYPE_

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

    uint16_t total_read;
    uint8_t byte0;
    union {
        // connectivity test
        uint8_t ct_value[32];
        // normal frame
#pragma pack(push)
#pragma pack(1)
        union {
            struct {
                uint16_t n_stream_id;
                uint16_t n_seq;
                uint16_t n_len;
            };
            uint8_t n_body[6];
        };
#pragma pack(pop)
        // cancellation frame
        struct {
            uint16_t c_stream_id;
            uint16_t c_len;
        };
    };

} frame_t;

typedef struct connection_internal {
    chunk_t * out_queue;
    frame_t current_frame;
    dbuf_t frame_data;
} connection_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
int check_conn_io(xl4bus_connection_t*);

#endif
