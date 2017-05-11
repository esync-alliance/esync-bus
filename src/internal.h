#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include "config.h"
#include <libxl4bus/low_level.h>

#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c,d) cfg.free(c)

#include "uthash.h"

#define FRAME_TYPE_MASK 0x7
#define FRAME_TYPE_NORMAL 0x0
#define FRAME_TYPE_CTEST 0x1
#define FRAME_TYPE_SABORT 0x2
#define FRAME_LAST_MASK (1<<5)
#define FRAME_MSG_FIRST_MASK (1<<3)

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

typedef struct stream {

    UT_hash_handle hh;
    uint16_t stream_id;

    int incoming_message_ct;

    dbuf_t incoming_message;

    uint16_t message_started;
    uint16_t frame_seq_in;
    uint16_t frame_seq_out;

} stream_t;

typedef struct connection_internal {
    chunk_t * out_queue;

    struct {
        size_t total_read;
        uint8_t byte0;
        union {
            struct {
                uint8_t len_converted;
                uint8_t len_bytes[3];
            };
            uint32_t frame_len;
        };

        dbuf_t data;

        uint32_t crc;

    } current_frame;

    stream_t * streams;

    int pending_connection_test;
    uint8_t connection_test_request[32];
    uint64_t connectivity_test_ts;

} connection_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
int check_conn_io(xl4bus_connection_t*);

/* secure.c */
// $TODO: validate incoming JWS message
int validate_jws(uint16_t * stream_id);

/* misc.c */
int consume_dbuf(dbuf_t * , dbuf_t * , int);
int add_to_dbuf(dbuf_t * , void * , size_t );
void free_dbuf(dbuf_t *, int);
void cleanup_stream(connection_internal_t *, stream_t *);

#endif
