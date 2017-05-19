#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include "config.h"
#include <libxl4bus/low_level.h>

#if NEED_PRINTF
#define vasprintf tft_vasprintf
#include "printf.h"
#endif

#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c,d) cfg.free(c)

#include "uthash.h"
#include "utlist.h"

#include <json.h>

#define FRAME_TYPE_MASK 0x7
#define FRAME_TYPE_NORMAL 0x0
#define FRAME_TYPE_CTEST 0x1
#define FRAME_TYPE_SABORT 0x2
#define FRAME_LAST_MASK (1<<5)
#define FRAME_MSG_FIRST_MASK (1<<3)
#define FRAME_MSG_FINAL_MASK (1<<4)

#define CT_JOSE_COMPACT 0
#define CT_JOSE_JSON    1

typedef struct dbuf {
    uint8_t * data;
    size_t len;
    size_t cap;
} dbuf_t;

typedef struct chunk {
    uint8_t * data;
    size_t len;
    struct chunk * next;
    struct chunk * prev;
} chunk_t;

typedef struct stream {

    UT_hash_handle hh;
    uint16_t stream_id;

    int incoming_message_ct;
    dbuf_t incoming_message_data;

    int message_started;
    uint16_t frame_seq_in;
    uint16_t frame_seq_out;

    int is_final;
    int is_reply;

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
    uint16_t stream_seq_out;

} connection_internal_t;

typedef enum client_state {
    DOWN,
    RESOLVING,
    CONNECTING,
    CONNECTED
} client_state_t;

typedef struct pending_fd {
    int fd;
    int flags;
} pending_fd_t;

typedef struct known_fd {
    int fd;
    UT_hash_handle hh;
    int modes;
    int is_ll_conn;
} known_fd_t;

typedef struct ip_addr {

    int family;
    union {
        uint8_t ipv4[4];
        uint8_t ipv6[16];
    };

} ip_addr_t;

typedef struct client_internal {

    client_state_t state;

#if XL4_PROVIDE_THREADS
    void * xl4_thread_space;
#endif

    pending_fd_t * pending;
    int pending_len;
    int pending_cap;
    ares_channel ares;

    ip_addr_t * addresses;
    int net_addr_current;

    int tcp_fd;

    char * host;
    int port;

    known_fd_t * known_fd;
    uint64_t down_target;
    xl4bus_connection_t * ll;
    int repeat_process;
#if XL4_PROVIDE_IPV4 && XL4_PROVIDE_IPV6
    int dual_ip;
#endif

} client_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
int check_conn_io(xl4bus_connection_t*);

/* secure.c */
// $TODO: validate incoming JWS message
int validate_jws(void * jws, size_t jws_len, int ct, uint16_t * stream_id, cjose_jws_t ** exp_jws);
int sign_jws(const void * data, size_t data_len, int pad, int offset, char ** jws_data, size_t * jws_len);

/* misc.c */
int consume_dbuf(dbuf_t * , dbuf_t * , int);
int add_to_dbuf(dbuf_t * , void * , size_t );
void free_dbuf(dbuf_t *, int);
void cleanup_stream(connection_internal_t *, stream_t **);
int cjose_to_err(cjose_err * err);
char * f_asprintf(char * fmt, ...);

#endif
