#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include "config.h"
#include "porting.h"
#include "itc.h"
#include <libxl4bus/low_level.h>

#include <json.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>

#define cfg XI(cfg)

#if XL4_PROVIDE_PRINTF
#define vasprintf tft_vasprintf
#include "printf.h"
#endif

#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c,d) cfg.free(c)
#include "uthash.h"
#include "utlist.h"

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
    // let the LL caller manage the outgoing stream IDs.
    // uint16_t stream_seq_out;

    mbedtls_x509_crt trust;
    mbedtls_x509_crt chain;
    mbedtls_x509_crl crl;

#if XL4_SUPPORT_THREADS
    int mt_read_socket;
#endif

} connection_internal_t;

typedef enum client_state {
    CS_DOWN,
    CS_RESOLVING,
    CS_CONNECTING,
    CS_EXPECTING_ALGO,
    CS_EXPECTING_CONFIRM,
    CS_RUNNING,
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

typedef enum message_info_state {
    MIS_VIRGIN,
    MIS_WAIT_DESTINATIONS,
    MIS_WAIT_DETAILS,
    MIS_WAIT_CONFIRM
} message_info_state_t;

typedef struct message_internal {

    xl4bus_message_t * msg;
    struct message_internal * next;
    struct message_internal * prev;
    uint16_t stream_id;
    UT_hash_handle hh;
    message_info_state_t mis;
    json_object * addr;
    void * custom;
    int in_hash;

} message_internal_t;

typedef struct client_internal {

    client_state_t state;

    pending_fd_t * pending;
    int pending_len;
    int pending_cap;
    ares_channel ares;

    ip_addr_t * addresses;
    int net_addr_current;
    message_internal_t * message_list;
    message_internal_t * stream_hash;

    uint16_t stream_id;

    int tcp_fd;

    char * host;
    int port;

    known_fd_t * known_fd;
    uint64_t down_target;
    xl4bus_connection_t * ll;
    int repeat_process;

#if XL4_PROVIDE_THREADS
    void * xl4_thread_space;
    int stop;
#endif

#if XL4_SUPPORT_IPV4 && XL4_SUPPORT_IPV6
    int dual_ip;
#endif

} client_internal_t;

extern xl4bus_ll_cfg_t cfg;

/* net.c */
#define check_conn_io XI(check_conn_io)
int check_conn_io(xl4bus_connection_t*);

/* secure.c */
// $TODO: validate incoming JWS message
#define validate_jws XI(validate_jws)
#define sign_jws XI(sign_jws)
int validate_jws(void * jws, size_t jws_len, int ct, uint16_t * stream_id, cjose_jws_t ** exp_jws);
int sign_jws(const void * data, size_t data_len, char const * ct, int pad, int offset, char ** jws_data, size_t * jws_len);

/* misc.c */

#define consume_dbuf XI(consume_dbuf)
#define add_to_dbuf XI(add_to_dbuf)
#define free_dbuf XI(free_dbuf)
#define cleanup_stream XI(cleanup_stream)
#define cjose_to_err XI(cjose_to_err)
#define f_asprintf XI(f_asprintf)
#define shutdown_connection_ts XI(shutdown_connection_ts)

int consume_dbuf(dbuf_t * , dbuf_t * , int);
int add_to_dbuf(dbuf_t * , void * , size_t );
void free_dbuf(dbuf_t *, int);
void cleanup_stream(connection_internal_t *, stream_t **);
int cjose_to_err(cjose_err * err);
char * f_asprintf(char * fmt, ...);
void shutdown_connection_ts(xl4bus_connection_t *);

#endif
