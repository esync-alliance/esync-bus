#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include "config.h"
#include "porting.h"
#include "itc.h"
#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>

#include "json-c-rename.h"
#include <json.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/asn1write.h>

#define cfg XI(cfg)
#define hash_sha256 XI(hash_sha256)
#define cert_cache_lock XI(cert_cache_lock)

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

#define KU_FLAG_ENCRYPT (1<<0)
#define KU_FLAG_SIGN (1<<1)

#define MAGIC_INIT 0xb357b0cd

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

    int err;

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

    cjose_jwk_t * private_key;
    cjose_jwk_t * remote_key;
    json_object * x5c;

    int ku_flags;

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
    /* for outgoing messages */
    MIS_VIRGIN,
    MIS_WAIT_DESTINATIONS,
    MIS_WAIT_DETAILS,
    MIS_WAIT_CONFIRM,
    /* for incoming messages */
    MIS_NEED_REMOTE
} message_info_state_t;

typedef struct remote_info {

    UT_hash_handle hh;
    // $TODO: we don't use crt after we processed incoming x5c, may
    // be we should dump it?
    mbedtls_x509_crt crt;
    char * x5t;
    cjose_jwk_t * key;
    // parsed xl4 bus addresses declared in the cert.
    xl4bus_address_t * addresses;
    int ref_count;

} remote_info_t;

typedef struct message_internal {

    message_info_state_t mis;
    int in_restart;

    union {

        // outgoing message
        struct {
            struct message_internal * next;
            struct message_internal * prev;
            xl4bus_message_t * msg;
            uint16_t stream_id;
            UT_hash_handle hh;
            json_object * addr;
            remote_info_t ** remotes;
            size_t key_count;
            size_t key_idx;
        };

        // incoming message
        struct {
            xl4bus_ll_message_t ll_msg;
        };

    };

    void * custom;

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

    int ll_timeout;

    cjose_jwk_t * private_key;

#if XL4_PROVIDE_THREADS
    void * xl4_thread_space;
    int stop;
#endif

#if XL4_SUPPORT_IPV4 && XL4_SUPPORT_IPV6
    int dual_ip;
#endif

} client_internal_t;

typedef struct validated_object {

    // these need to be cleaned up
    cjose_jws_t * exp_jws;
    json_object * bus_object;
    json_object * x5c;
    remote_info_t * remote_info;
    char * content_type;

    // these are internal, and are maintained by the ones above
    uint8_t * data;
    size_t data_len;
    cjose_header_t * p_headers;

} validated_object_t;


typedef int (*x509_lookup_t)(char * x5t, void * data, xl4bus_buf_t ** x509, cjose_jwk_t ** jwk);

extern xl4bus_ll_cfg_t cfg;
extern const mbedtls_md_info_t * hash_sha256;

#if XL4_SUPPORT_THREADS
extern void * cert_cache_lock;
#endif

/* net.c */
#define check_conn_io XI(check_conn_io)
int check_conn_io(xl4bus_connection_t*);

/* signed.c */
// $TODO: validate incoming JWS message
#define validate_jws XI(validate_jws)
#define sign_jws XI(sign_jws)
#define encrypt_jwe XI(encrypt_jwe)
#define decrypt_jwe XI(decrypt_jwe)
int validate_jws(void const * bin, size_t bin_len, int ct, xl4bus_connection_t * conn, validated_object_t * vo, char ** missing_remote);
int sign_jws(xl4bus_connection_t * conn, json_object * bus_object, const void * data, size_t data_len, char const * ct, char ** jws_data, size_t * jws_len);
int encrypt_jwe(cjose_jwk_t *, const char * x5t, const void * data, size_t data_len, char const * ct, int pad, int offset, char ** jwe_data, size_t * jwe_len);
int decrypt_jwe(void * bin, size_t bin_len, int ct, char * x5t, cjose_jwk_t * key, void ** decrypted, size_t * decrypted_len, char ** cty);

/* addr.c */

#define make_json_address XI(make_json_address)
#define build_address_list XI(build_address_list)

int make_json_address(xl4bus_address_t * addr, json_object ** json);
int build_address_list(json_object *, xl4bus_address_t **);

/* misc.c */

#define consume_dbuf XI(consume_dbuf)
#define add_to_dbuf XI(add_to_dbuf)
#define free_dbuf XI(free_dbuf)
#define cleanup_stream XI(cleanup_stream)
#define cjose_to_err XI(cjose_to_err)
#define f_asprintf XI(f_asprintf)
#define shutdown_connection_ts XI(shutdown_connection_ts)
#define mpi2jwk XI(mpi2jwk)
#define clean_keyspec XI(clean_keyspec)
#define get_oid XI(get_oid)
#define make_chr_oid XI(make_chr_oid)
#define z_strcmp XI(z_strcmp)
#define make_private_key XI(make_private_key)
#define pack_content_type XI(pack_content_type)
#define inflate_content_type XI(inflate_content_type)
#define asn1_to_json XI(asn1_to_json)
#define clean_validated_object XI(clean_validated_object)

int consume_dbuf(dbuf_t * , dbuf_t * , int);
int add_to_dbuf(dbuf_t * , void * , size_t );
void free_dbuf(dbuf_t *, int);
void cleanup_stream(connection_internal_t *, stream_t **);
int cjose_to_err(cjose_err * err);
char * f_asprintf(char * fmt, ...);
void shutdown_connection_ts(xl4bus_connection_t *);
int mpi2jwk(mbedtls_mpi *, uint8_t **, size_t *);
void clean_keyspec(cjose_jwk_rsa_keyspec *);
int get_oid(unsigned char ** p, unsigned char *, mbedtls_asn1_buf * oid);
char * make_chr_oid(mbedtls_asn1_buf *);
int z_strcmp(const char *, const char *);
int make_private_key(xl4bus_identity_t *, mbedtls_pk_context *, cjose_jwk_t **);
const char * pack_content_type(const char *);
int asn1_to_json(xl4bus_asn1_t *, json_object **);
char * inflate_content_type(char const *);
void clean_validated_object(validated_object_t * );

/* x509.c */

#define find_by_x5t XI(find_by_x5t)
#define accept_x5c XI(accept_x5c)
#define make_cert_hash XI(make_cert_hash)
#define release_remote_info XI(release_remote_info)


int make_cert_hash(void *, size_t, char **);
// finds the cjose key object for the specified tag.
remote_info_t * find_by_x5t(const char * x5t);
void release_remote_info(remote_info_t *);
int accept_x5c(json_object * x5c, xl4bus_connection_t * conn, remote_info_t **);

#endif
