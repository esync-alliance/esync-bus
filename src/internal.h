#ifndef _XL4BUS_INTERNAL_H_
#define _XL4BUS_INTERNAL_H_

#include "config.h"
#include "porting.h"
#include "itc.h"
#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>

#include "lib/rb_tree.h"

#include "json-c-rename.h"
#include <json.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/version.h>

// Ensure correct version of mbedtls is used.
#if MBEDTLS_VERSION_NUMBER != 0x020c0000
#error MbedTLS must be of version 2.9.0, I see MBEDTLS_VERSION_NUMBER
#endif

#define cfg XI(cfg)
#define hash_sha256 XI(hash_sha256)
#define cert_cache_lock XI(cert_cache_lock)

#if XL4_PROVIDE_PRINTF
#define vasprintf tft_vasprintf
#include "printf.h"
#endif

#define HASH_NONFATAL_OOM 1
#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c,d) do { cfg.free(c); memset(c, 0, d); } while(0)
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
#define CT_APPLICATION_JSON 2
#define CT_TRUST_MESSAGE 3

#define FCT_JOSE_COMPACT "application/jose"
#define FCT_JOSE_JSON "application/jose+json"
#define FCT_APPLICATION_JSON "application/json"
#define FCT_TRUST_MESSAGE "application/vnd.xl4.busmessage-trust+json"
#define FCT_APPLICATION_OCTET_STREAM "application/octet-stream"
#define FCT_BUS_MESSAGE "application/vnd.xl4.busmessage+json"

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
    int stream_id;
    struct chunk * next;
    struct chunk * prev;
} chunk_t;

typedef struct stream {

    int ref_count;

    UT_hash_handle hh;
    uint16_t stream_id;

    int incoming_message_ct;
    dbuf_t incoming_message_data;

    int message_started;
    uint16_t frame_seq_in;
    uint16_t frame_seq_out;

    int is_final;
    int is_reply;

    uint64_t times_out_at_ms;
    rb_node_t rb_timeout;

    int released;

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

    // this hash is protected by a read lock only.
    // An alien thread may read from this hash. So the
    // alien thread must take out a read lock. However,
    // processing thread only needs to take locks when
    // making changes. This will work as long as alien
    // threads don't modify the hash.
    stream_t * streams;

    int pending_connection_test;
    uint8_t connection_test_request[32];
    uint64_t connectivity_test_ts;

    mbedtls_x509_crt trust;
    mbedtls_x509_crt chain;
    mbedtls_x509_crl crl;

    cjose_jwk_t * private_key;
    cjose_jwk_t * remote_key;
    cjose_jwk_t * session_key;
    json_object * x5c;

    int ku_flags;

    uint16_t next_stream_id;

    rb_node_t * timeout_tree;

#if XL4_SUPPORT_THREADS
    int mt_read_socket;
    void * hash_lock;
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
    MIS_NEED_REMOTE,
    MIS_WAITING_KEY,
    /* for key requests */
    MIS_EXPECTING_KEY
} message_info_state_t;

typedef struct remote_info {

    UT_hash_handle hh_x5t;
    UT_hash_handle hh_kid;

    // $TODO: we don't use crt after we processed incoming x5c, may
    // be we should dump it?
    mbedtls_x509_crt crt;

    char * x5t;

    // public key of the remote
    cjose_jwk_t * key;

    // parsed xl4 bus addresses declared in the cert from the remote
    xl4bus_address_t * addresses;

    char * to_kid;
    cjose_jwk_t * to_key;
    uint64_t to_key_expiration;

    char * from_kid;
    cjose_jwk_t * from_key;
    uint64_t from_key_expiration;

    uint8_t from_kid_prefix[256 / 8 + 256 / 8];

    int in_kid_hash;

    int ref_count;

} remote_info_t;

typedef struct message_internal {

    message_info_state_t mis;
    int in_restart;
    int ref_count;

    xl4bus_ll_message_t ll_msg;
    struct message_internal * next;
    struct message_internal * prev;
    xl4bus_message_t * msg;
    uint16_t stream_id;
    UT_hash_handle hh;
    json_object * addr;
    remote_info_t ** remotes;
    size_t key_count;
    size_t key_idx;
    int in_hash;
    int in_list;
    int expired_count;

    struct message_internal * key_wait;

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
    void * hash_lock;
    /* run_lock is used to control client start/stop when low-level connection
     * does not exist, and we can't exchange control messages yet
     */
    void * run_lock;
    int run_locked;
#endif

#if XL4_SUPPORT_IPV4 && XL4_SUPPORT_IPV6
    int dual_ip;
#endif

} client_internal_t;

typedef struct decrypt_and_verify_data {

    void const * in_data;
    size_t in_data_len;
    uint8_t in_ct;

    void const * out_data;
    size_t out_data_len;
    char const * out_ct;

    cjose_jwk_t * asymmetric_key;
    cjose_jwk_t * symmetric_key;

    cjose_key_locator asymmetric_key_locator;
    cjose_key_locator symmetric_key_locator;

    void * symmetric_locator_data;
    void * asymmetric_locator_data;

    // if set, then the remote, when verifying, must present this tag,
    // otherwise verification will fail.
    char const * remote_x5t;

    char const * my_x5t;
    mbedtls_x509_crt * trust;
    mbedtls_x509_crl * crl;
    int ku_flags;

    int was_encrypted;
    int was_symmetric;
    int was_verified;

    json_object * bus_object;

    remote_info_t * remote;

    char * missing_x5t;

    // items below need to be freed after result is processed, freeing this data
    // will invalidate the result, but the result may not depend on this data either
    void * x_data;
    void * x_content_type;
    cjose_jws_t * x_jws;

} decrypt_and_verify_data_t;

typedef int (*x509_lookup_t)(char * x5t, void * data, xl4bus_buf_t ** x509, cjose_jwk_t ** jwk);

extern xl4bus_ll_cfg_t cfg;
extern const mbedtls_md_info_t * hash_sha256;

#if XL4_SUPPORT_THREADS
extern void * cert_cache_lock;
#endif

/* net.c */
#define check_conn_io XI(check_conn_io)
#define ref_stream XI(ref_stream)
#define unref_stream XI(unref_stream)
#define release_stream XI(release_stream)

int check_conn_io(xl4bus_connection_t*);
stream_t * ref_stream(stream_t *);
void unref_stream(stream_t *);
void release_stream(xl4bus_connection_t *, stream_t *, xl4bus_stream_close_reason_t);

/* jwx.c */
#define sign_jws XI(sign_jws)
#define encrypt_jwe XI(encrypt_jwe)
#define decrypt_jwe XI(decrypt_jwe)
#define decrypt_and_verify XI(decrypt_and_verify)
#define clean_decrypt_and_verify XI(clean_decrypt_and_verify)
int sign_jws(xl4bus_connection_t * conn, json_object * bus_object, const void * data, size_t data_len, char const * ct, char ** jws_data, size_t * jws_len);
int encrypt_jwe(cjose_jwk_t *, const char * x5t, const void * data, size_t data_len, char const * ct, int pad, int offset, char ** jwe_data, size_t * jwe_len);
int decrypt_jwe(void * bin, size_t bin_len, int ct, char * x5t, cjose_jwk_t * a_key, cjose_jwk_t * s_key,
        int * is_verified, void ** decrypted, size_t * decrypted_len, char ** cty);
int decrypt_and_verify(decrypt_and_verify_data_t * dav);
void clean_decrypt_and_verify(decrypt_and_verify_data_t * dav);

/* addr.c */

#define make_json_address XI(make_json_address)
#define build_address_list XI(build_address_list)

int make_json_address(xl4bus_address_t * addr, json_object ** json);
int build_address_list(json_object *, xl4bus_address_t **);

/* misc.c */

#define consume_dbuf XI(consume_dbuf)
#define add_to_dbuf XI(add_to_dbuf)
#define free_dbuf XI(free_dbuf)
#define clear_dbuf XI(clear_dbuf)
#define cjose_to_err XI(cjose_to_err)
#define f_asprintf XI(f_asprintf)
#define shutdown_connection_ts XI(shutdown_connection_ts)
#define mpi2jwk XI(mpi2jwk)
#define clean_keyspec XI(clean_keyspec)
#define get_oid XI(get_oid)
#define make_chr_oid XI(make_chr_oid)
#define z_strcmp XI(z_strcmp)
#define make_private_key XI(make_private_key)
#define deflate_content_type XI(deflate_content_type)
#define inflate_content_type XI(inflate_content_type)
#define get_numeric_content_type XI(get_numeric_content_type)
#define asn1_to_json XI(asn1_to_json)
#define str_content_type XI(str_content_type)
#define xl4json_get_pointer XI(xl4json_get_pointer)
#define free_s XI(free_s)

int consume_dbuf(dbuf_t * , dbuf_t * , int);
int add_to_dbuf(dbuf_t * , void * , size_t );
void free_dbuf(dbuf_t **);
void clear_dbuf(dbuf_t *);
int cjose_to_err(cjose_err * err);
char * f_asprintf(char * fmt, ...);
void shutdown_connection_ts(xl4bus_connection_t *);
int mpi2jwk(mbedtls_mpi *, uint8_t **, size_t *);
void clean_keyspec(cjose_jwk_rsa_keyspec *);
int get_oid(unsigned char ** p, unsigned char *, mbedtls_asn1_buf * oid);
char * make_chr_oid(mbedtls_asn1_buf *);
int z_strcmp(const char *, const char *);
int make_private_key(xl4bus_identity_t *, mbedtls_pk_context *, cjose_jwk_t **);
const char * deflate_content_type(const char *);
char * inflate_content_type(char const *);
int get_numeric_content_type(char const *, uint8_t *);
int asn1_to_json(xl4bus_asn1_t *, json_object **);
char const * str_content_type(int ct);
int xl4json_get_pointer(json_object *, char const *, json_type, void *);
void free_s(void*, size_t);

/**
 * Helper method to create json object from a set of properties.
 * The variable parameters that follow the first argument are treated as
 * property type, including instruction on how to add the property, followed by property name,
 * and optionally followed by property value. The very last, single,
 * parameter value must be `(void*)0`. Property names are literals. Property types are literals
 * carrying special meaning described below:
 *
 * ['@'] <type char>
 *
 * The following property types are recognized:
 *
 * J - json_object *, the parameter must be a pointer to a json object. The
 *     reference count for the JSON object is not modified, however the object
 *     is attached to the structure of the returned object, which effectively
 *     moves one reference count from the invoking code to the returned object.
 *     if you need to keep the reference to the json object, call `json_object_get`
 *     on the argument.
 * M - json_object *, works almost the same way as with 'J', but, if the actual object
 *     pointer encountered in the corresponding position is 0, treats this as a memory
 *     allocation failure, causing the function to return 0. This is useful to have
 *     chained make_json_obj() calls, without explicitly doing memory checks. Can't be used with '@' prefix.
 * N - null, no value
 * B - boolean, argument is type int
 * D - number, argument is type double
 * I - number, argument is int
 * 6 - number, argument is int64_t
 * S - string, argument is char*
 * X - string, argument is char*, but the string is freed after use
 *
 * Lowercase letters can be used as well.
 *
 * A special prefix '@' can be used, in which case if the value
 * could not be created (null), then no property is added.
 *
 * Examples:
 * `make_json_obj(0, "B", "clean", 1, "S", "code", "x12", 0)` -> creates
 * new object `{"clean":true, "code":"x12"}`
 *
 * @param obj If `0`, then a new JSON object will be created, otherwise properties
 * will be added to the specified JSON object. If memory problems are detected, and the
 * existing object is provided, `0` will be returned from this function, and reference
 * count on the existing object will be dropped to avoid memory leaks in cases like:
 * `obj = make_json_obj(obj, ...)`. If you don't want the object to be released, call
 * `json_object_get()` on the first parameter, but then call `json_object_put` on the returned
 * object. This generally will work:
 * `json_object_put(obj = make_json_obj(obj, ...)`. If `0` were returned then `json_object_put` is a no-op, but
 * you will need to keep the reference to that object elsewhere, otherwise the memory will leak.
 * @param ... sequence of parameters identifying JSON object properties to add,
 * terminated with `0`.
 * @return populated object or `0` if there were memory issues creating any of the objects.
 */
json_object * xl4json_make_obj(json_object * obj, ...);

/**
 * This is analogous to ::make_json_obj, but uses `va_list` arguments instead
 * of variadic arguments.
 * @param obj json object to pass to ::make_json_obj
 * @param ap2 represents variadic arguments
 * @return populated object or `0` if there were problems creating any of the objects.
 */
json_object * xl4json_make_obj_v(json_object *obj, va_list ap2);

/* x509.c */

#define find_by_x5t XI(find_by_x5t)
#define accept_x5c XI(accept_x5c)
#define accept_remote_x5c XI(accept_remote_x5c)
#define make_cert_hash XI(make_cert_hash)
#define release_remote_info XI(release_remote_info)
#define process_remote_key XI(process_remote_key)

int make_cert_hash(void *, size_t, char **);
// finds the cjose key object for the specified tag.
remote_info_t * find_by_x5t(const char * x5t);
void release_remote_info(remote_info_t *);
int accept_x5c(json_object * x5c, char const * my_x5t, mbedtls_x509_crt * trust, mbedtls_x509_crl * crl, int * ku_flags, remote_info_t **);
int accept_remote_x5c(json_object * x5c, xl4bus_connection_t * conn, remote_info_t **);
int process_remote_key(json_object*, char const * local_x5t, remote_info_t * source);

/* timeout.h */

#define schedule_stream_timeout XI(schedule_stream_timeout)
#define remove_stream_timeout XI(remove_stream_timeout)
#define release_timed_out_streams XI(release_timed_out_streams)
#define next_stream_timeout XI(next_stream_timeout)

void schedule_stream_timeout(xl4bus_connection_t * conn, stream_t * stream, unsigned);
void remove_stream_timeout(xl4bus_connection_t * conn, stream_t * stream);
void release_timed_out_streams(xl4bus_connection_t * conn);
int next_stream_timeout(xl4bus_connection_t * conn);

#endif
