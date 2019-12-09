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

#define STRINGIFY(s) #s

#if XL4_DEBUG_REFS
#define MAKE_REF_FUNCTION(name) \
    name ## _t * real_ref_ ## name(char const * file, int line, name ## _t * obj)
#define MAKE_UNREF_FUNCTION(name) \
    void real_unref_ ## name(char const * file, int line, name ## _t * obj)
#define STD_REF_FUNCTION(name) \
    if (!obj) { DBG("ref:" STRINGIFY(name) "[0]=0 %s:%d", chop_path(file), line); return 0; } \
    int new = pf_add_and_get(&obj->ref_count, 1); \
    DBG("ref:" STRINGIFY(name) "[%p]=%d %s:%d", obj, new, chop_path(file), line); \
    return obj
#define STD_UNREF_FUNCTION(name) \
    if (!obj) { DBG("unref:" STRINGIFY(name) "[0]=0 %s:%d", chop_path(file), line); return; } \
    int new_ref = pf_add_and_get(&obj->ref_count, -1); \
    DBG("unref:" STRINGIFY(name) "[%p]=%d %s:%d", obj, new_ref, chop_path(file), line); \
    if (new_ref) { return; } \
    do{}while(0)

#else
#define MAKE_REF_FUNCTION(name) \
    name ## _t * XI(ref_ ## name)(name ## _t * obj)
#define MAKE_UNREF_FUNCTION(name) \
    void XI(unref_ ## name)(name ## _t * obj)
#define STD_REF_FUNCTION(nothing) \
    if (!obj) { return 0; } \
    pf_add_and_get(&obj->ref_count, 1); \
    return obj
#define STD_UNREF_FUNCTION(nothing) \
    if (!obj) { return; } \
    if (pf_add_and_get(&obj->ref_count, -1)) { return; } \
    do{}while(0)
#endif

#define MAKE_REF_UNREF(name) \
    MAKE_REF_FUNCTION(name); \
    MAKE_UNREF_FUNCTION(name);

// Ensure correct version of mbedtls is used.
#if MBEDTLS_VERSION_NUMBER != 0x020c0000
#error MbedTLS must be of version 2.9.0, I see MBEDTLS_VERSION_NUMBER
#endif

#define cfg XI(cfg)
#define hash_sha256 XI(hash_sha256)

#if XL4_PROVIDE_PRINTF
#define vasprintf tft_vasprintf
#include "printf.h"
#endif

#define HASH_NONFATAL_OOM 1
#define uthash_malloc(c) cfg.malloc(c)
#define uthash_free(c,d) do { memset(c, 0, d); cfg.free(c); } while(0)
#include "uthash.h"
#include "utlist.h"

#define FRAME_TYPE_MASK 0x7
#define FRAME_TYPE_NORMAL 0x0
#define FRAME_TYPE_CTEST 0x1
#define FRAME_TYPE_SABORT 0x2
#define FRAME_LAST_MASK (1<<5)
#define FRAME_MSG_FIRST_MASK (1<<3)
#define FRAME_MSG_FINAL_MASK (1<<4)


#define KU_FLAG_ENCRYPT (1<<0)
#define KU_FLAG_SIGN (1<<1)

#define MAGIC_INIT 0xb357b0cd

// forward definitions

struct remote_info;

typedef struct xl4bus_global_cache {

    // I thought about this for a while - whether certificate cache should be
    // global or not. The key into this cache is sha-256 of the certificate.
    // So, there is no real danger of collisions (the certificate still needs
    // to be valid to be added to the cache, though I suppose it's possible
    // to implement some padding attack and knock another certificate out of
    // the cache, effectively DDoSing the caller that owns that knocked out
    // cert. The fix will be to parse ASN.1 as it's being read, making sure
    // that hashing stops when X.509 structure stops).
    // The only way that a credential can legitimately have the same sha-256
    // value, but has other differences - is when the chain is different. Meaning
    // that the same certificate has been validated by different chains. However,
    // the cache will only be overwritten when when the second chain is received,
    // and that second chain will need to be validated first. The connection with
    // the first chain identity will continue to be given a pass for the same
    // sha-256 tag, but I don't see this as a security problem, as all information
    // pertaining to the client still must be present in the top-level certificate,
    // which is what's hashed.
    // Alternative is to have cache per identity (so that identities with the same
    // trust anchors can share caches), but that adds burden on the user to maintain
    // those somehow, and, as stated above, doesn't provide any real additional
    // security.
    //
    // $TODO: On second thought, the certificate cache must be bound to a trust.
    // If trusts are different for connections, the certificates must not be
    // held together, since they won't authenticate against different trust

    struct remote_info * x5t_cache;

    // $TODO: The KID cache is even more controversial. The KID is based on
    // local and remote X5t values, so it's really per identity used in a client,
    // but to implement it per client is simply more tedious, especially when it comes
    // to clean up. Since using multiple identities is not a use case for us right now,
    // I'm making this a global. The work to refactor this can be not so trivial.
    struct remote_key * kid_cache;

    rb_node_t * remote_key_expiration;

#if XL4_SUPPORT_THREADS
    void * cert_cache_lock;
#endif

} global_cache_t;

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
    xl4bus_buf_t incoming_message_data;

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

        xl4bus_buf_t data;

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
    int session_key_use_ok;
    uint64_t session_key_expiration;
    cjose_jwk_t * old_session_key;
    uint64_t old_session_key_expiration;
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
} message_info_state_t;

typedef struct remote_key {

    UT_hash_handle hh;

    struct remote_info * remote_info;

    char const * from_kid;
    cjose_jwk_t * from_key;
    uint64_t from_key_expiration;

    int ref_count;

    rb_node_t rb_expiration;

} remote_key_t;

typedef struct remote_info {

    UT_hash_handle hh;

    // $TODO: we don't use crt after we processed incoming x5c, may
    // be we should dump it?
    mbedtls_x509_crt crt;

    char * x5t;

    // public key of the remote
    cjose_jwk_t * remote_public_key;

    // parsed xl4 bus addresses declared in the cert from the remote
    xl4bus_address_t * addresses;

    cjose_jwk_t * to_key;
    char const * to_kid;
    // if that time is reached, make a new key
    uint64_t to_key_expiration;
    // key can be returned unless time reaches this value
    uint64_t to_key_use_expiration;

    cjose_jwk_t * old_to_key;
    char const * old_to_kid;
    // key can be returned unless time reaches this value
    uint64_t old_to_key_use_expiration;

    int ref_count;

} remote_info_t;

/*
 * message_internal structure keeps state of a message as it's being delivered.
 * the current state of the message sending process is stored in 'mis'.
 * It's used in two cases - for outgoing messages - while the client is figuring out who
 * to encrypt the message to, and the incoming messages, when the client needs to obtain
 * a key/certificate to the message to be able to decrypt it.
 *
 * Outgoing message is registered in stream hash - so when a response is received on a stream
 * that is used to send out the message, it can be identified. They are also registered in a message list -
 * so they can be gathered up together. A message may not be in the stream hash if the
 * connection terminated. Messages are resent if client reconnects to the broker. Messages are
 * kicked out if they time out.
 *
 * Incoming messages are also registered in the message list, so they are easy to clean up
 * when needed.
 *
 * When an incoming message needs a state, it is registered with a stream hash if we need to
 * make a certificate request. The response to the certificate request comes from the broker, so when response
 * is received on the same stream, the message will be attempted to be redelivered.
 *
 * If incoming message needs a key, then it is registered with kid_hash_list (by the KID that is being
 * requested). When a response containing this KID is received, all such messages are found and attempted
 * redelivery.
 *
 */

typedef struct message_internal {

    message_info_state_t mis;
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
    int in_kid_list;
    int expired_count;
    char * needs_kid;

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

#if WITH_UNIT_TEST
    int rcv_paused;
#endif

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

    global_cache_t cache;

} client_internal_t;

typedef struct decrypt_and_verify_data {

    void const * in_data;
    size_t in_data_len;
    uint8_t in_ct;

    void const * out_data;
    size_t out_data_len;
    char const * out_ct;

    cjose_jwk_t * asymmetric_key;
    cjose_jwk_t * old_symmetric_key;
    cjose_jwk_t * new_symmetric_key;

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
    int was_new_symmetric;
    int was_verified;

    json_object * bus_object;

    remote_info_t * remote;

    char * missing_x5t;

    // items below need to be freed after result is processed, freeing this data
    // will invalidate the result, but the result may not depend on this data either
    void * x_data;
    void * x_content_type;
    cjose_jws_t * x_jws;

    xl4bus_identity_t * full_id;

    global_cache_t * cache;

} decrypt_and_verify_data_t;

#define cfg XI(cfg)
#define hash_sha256 XI(hash_sha256)

extern xl4bus_ll_cfg_t cfg;
extern const mbedtls_md_info_t * hash_sha256;

/* net.c */
#define check_conn_io XI(check_conn_io)
#if XL4_DEBUG_REFS
#define ref_stream(a) real_ref_stream(__FILE__, __LINE__, a)
#define unref_stream(a) real_unref_stream(__FILE__, __LINE__, a)
#else
#define ref_stream XI(ref_stream)
#define unref_stream XI(unref_stream)
#endif
#define release_stream XI(release_stream)

int check_conn_io(xl4bus_connection_t*);

MAKE_REF_UNREF(stream);

void release_stream(xl4bus_connection_t *, stream_t *, xl4bus_stream_close_reason_t);

/* jwx.c */
#define sign_jws XI(sign_jws)
#define encrypt_jwe XI(encrypt_jwe)
#define decrypt_jwe XI(decrypt_jwe)
#define decrypt_and_verify XI(decrypt_and_verify)
#define clean_decrypt_and_verify XI(clean_decrypt_and_verify)
#define pick_session_key XI(pick_session_key)

int sign_jws(cjose_jwk_t * key, char const * x5t, json_object * x5c, json_object * bus_object, const void * data,
        size_t data_len, char const * ct, int pad, int offset, char ** jws_data, size_t * jws_len);
int encrypt_jwe(cjose_jwk_t *, const char * x5t, json_object * bus_object, const void * data, size_t data_len, char const * ct, int pad, int offset, char ** jwe_data, size_t * jwe_len);
int decrypt_jwe(void * bin, size_t bin_len, int ct, char * x5t, cjose_jwk_t * a_key, cjose_jwk_t * s_key,
        int * is_verified, void ** decrypted, size_t * decrypted_len, char ** cty);
int decrypt_and_verify(decrypt_and_verify_data_t * dav);
void clean_decrypt_and_verify(decrypt_and_verify_data_t * dav);
cjose_jwk_t * pick_session_key(xl4bus_connection_t * conn);

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
#define free_s XI(free_s)
#define zero_s XI(zero_s)

int consume_dbuf(xl4bus_buf_t * , xl4bus_buf_t * , int);
int add_to_dbuf(xl4bus_buf_t * , void * , size_t );
void free_dbuf(xl4bus_buf_t **);
void clear_dbuf(xl4bus_buf_t *);
int cjose_to_err(cjose_err * err);
char * f_asprintf(char * fmt, ...);
void shutdown_connection_ts(xl4bus_connection_t *, char const * reason);
int mpi2jwk(mbedtls_mpi *, uint8_t **, size_t *);
void clean_keyspec(cjose_jwk_rsa_keyspec *);
int get_oid(unsigned char ** p, unsigned char *, mbedtls_asn1_buf * oid);
char * make_chr_oid(mbedtls_asn1_buf *);
int z_strcmp(const char *, const char *);
int z_strncmp(const char *, const char *, size_t);
int make_private_key(xl4bus_identity_t *, mbedtls_pk_context *, cjose_jwk_t **);
const char * deflate_content_type(const char *);
char * inflate_content_type(char const *);
int get_numeric_content_type(char const *, uint8_t *);
int asn1_to_json(xl4bus_asn1_t *, json_object **);
char const * str_content_type(int ct);
void free_s(void*, size_t);
void zero_s(void*, size_t);

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
#define find_by_kid XI(find_by_kid)
#define accept_x5c XI(accept_x5c)
#define accept_remote_x5c XI(accept_remote_x5c)

#if !XL4_DEBUG_REFS
#define unref_remote_info XI(unref_remote_info)
#define unref_remote_key XI(unref_remote_key)
#define ref_remote_info XI(ref_remote_info)
#define ref_remote_key XI(ref_remote_key)
#else
#define unref_remote_info(a) real_unref_remote_info(__FILE__, __LINE__, a)
#define unref_remote_key(a) real_unref_remote_key(__FILE__, __LINE__, a)
#define ref_remote_info(a) real_ref_remote_info(__FILE__, __LINE__, a)
#define ref_remote_key(a) real_ref_remote_key(__FILE__, __LINE__, a)
#endif

#define release_remote_key_nl XI(release_remote_key)
#define process_remote_key XI(process_remote_key)
#define base64url_hash XI(base64url_hash)
#define update_remote_symmetric_key XI(update_remote_symmetric_key)

#define address_from_cert XI(address_from_cert)

// finds the cjose key object for the specified tag.
remote_info_t * find_by_x5t(global_cache_t *, const char * x5t);
remote_key_t * find_by_kid(global_cache_t *, const char * kid);
void release_remote_key_nl(global_cache_t *, remote_key_t *);

MAKE_REF_UNREF(remote_key)
MAKE_REF_UNREF(remote_info)

int accept_x5c(global_cache_t *, json_object * x5c, mbedtls_x509_crt * trust, mbedtls_x509_crl * crl, int * ku_flags, remote_info_t **);
int accept_remote_x5c(json_object * x5c, xl4bus_connection_t * conn, remote_info_t **);
int process_remote_key(global_cache_t *, json_object*, char const * local_x5t, remote_info_t * source, char const ** kid);
int update_remote_symmetric_key(char const * local_x5t, remote_info_t * remote);

int address_from_cert(mbedtls_x509_crt * crt, xl4bus_address_t ** cert_addresses);

/**
 * Hash the specified data (SHA-256), and convert the result into base64url value.
 * Convenience method.
 * @param data data to hash
 * @param data_len length of data to hash
 * @param hash if `!0`, then the raw hash is stored in the specified buffer.
 * @param to where the result is stored
 * @return E_XL4BUS_ error code.
 */
int base64url_hash(void * data, size_t data_len, char ** to, xl4bus_buf_t * hash);

/* timeout.c */

#define schedule_stream_timeout XI(schedule_stream_timeout)
#define remove_stream_timeout XI(remove_stream_timeout)
#define release_timed_out_streams XI(release_timed_out_streams)
#define next_stream_timeout XI(next_stream_timeout)

void schedule_stream_timeout(xl4bus_connection_t * conn, stream_t * stream, unsigned);
void remove_stream_timeout(xl4bus_connection_t * conn, stream_t * stream);
void release_timed_out_streams(xl4bus_connection_t * conn);
int next_stream_timeout(xl4bus_connection_t * conn);

/* client.c */

#if XL4_DEBUG_REFS
#define ref_message_internal(a) real_ref_message_internal(__FILE__, __LINE__, a)
#define unref_message_internal(a) real_unref_message_internal(__FILE__, __LINE__, a)
#else
#define ref_message_internal XI(ref_message_internal)
#define unref_message_internal XI(unref_message_internal)
#endif

MAKE_REF_UNREF(message_internal)


#endif
