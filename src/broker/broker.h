#ifndef _XL4BUS_BROKER_BROKER_H_
#define _XL4BUS_BROKER_BROKER_H_

#include <stdint.h>
#include <sys/types.h>

#include <libxl4bus/types.h>
#include <cjose/cjose.h>

#include <mbedtls/bignum.h>
#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>

#include "json-c-rename.h"
#include "json.h"
#include "utarray.h"
#include "uthash.h"

typedef enum poll_info_type {
    PIT_INCOMING, // socket for new incoming connections
    PIT_XL4 // existing low-level connection sockets
} poll_info_type_t;

typedef struct poll_info {

    poll_info_type_t type;
    int fd;
    struct conn_info * ci;

} poll_info_t;

typedef struct conn_info {

    // struct pollfd pfd;
    int reg_req;

    int is_dm_client;
    int ua_count;
    char ** ua_names;
    int group_count;
    char ** group_names;

    int poll_modes;

    xl4bus_connection_t * conn;

    struct conn_info * next;
    struct conn_info * prev;

    poll_info_t pit;

    int ll_poll_timeout;

    json_object * remote_x5c;
    char * remote_x5t;

    int sent_x5c;

} conn_info_t;

typedef struct remote_info {

    UT_hash_handle hh;
    char * x5t;
    cjose_jwk_t * key;
    // parsed xl4 bus addresses declared in the cert.
    xl4bus_address_t * addresses;

} remote_info_t;

typedef struct {
    UT_hash_handle hh;
    const char * str;
} str_t;

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
    int data_copy; // if data to be release separately

} validated_object_t;

typedef struct conn_info_hash_tree {

    char * key;
    UT_hash_handle hh; // key into parent's hash
    UT_array items;
    struct conn_info_hash_tree * nodes;
    struct conn_info_hash_tree * parent;

} conn_info_hash_tree_t;

typedef struct conn_info_hash_list {
    UT_hash_handle hh;
    UT_array items;
    char * key;
} conn_info_hash_list_t;

extern int be_quiet;
extern UT_array dm_clients;
extern conn_info_hash_list_t * ci_by_group;
extern conn_info_t * connections;
extern int poll_fd;
extern xl4bus_identity_t broker_identity;
extern conn_info_hash_tree_t * ci_ua_tree;

// e900
#define E900(a,b,c) do { if (!be_quiet) { e900(a, b, c); }} while(0)
void e900(char * msg, xl4bus_address_t * from, xl4bus_address_t * to);

// hash_tree

void hash_tree_add(conn_info_t *, const char * ua_name);
void hash_tree_remove(conn_info_t *);
void hash_tree_do_rec(conn_info_hash_tree_t * current, conn_info_t *, const char * full_name, const char * ua_name, int ok_more, int is_delete, UT_array * gather);
int hash_tree_maybe_delete(conn_info_hash_tree_t * current);

// gather

void gather_destinations(json_object * array, json_object ** x5t, UT_array * conns);
void gather_destination(xl4bus_address_t *, str_t ** x5t, UT_array * conns);
void finish_x5t_destinations(json_object ** x5t, str_t * strings);
void gather_all_destinations(xl4bus_address_t * first, UT_array * conns);

// crypto

int validate_jws(int trusted, void const * data, size_t data_len, validated_object_t * vo);
int accept_x5c(json_object * x5c, remote_info_t ** rmi);
remote_info_t * find_by_x5t(const char * x5t);
char * make_cert_hash(void * der, size_t der_len);
int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len);
int get_oid(unsigned char **p, unsigned char *end, mbedtls_asn1_buf *oid);
char * make_chr_oid(mbedtls_asn1_buf *);
void clean_keyspec(cjose_jwk_rsa_keyspec *);
int sign_jws(conn_info_t * ci, json_object * bus_object, const void *data, size_t data_len, char const * ct, const void **jws_data, size_t *jws_len);
int init_x509_values(void);
int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to);
int make_private_key(xl4bus_identity_t * id, mbedtls_pk_context * pk, cjose_jwk_t ** jwk);
void load_pem_array(char ** file_list, xl4bus_asn1_t ***asn_list, char const *string);
int free_remote_info(remote_info_t *entry);

// bus

int brk_on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
void on_sent_message(xl4bus_connection_t *, xl4bus_ll_message_t *, void *, int);
int set_poll(xl4bus_connection_t *, int, int);
void on_connection_shutdown(xl4bus_connection_t * conn);

// main

void send_presence(json_object * connected, json_object * disconnected, conn_info_t * except);
int send_json_message(conn_info_t *, const char *, json_object * body, uint16_t stream_id, int is_reply, int is_final);
void count(int in, int out);

// inline

static inline int void_cmp_fun(void const * a, void const * b) {

    void * const * ls = a;
    void * const * rs = b;

    if ((uintptr_t)*ls > (uintptr_t)*rs) {
        return 1;
    } else if (*ls == *rs) {
        return 0;
    }
    return -1;
}

#endif
