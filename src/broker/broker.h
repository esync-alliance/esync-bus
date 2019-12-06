#ifndef _XL4BUS_BROKER_BROKER_H_
#define _XL4BUS_BROKER_BROKER_H_

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <libxl4bus/types.h>
#include <cjose/cjose.h>

#include <mbedtls/bignum.h>
#include <mbedtls/asn1.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include "json-c-rename.h"
#include <json.h>
#include "utarray.h"
#include "uthash.h"

#include "lib/hash_list.h"

#define BCC_QUIT    1
#define BCC_MAGIC   0x8f64925e

typedef struct __attribute__((__packed__)) broker_control_command_mandatory {
    uint32_t magic;
    uint32_t cmd;
    uint32_t seq;
} broker_control_command_mandatory_t;

typedef struct __attribute__((__packed__)) broker_control_command {
    broker_control_command_mandatory_t hdr;
} broker_control_command_t;

typedef enum poll_info_type {
    PIT_INCOMING, // socket for new incoming connections
    PIT_XL4, // existing low-level connection sockets
    PIT_BCC, // socket for BCC messages
} poll_info_type_t;

typedef struct poll_info {

    poll_info_type_t type;
    int fd;
    struct conn_info * ci;

} poll_info_t;

typedef struct conn_info {

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

    struct broker_context * ctx;

} conn_info_t;

typedef struct remote_info {

    UT_hash_handle hh;
    char * x5t;
    cjose_jwk_t * remote_public_key;
    // parsed xl4 bus addresses declared in the cert.
    xl4bus_address_t * addresses;

} remote_info_t;

typedef struct {
    UT_hash_handle hh;
    const char * str;
} str_t;

typedef struct conn_info_hash_tree {

    char * key;
    UT_hash_handle hh; // key into parent's hash
    UT_array items;
    struct conn_info_hash_tree * nodes;
    struct conn_info_hash_tree * parent;

} conn_info_hash_tree_t;

typedef struct broker_context {

    int be_quiet;
    unsigned stream_timeout_ms;
    int perf_enabled;

    char * key_path;
    char ** cert_path;
    char ** ca_list;
    char * demo_pki;
    char * key_password;

    char const * argv0;
    struct sockaddr_in b_addr;
    int fd;

    int max_ev;
    int timeout;

    int use_bcc;
    char * bcc_path;
    int bcc_fd;

    poll_info_t main_pit;
    poll_info_t bcc_pit;

    int quit;

    int init_ll;

    int poll_fd;

    UT_array dm_clients;
    hash_list_t * ci_by_group;
    hash_list_t * ci_by_x5t;
    conn_info_t * connections;
    xl4bus_identity_t broker_identity;
    conn_info_hash_tree_t * ci_ua_tree;

    struct xl4bus_global_cache * g_cache;

    hash_list_t * ci_by_name;

    mbedtls_x509_crt trust;
    mbedtls_x509_crl crl;
    const mbedtls_md_info_t * hash_sha256;
    json_object * my_x5c;
    cjose_jwk_t * private_key;

#if WITH_UNIT_TEST
    xl4bus_handle_ll_message single_step;
#endif

} broker_context_t;

// e900
#define E900(ctx, a,b,c) do { if (!(ctx)->be_quiet) { e900(a, b, c); }} while(0)
void e900(char * msg, xl4bus_address_t * from, xl4bus_address_t * to);

// hash_tree

void hash_tree_add(conn_info_t *, const char * ua_name);
void hash_tree_remove(conn_info_t *);
void hash_tree_do_rec(conn_info_hash_tree_t * current, conn_info_t *, const char * full_name, const char * ua_name, int ok_more, int is_delete, UT_array * gather);
int hash_tree_maybe_delete(conn_info_hash_tree_t * current);

// gather

void gather_destinations(broker_context_t * bc, json_object * array, json_object ** x5t, UT_array * conns);
void gather_destination(broker_context_t * bc, xl4bus_address_t *, str_t ** x5t, UT_array * conns);
void finish_x5t_destinations(json_object ** x5t, str_t * strings);
void gather_all_destinations(broker_context_t * bc, xl4bus_address_t * first, UT_array * conns);

// crypto

char * make_cert_hash(broker_context_t *, void * der, size_t der_len);
int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len);
void clean_keyspec(cjose_jwk_rsa_keyspec *);
int init_x509_values(broker_context_t *);
int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to);
int make_private_key(xl4bus_identity_t * id, mbedtls_pk_context * pk, cjose_jwk_t ** jwk);
void load_pem_array(char ** file_list, xl4bus_asn1_t ***asn_list, char const *string);

// bus

int brk_on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
void on_sent_message(xl4bus_connection_t *, xl4bus_ll_message_t *, void *, int);
int set_poll(xl4bus_connection_t *, int, int);
void on_connection_shutdown(xl4bus_connection_t * conn);
int on_stream_close(struct xl4bus_connection *, uint16_t stream, xl4bus_stream_close_reason_t);

// broker

void init_broker_context(broker_context_t * c);
void release_broker_context(broker_context_t * c);
void send_presence(broker_context_t *, json_object * connected, json_object * disconnected, conn_info_t * except);
int send_json_message(conn_info_t *, const char *, json_object * body, uint16_t stream_id, int is_reply, int is_final);
void count(broker_context_t * bc, int in, int out);
int start_broker(broker_context_t * bc);
int cycle_broker(broker_context_t * bc, int);
void add_to_str_array(char *** array, char const * str);
int process_incoming_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg);
int check_remote_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, json_object ** bus_object);

#endif
