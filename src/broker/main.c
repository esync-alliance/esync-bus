
#include "lib/common.h"

#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>
#include "lib/debug.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <poll.h>
// #include <pthread.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include "json-c-rename.h"
#include "json.h"

#include <cjose/cjose.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>

#include <uthash.h>
#include <utarray.h>
#include <utlist.h>

#define REMOVE_FROM_ARRAY(array, item, msg, x...) do { \
    void * __addr = utarray_find(array, &item, void_cmp_fun); \
    if (__addr) { \
        long idx = (long)utarray_eltidx(array, __addr); \
        if (idx >= 0) { \
            utarray_erase(array, idx, 1); \
        } else {\
            DBG(msg " : index not found for array %p elt %p, addr %p", ##x, array, item, __addr); \
        } \
    } else { \
        DBG(msg " : address not found for array %p elt %p", ##x, array, item); \
    }\
} while(0)

#define UTCOUNT_WITHOUT(array, item, to) do { \
    unsigned long __a = utarray_len(array); \
    if (__a && (item)) { \
        if (utarray_find(array, &(item), void_cmp_fun)) { \
            __a--; \
        } \
    } \
    (to) = __a; \
} while(0)

#define REMOVE_FROM_HASH(root, obj, key_fld, n_len, msg, x...) do { \
    conn_info_hash_list_t * __list; \
    const char * __keyval = (obj)->key_fld; \
    size_t __keylen = strlen(__keyval) + 1; \
    HASH_FIND(hh, root, __keyval, __keylen, __list); \
    if (__list) { \
        REMOVE_FROM_ARRAY(&__list->items, obj, msg " - key %s", ##x, __keyval); \
        if (!(n_len = utarray_len(&__list->items))) { \
            utarray_done(&__list->items); \
            HASH_DEL(root, __list); \
            free(__list->key); \
            free(__list); \
        } \
    } else { \
        DBG(msg " : no entry for %s", ##x, __keyval); \
        n_len = 0; \
    } \
} while(0)

#define ADD_TO_ARRAY_ONCE(array, item) do {\
    if (!utarray_find(array, &(item), void_cmp_fun)) { \
        utarray_push_back(array, &(item)); \
        utarray_sort(array, void_cmp_fun); \
    } \
} while(0)

#define HASH_LIST_ADD(root, obj, key_fld) do { \
    conn_info_hash_list_t * __list; \
    const char * __keyval = (obj)->key_fld; \
    size_t __keylen = strlen(__keyval) + 1; \
    HASH_FIND(hh, root, __keyval, __keylen, __list); \
    if (!__list) { \
        __list = f_malloc(sizeof(conn_info_hash_list_t)); \
        __list->key = f_strdup(__keyval); \
        HASH_ADD_KEYPTR(hh, root, __list->key, __keylen, __list); \
        /* utarray_new(__list->items, &ut_ptr_icd); */ \
        utarray_init(&__list->items, &ut_ptr_icd); \
    } \
    ADD_TO_ARRAY_ONCE(&__list->items, obj); \
} while(0)

struct conn_info;

typedef enum poll_info_type {
    PIT_INCOMING, // socket for new incoming connections
    PIT_XL4 // existing low-level connection sockets
} poll_info_type_t;

typedef struct poll_info {

    poll_info_type_t type;
    int fd;
    struct conn_info * ci;

} poll_info_t;

#define MAGIC_CLIENT_MESSAGE 0xed989b71
#define MAGIC_SYS_MESSAGE 0xd6588fb0

typedef struct msg_context {

    uint32_t magic;
    union {
        struct {
            char * in_msg_id;
            xl4bus_address_t * from;
            xl4bus_address_t * to;
        };
    };

} msg_context_t;

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

    struct poll_info pit;

    int ll_poll_timeout;

    uint16_t out_stream_id;

    json_object * remote_x5c;
    char * remote_x5t;

    int sent_x5c;

} conn_info_t;

typedef struct {
    UT_hash_handle hh;
    const char * str;
} str_t;

typedef struct conn_info_hash_list {
    UT_hash_handle hh;
    UT_array items;
    char * key;
} conn_info_hash_list_t;

typedef struct conn_info_hash_tree {

    char * key;
    UT_hash_handle hh; // key into parent's hash
    UT_array items;
    struct conn_info_hash_tree * nodes;
    struct conn_info_hash_tree * parent;

} conn_info_hash_tree_t;

typedef struct remote_info {

    UT_hash_handle hh;
    char * x5t;
    cjose_jwk_t * key;
    // parsed xl4 bus addresses declared in the cert.
    xl4bus_address_t * addresses;

} remote_info_t;

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

static int on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void on_sent_message(xl4bus_connection_t *, xl4bus_ll_message_t *, void *, int);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int, int);

static void gather_destinations(json_object * array, json_object ** x5t, UT_array * conns);
static void gather_destination(xl4bus_address_t *, str_t ** x5t, UT_array * conns);
static void finish_x5t_destinations(json_object ** x5t, str_t * strings);
static void gather_all_destinations(xl4bus_address_t * first, UT_array * conns);
static void on_connection_shutdown(xl4bus_connection_t * conn);
static void send_presence(json_object * connected, json_object * disconnected, conn_info_t * except);
static int send_json_message(conn_info_t *, const char *, json_object * body, uint16_t stream_id, int is_reply, int is_final);
static int validate_jws(int trusted, void const * data, size_t data_len, validated_object_t * vo);
static int accept_x5c(json_object * x5c, remote_info_t ** rmi);
static remote_info_t * find_by_x5t(const char * x5t);
static char * make_cert_hash(void * der, size_t der_len);
static int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len);
static int get_oid(unsigned char **p, unsigned char *end, mbedtls_asn1_buf *oid);
static char * make_chr_oid(mbedtls_asn1_buf *);
static void clean_keyspec(cjose_jwk_rsa_keyspec *);
static int sign_jws(conn_info_t * ci, json_object * bus_object, const void *data, size_t data_len, char const * ct, const void **jws_data, size_t *jws_len);
static int init_x509_values(void);
static int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to);
static int make_private_key(xl4bus_identity_t * id, mbedtls_pk_context * pk, cjose_jwk_t ** jwk);
static void e900(char * msg, xl4bus_address_t * from, xl4bus_address_t * to);
static void free_message_context(msg_context_t *);
static void hash_tree_add(conn_info_t *, const char * ua_name);
static void hash_tree_remove(conn_info_t *);
static void hash_tree_do_rec(conn_info_hash_tree_t * current, conn_info_t *, const char * full_name, const char * ua_name, int ok_more, int is_delete, UT_array * gather);
static int hash_tree_maybe_delete(conn_info_hash_tree_t * current);
static void count(int in, int out);
static void help(void);
static void load_pem_array(char ** file_list, xl4bus_asn1_t ***asn_list, char const *string);


int debug = 0;

static conn_info_hash_list_t * ci_by_name2 = 0;
static conn_info_hash_tree_t * ci_ua_tree = 0;
static conn_info_hash_list_t * ci_by_group = 0;
static conn_info_hash_list_t * ci_by_x5t = 0;
static UT_array dm_clients;
static int poll_fd;
static conn_info_t * connections;

static xl4bus_identity_t broker_identity;
static mbedtls_x509_crt trust;
static mbedtls_x509_crl crl;
static remote_info_t * tag_cache = 0;
static char * my_x5t;
static json_object * my_x5c;
static cjose_jwk_t * private_key;

static const mbedtls_md_info_t * hash_sha256;

static struct {
    int enabled;
    time_t second;
    int in;
    int out;
} perf = {
        .enabled = 0,
        .second = 0
};

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


void help() {

    printf("%s",
"-h\n"
"   print this text (no other options can be used with -h)\n"
"-k <path>\n"
"   specify private key file (PEM format) to use\n"
"-K <text>\n"
"   specify private key file password, if needed\n"
"-c <path>\n"
"   certificate to use (PEM format), specify multiple times for a chain\n"
"-t <path>\n"
"   trust anchor to use (PEM format), \n"
"   specify multiple times for multiple anchors\n"
"-D <dir>\n"
"   use demo PKI directory layout, \n"
"   reading credentials from specified directory in ../pki\n"
"   The current directory id determined by the location of this binary\n"
"-d\n"
"   turn on debugging output\n"
"-p\n"
"   turn on performance output\n"
    );
    _exit(1);

}

static void add_to_str_array(char *** array, char * str) {

    if (!*array) {
        *array = f_malloc(sizeof(void*) * 2);
        *array[0] = f_strdup(str);
    } else {

    }

}

static size_t str_array_len(char ** array) {

    char ** i;
    for (i = array; *i; i++);
    return (size_t)(i - array);

}

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;
    int c;

    MSG("xl4-broker %s", xl4bus_version());
    MSG("Use -h to see help options");

    char * key_path = 0;
    char ** cert_path = 0;
    char ** ca_list = 0;
    char * demo_pki = 0;
    char * key_password = 0;

    while ((c = getopt(argc, argv, "hk:K:c:t:D:dp")) != -1) {

        switch (c) {

            case 'h':
                help();
                break;
            case 'k':
                if (key_path) {
                    FATAL("Key can only be specified once");
                }
                key_path = f_strdup(optarg);
                break;
            case 'K':
                key_password = f_strdup(optarg);
                secure_bzero(optarg, strlen(optarg));
                *optarg = '*';
                break;
            case 'c':
                add_to_str_array(&cert_path, optarg);
                break;
            case 't':
                add_to_str_array(&ca_list, optarg);
                break;
            case 'D':
                if (demo_pki) {
                    FATAL("demo PKI label dir can only be specified once");
                }
                demo_pki = f_strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'p':
                perf.enabled = 1;
                break;

            default: help(); break;

        }

    }


#if 0
    ll_cfg.realloc = realloc;
    ll_cfg.malloc = malloc;
    ll_cfg.free = free;
#else
    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    if (debug) {
        ll_cfg.debug_f = print_out;
    }
#endif

    if (demo_pki && (key_path || ca_list || cert_path)) {
        FATAL("Demo PKI label can not be used with X.509 identity parameters");
    }

    if (xl4bus_init_ll(&ll_cfg)) {
        FATAL("failed to initialize xl4bus");
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in b_addr;
    memset(&b_addr, 0, sizeof(b_addr));
    b_addr.sin_family = AF_INET;
    b_addr.sin_port = htons(9133);
    b_addr.sin_addr.s_addr = INADDR_ANY;

    memset(&broker_identity, 0, sizeof(broker_identity));

    if (demo_pki) {
        load_test_x509_creds(&broker_identity, demo_pki, argv[0]);
        free(demo_pki);
    } else {

        broker_identity.type = XL4BIT_X509;

        if (key_path) {
            if (!(broker_identity.x509.private_key = load_pem(key_path))) {
                ERR("Key file %s could not be loaded", key_path);
            }
            free(key_path);
        } else {
            ERR("No key file specified");
        }

        if (ca_list) {
            load_pem_array(ca_list, &broker_identity.x509.trust, "trust");
            free(ca_list);
        } else {
            ERR("No trust anchors specified");
        }

        if (cert_path) {
            load_pem_array(cert_path, &broker_identity.x509.chain, "certificate");
            free(cert_path);
        } else {
            ERR("No certificate/certificate chain specified");
        }

        if (key_password) {
            broker_identity.x509.custom = key_password;
            broker_identity.x509.password = simple_password_input;
        } else if (key_path) {
            // $TODO: Using console_password_input ATM is a bad idea
            // because it will ask the password every time it's needed.
            broker_identity.x509.password = console_password_input;
            broker_identity.x509.custom = f_strdup(key_path);
        }

    }

    if (!(hash_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256))) {
        FATAL("Can not find SHA-256 hash implementation");
    }

    if (init_x509_values() != E_XL4BUS_OK) {
        FATAL("Failed to initialize X.509 values");
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        ERR_SYS("setsockopt(SO_REUSEADDR)");
    }

    utarray_init(&dm_clients, &ut_ptr_icd);

    if (bind(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        FATAL_SYS("Can't bind listening socket");
    }

    if (listen(fd, 5)) {
        FATAL_SYS("Can't set up TCP listen queue");
    }

    if (set_nonblocking(fd)) {
        FATAL_SYS("Can't set non-blocking socket mode");
    }

    poll_fd = epoll_create1(0);
    if (poll_fd < 0) {
        FATAL_SYS("Can't create epoll socket");
    }

    poll_info_t main_pit = {
            .type = PIT_INCOMING,
            .fd = fd
    };

    struct epoll_event ev;
    ev.events = POLLIN;
    ev.data.ptr = &main_pit;

    if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd, &ev)) {
        FATAL_SYS("epoll_ctl() failed");
    }

    int max_ev = 1;
    int timeout = -1;

    while (1) {

        struct epoll_event rev[max_ev];
        uint64_t before = 0;

        if (timeout >= 0) {
            before = msvalue();
        }
        int ec = epoll_wait(poll_fd, rev, max_ev, timeout);
        if (timeout >= 0) {
            before = msvalue() - before;
            if (timeout > before) {
                timeout -= before;
            } else {
                timeout = 0;
            }
        }
        if (ec < 0) {
            if (errno == EINTR) { continue; }
            FATAL_SYS("epoll_wait() failed");
        }

        if (ec == max_ev) { max_ev++; }

        for (int i=0; i<ec; i++) {

            poll_info_t * pit = rev[i].data.ptr;
            if (pit->type == PIT_INCOMING) {

                if (rev[i].events & POLLERR) {
                    get_socket_error(pit->fd);
                    FATAL_SYS("Connection socket error");
                }

                if (rev[i].events & POLLIN) {

                    socklen_t b_addr_len = sizeof(b_addr);
                    int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
                    if (fd2 < 0) {
                        FATAL_SYS("accept() failed");
                    }

                    xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));
                    conn_info_t * ci = f_malloc(sizeof(conn_info_t));

                    conn->on_message = on_message;
                    conn->on_sent_message = on_sent_message;
                    conn->fd = fd2;
                    conn->set_poll = set_poll;

                    memcpy(&conn->identity, &broker_identity, sizeof(broker_identity));

                    conn->custom = ci;
                    ci->conn = conn;
                    ci->pit.ci = ci;
                    ci->pit.type = PIT_XL4;
                    ci->pit.fd = fd2;
                    ci->out_stream_id = 1;

                    // DBG("Created connection %p/%p fd %d", ci, ci->conn, fd2);

                    int err = xl4bus_init_connection(conn);

                    if (err == E_XL4BUS_OK) {

                        conn->on_shutdown = on_connection_shutdown;

                        DL_APPEND(connections, ci);

                        // send initial message - alg-supported
                        // https://gitlab.excelfore.com/schema/json/xl4bus/alg-supported.json
                        json_object *aux;
                        json_object *body = json_object_new_object();

                        json_object_object_add(body, "signature", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RS256"));
                        json_object_object_add(body, "encryption-key", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RSA-OAEP"));
                        json_object_object_add(body, "encryption-alg", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("A128CBC-HS256"));

                        err = send_json_message(ci, "xl4bus.alg-supported", body, ci->out_stream_id+=2, 0, 0);
                        timeout = pick_timeout(timeout, ci->ll_poll_timeout);
                        DBG("timeout adjusted to %d (new conn %p)", timeout, ci);

                        if (err == E_XL4BUS_OK) {
                            int s_err;
                            if ((s_err = xl4bus_process_connection(conn, -1, 0)) == E_XL4BUS_OK) {
                            } else {
                                DBG("xl4bus process (initial) returned %d", s_err);
                            }
                        }

                    } else {
                        free(ci);
                        free(conn);
                    }

                }

            } else if (pit->type == PIT_XL4) {

                conn_info_t * ci = pit->ci;
                int flags = 0;
                if (rev[i].events & POLLIN) {
                    flags |= XL4BUS_POLL_READ;
                }
                if (rev[i].events & POLLOUT) {
                    flags |= XL4BUS_POLL_WRITE;
                }
                if (rev[i].events & (POLLERR|POLLNVAL|POLLHUP)) {
                    flags |= XL4BUS_POLL_ERR;
                }

                int s_err;
                if ((s_err = xl4bus_process_connection(ci->conn, pit->fd, flags)) == E_XL4BUS_OK) {
                    timeout = pick_timeout(timeout, ci->ll_poll_timeout);
                    DBG("timeout adjusted to %d (exist conn %p)", timeout, ci);
                } else {
                    DBG("xl4bus process (fd up route) returned %d", s_err);
                }

            } else {
                DBG("PIT type %d?", pit->type);
                return 1;
            }

        }

        if (!timeout) {

            timeout = -1;

            conn_info_t * aux;
            conn_info_t * ci;

            DL_FOREACH_SAFE(connections, ci, aux) {
                int s_err;
                ci->ll_poll_timeout = -1;
                if ((s_err = xl4bus_process_connection(ci->conn, -1, 0)) == E_XL4BUS_OK) {
                    timeout = pick_timeout(timeout, ci->ll_poll_timeout);
                    DBG("timeout adjusted to %d (exist conn %p), timeout route", timeout, ci);
                } else {
                    DBG("xl4bus process (timeout route) returned %d", s_err);
                }
            }

        }

    }

}

void load_pem_array(char ** file_list, xl4bus_asn1_t ***asn_list, char const * f_type) {

    size_t cnt = str_array_len(file_list) + 1;
    *asn_list = f_malloc(cnt * sizeof(void*));
    int i = 0, j = 0;
    for (;i<cnt; i++) {
        if (!file_list[i]) {
            (*asn_list)[j] = 0;
            break;
        }
        if (!((*asn_list)[j] = load_pem(file_list[i]))) {
            ERR("Problem loading %s file %s", f_type, file_list[i]);
        }
        free(file_list[i]);
        j++;

    }

}

int set_poll(xl4bus_connection_t * conn, int fd, int flg) {

    conn_info_t * ci = conn->custom;

    if (fd == XL4BUS_POLL_TIMEOUT_MS) {
        ci->ll_poll_timeout = pick_timeout(ci->ll_poll_timeout, flg);
        return E_XL4BUS_OK;
    }

    // $TODO: because we use non-mt only, fd is bound to
    // only be fd for the network connection. However, there is
    // no promise it is, which means that conn_info must support
    // multiple poll_info entries.

    uint32_t need_flg = 0;
    if (flg & XL4BUS_POLL_WRITE) {
        need_flg |= POLLOUT;
    }
    if (flg & XL4BUS_POLL_READ) {
        need_flg |= POLLIN;
    }

    if (ci->poll_modes != need_flg) {

        int rc;

        if (need_flg) {
            struct epoll_event ev = {
                    .events = need_flg,
                    .data = { .ptr =  &ci->pit }
            };

            if (ci->poll_modes) {
                rc = epoll_ctl(poll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
            } else {
                rc = epoll_ctl(poll_fd, EPOLL_CTL_ADD, conn->fd, &ev);
            }

        } else {
            if (ci->poll_modes) {
                rc = epoll_ctl(poll_fd, EPOLL_CTL_DEL, conn->fd, (struct epoll_event *) 1);
            } else {
                rc = 0;
            }
        }

        if (rc) { return E_XL4BUS_SYS; }
        ci->poll_modes = need_flg;

    }

    return E_XL4BUS_OK;

}

int on_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int err /* = E_XL4BUS_OK */;
    json_object * root = 0;
    conn_info_t * ci = conn->custom;
    json_object * connected = 0;
    validated_object_t vot;
    xl4bus_address_t * forward_to = 0;
    xl4bus_identity_t id;
    cjose_err c_err;
    char * in_msg_id = 0;
    int trusted = 0;
    UT_array send_list;

    utarray_init(&send_list, &ut_ptr_icd);
    memset(&vot, 0, sizeof(vot));
    memset(&id, 0, sizeof(id));

    do {

        // all incoming messages must pass JWS validation, and hence must be JWS messages.
        // note, since validate_jws only supports compact serialization, we only expect compact serialization here.

#if XL4_DISABLE_JWS

        if (!z_strcmp(msg->content_type, "application/vnd.xl4.busmessage-trust+json")) {
            trusted = 1;
        } else {
#endif

        BOLT_IF(z_strcmp(msg->content_type, "application/jose"), E_XL4BUS_DATA,
                "JWS compact message required, got %s", NULL_STR(msg->content_type));

#if XL4_DISABLE_JWS
        }
#endif

        BOLT_SUB(validate_jws(trusted, msg->data, msg->data_len, &vot));

        BOLT_IF(ci->remote_x5t && z_strcmp(ci->remote_x5t, vot.remote_info->x5t),
                E_XL4BUS_DATA, "Switching remote identities is not supported");

        DBG("Incoming BUS object: %s", json_object_get_string(vot.bus_object));

        if (vot.x5c) {

            id.type = XL4BIT_X509;

            int certs = json_object_array_length(vot.x5c);

            id.x509.chain = f_malloc(sizeof(void*) * (certs+1));

            for (int i=0; i<certs; i++) {
                id.x509.chain[i] = f_malloc(sizeof(xl4bus_asn1_t));
                id.x509.chain[i]->enc = XL4BUS_ASN1ENC_DER;
                const char * in = json_object_get_string(json_object_array_get_idx(vot.x5c, i));
                size_t in_len = strlen(in);
                BOLT_CJOSE(cjose_base64_decode(in, in_len, &id.x509.chain[i]->buf.data, &id.x509.chain[i]->buf.len, &c_err));
            }

            BOLT_NEST();

            BOLT_SUB(xl4bus_set_remote_identity(conn, &id));

        }

        if (!ci->remote_x5c && conn->remote_x5c) {
            ci->remote_x5c = json_tokener_parse(conn->remote_x5c);
        }

        if (!ci->remote_x5t && conn->remote_x5t) {
            // we must copy x5t, since we need it when we deallocate
            // things, at which point it would be cleaned up already
            ci->remote_x5t = f_strdup(conn->remote_x5t);
        }

        BOLT_IF(!ci->remote_x5c || !ci->remote_x5t, E_XL4BUS_DATA, "Remote identity is not fully established");

        DBG("Incoming message content type %s", vot.content_type);

        if (!strcmp("application/vnd.xl4.busmessage+json", vot.content_type)) {

            // the json must be ASCIIZ.
            BOLT_IF((vot.data_len == 0) || vot.data[vot.data_len - 1], E_XL4BUS_CLIENT,
                    "Incoming message is not ASCIIZ");

            BOLT_IF(!(root = json_tokener_parse((const char*)vot.data)),
                    E_XL4BUS_CLIENT, "Not valid json: %s", vot.data);

            json_object *aux;
            BOLT_IF(!json_object_object_get_ex(root, "type", &aux) || !json_object_is_type(aux, json_type_string),
                    E_XL4BUS_CLIENT, "No/non-string type property in %s", vot.data);

            const char *type = json_object_get_string(aux);

            DBG("LLP message type %s", type);

            if (!strcmp(type, "xl4bus.registration-request")) {

                BOLT_IF(ci->reg_req, E_XL4BUS_CLIENT, "already registered");
                ci->reg_req = 1;

                BOLT_MEM(connected = json_object_new_array());

                for (xl4bus_address_t *r_addr = conn->remote_address_list; r_addr; r_addr = r_addr->next) {

                    if (r_addr->type == XL4BAT_GROUP) {

                        ci->group_names = f_realloc(ci->group_names, sizeof(char *) * (ci->group_count + 1));
                        ci->group_names[ci->group_count] = f_strdup(r_addr->group);
                        HASH_LIST_ADD(ci_by_group, ci, group_names[ci->group_count]);
                        ci->group_count++;

                        json_object *cel;
                        json_object *sel;
                        BOLT_MEM(cel = json_object_new_object());
                        json_object_array_add(connected, cel);
                        BOLT_MEM(sel = json_object_new_string(r_addr->group));
                        json_object_object_add(cel, "group", sel);

                    } else if (r_addr->type == XL4BAT_SPECIAL) {

                        if (r_addr->special == XL4BAS_DM_CLIENT) {

                            ci->is_dm_client = 1;

                            ADD_TO_ARRAY_ONCE(&dm_clients, ci);

                            json_object *cel = json_object_new_object();
                            json_object_object_add(cel, "special", json_object_new_string("dmclient"));
                            json_object_array_add(connected, cel);

                        }

                    } else if (r_addr->type == XL4BAT_UPDATE_AGENT) {

                        // $TODO: If the update agent address is too long, this becomes
                        // a silent failure. May be this should be detected?
                        hash_tree_add(ci, r_addr->update_agent);
                        HASH_LIST_ADD(ci_by_name2, ci, ua_names[ci->ua_count]);

                        ci->ua_count++;

                        json_object *cel;
                        json_object *sel;
                        BOLT_MEM(cel = json_object_new_object());
                        json_object_array_add(connected, cel);
                        BOLT_MEM(sel = json_object_new_string(r_addr->update_agent));
                        json_object_object_add(cel, "update-agent", sel);

                    }

                }

                BOLT_NEST();

                HASH_LIST_ADD(ci_by_x5t, ci, remote_x5t);

                // send current presence
                // https://gitlab.excelfore.com/schema/json/xl4bus/presence.json
                json_object *body;
                BOLT_MEM(body = json_object_new_object());

                {
                    json_object *bux;
                    BOLT_MEM(bux = json_object_new_array());
                    json_object_object_add(body, "connected", bux);

                    unsigned long lc;

                    UTCOUNT_WITHOUT(&dm_clients, ci, lc);

                    if (lc) {
                        json_object *cux;
                        BOLT_MEM(cux = json_object_new_object());
                        json_object_array_add(bux, cux);
                        json_object *dux;
                        BOLT_MEM(dux = json_object_new_string("dmclient"));
                        json_object_object_add(cux, "special", dux);
                    }

                    conn_info_hash_list_t *tmp;
                    conn_info_hash_list_t *cti;

                    HASH_ITER(hh, ci_by_name2, cti, tmp) {
                        UTCOUNT_WITHOUT(&cti->items, ci, lc);
                        if (lc > 0) {
                            json_object *cux;
                            BOLT_MEM(cux = json_object_new_object());
                            json_object_array_add(bux, cux);
                            json_object *dux;
                            BOLT_MEM(dux = json_object_new_string(cti->hh.key));
                            json_object_object_add(cux, "update-agent", dux);
                        }
                    }

                    BOLT_NEST();

                    HASH_ITER(hh, ci_by_group, cti, tmp) {
                        UTCOUNT_WITHOUT(&cti->items, ci, lc);
                        if (lc > 0) {
                            json_object *cux;
                            BOLT_MEM(cux = json_object_new_object());
                            json_object_array_add(bux, cux);
                            json_object *dux;
                            BOLT_MEM(dux = json_object_new_string(cti->hh.key));
                            json_object_object_add(cux, "group", dux);
                        }
                    }

                    BOLT_NEST();

                }

                if ((err = send_json_message(ci, "xl4bus.presence", body, msg->stream_id, 1, 1)) != E_XL4BUS_OK) {
                    ERR("failed to send a message : %s", xl4bus_strerr(err));
                    xl4bus_shutdown_connection(conn);
                } else {
                    // tell everybody else this client arrived.
                    if (json_object_array_length(connected)) {
                        send_presence(connected, 0, ci);
                        connected = 0; // connected is consumed
                    }

                }

                break;

            } else if (!strcmp("xl4bus.request-destinations", type)) {

                // https://gitlab.excelfore.com/schema/json/xl4bus/request-destinations.json

                json_object *x5t = 0;
                char const * req_dest = "(NONE)";

                if (json_object_object_get_ex(root, "body", &aux) && json_object_is_type(aux, json_type_object)) {
                    json_object *array;
                    if (json_object_object_get_ex(aux, "destinations", &array)) {
                        req_dest = json_object_get_string(array);
                        gather_destinations(array, &x5t, 0);
                    }
                }

                // send destination list
                // https://gitlab.excelfore.com/schema/json/xl4bus/destination-info.json
                json_object *body = json_object_new_object();
                if (x5t) {
                    json_object_object_add(body, "x5t#S256", x5t);
                }

                int has_dest = x5t && (json_object_array_length(x5t) > 0);

                send_json_message(ci, "xl4bus.destination-info", body, msg->stream_id, 1, !has_dest);

                if (!has_dest) {
                    e900(f_asprintf("%p-%04x has no viable destinations for %s", conn, msg->stream_id, req_dest), conn->remote_address_list, 0);
                }

                break;

            } else if (!strcmp("xl4bus.request-cert", type)) {

                json_object * x5c = json_object_new_array();

                if (json_object_object_get_ex(root, "body", &aux) && json_object_is_type(aux, json_type_object)) {
                    json_object *array;
                    if (json_object_object_get_ex(aux, "x5t#S256", &array) &&
                            json_object_is_type(array, json_type_array)) {

                        int l = json_object_array_length(array);
                        for (int i=0; i<l; i++) {

                            json_object * x5t_json = json_object_array_get_idx(array, i);
                            if (!json_object_is_type(x5t_json, json_type_string)) { continue; }

                            const char * x5t = json_object_get_string(x5t_json);

                            UT_array * send_list = 0;

                            conn_info_hash_list_t * val;
                            HASH_FIND(hh, ci_by_x5t, x5t, strlen(x5t)+1, val);
                            if (val) {
                                send_list = &val->items;
                            }

                            if (!send_list) { continue; }

                            int l2 = utarray_len(send_list);

                            // because these must be the same x5t, we only need
                            // to send out one x5c, because they all must be the same

                            if (l2 > 1) { l2 = 1; }

                            for (int j=0; j<l2; j++) {

                                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(send_list, j);
                                if (ci2->remote_x5c) {
                                    json_object_array_add(x5c, json_object_get(ci2->remote_x5c));
                                }

                            }

                        }

                    }
                }

                json_object * body = json_object_new_object();
                json_object_object_add(body, "x5c", x5c);
                send_json_message(ci, "xl4bus.cert-details", body, msg->stream_id, 1, 0);

                break;

            } else if (!strcmp("xl4bus.message-confirm", type)) {
                // do nothing, it's the client telling us it's OK.

                e900(f_asprintf("Confirmed receipt of %p-%04x", conn, msg->stream_id), conn->remote_address_list, 0);

                BOLT_IF(!msg->is_final, E_XL4BUS_CLIENT, "Message confirmation must be final");
                break;
            }

            BOLT_SAY(E_XL4BUS_CLIENT, "Don't know what to do with XL4 message type %s", type);

        } else {

            json_object * destinations;

            uint16_t stream_id = msg->stream_id;

            in_msg_id = f_asprintf("%p-%04x", conn, (unsigned int)stream_id);

            if (!json_object_object_get_ex(vot.bus_object, "destinations", &destinations)) {
                e900(f_asprintf("Rejected message %s - no destinations", in_msg_id), conn->remote_address_list, 0);
                BOLT_SAY(E_XL4BUS_DATA, "Not XL4 message, no destinations in bus object");
            }

            BOLT_SUB(xl4bus_json_to_address(json_object_get_string(destinations), &forward_to));

            gather_all_destinations(forward_to, &send_list);

            int l = utarray_len(&send_list);

            DBG("Received application message, has %d send list elements", l);

            e900(f_asprintf("Incoming message %s", in_msg_id), conn->remote_address_list, forward_to);

            count(1, 0);

            int sent_to_any = 0;

            for (int i=0; i<l; i++) {
                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(&send_list, i);
                if (ci2 == ci) {
                    DBG("Ignored one sender - loopback");
                    // prevent loopback
                    continue;
                }

                sent_to_any = 1;

                // the message is not final, the other side may return a certificate request.
                msg->is_final = 0;
                msg->is_reply = 0;
                msg->stream_id = ci2->out_stream_id+=2;

                count(0, 1);

                // note: we are sending data that is inside the incoming message.
                // this only works so far because we are not using multi-threading
                // but eventually we should not do that, nor use incoming message
                // structure for anything.

                msg_context_t * ctx = 0;

                do {

                    ctx = f_malloc(sizeof(msg_context_t));

                    ctx->magic = MAGIC_CLIENT_MESSAGE;
                    // $TODO: we should respond to failures
                    BOLT_SUB(xl4bus_copy_address(conn->remote_address_list, 1, &ctx->from));
                    BOLT_SUB(xl4bus_copy_address(forward_to, 1, &ctx->to));
                    BOLT_MEM(ctx->in_msg_id = f_strdup(in_msg_id));

                    int sub_err = xl4bus_send_ll_message(ci2->conn, msg, ctx, 0);

                    if (sub_err) {
                        // printf("failed to send a message : %s\n", xl4bus_strerr(err));
                        e900(f_asprintf("Failed to send message %s as %p-%04x: %s", in_msg_id, ci2->conn,
                                (unsigned int)msg->stream_id, xl4bus_strerr(sub_err)),
                                conn->remote_address_list, forward_to);
                        xl4bus_shutdown_connection(ci2->conn);
                        i--;
                        l--;
                    }

                    // ESYNC-1345 - the on_sent_message is always called in m/t model.
                    // so the context will be cleaned up in callback.

                } while (0);

            }

            if (!sent_to_any) {
                e900(f_asprintf("Message %s perished - no effective destinations", in_msg_id),
                        conn->remote_address_list, forward_to);
            }

            send_json_message(ci, "xl4bus.message-confirm", 0, stream_id, 1, 1);

        }

    } while (0);

    for (xl4bus_asn1_t ** asn1 = id.x509.chain; asn1 && *asn1; asn1++) {
        free((*asn1)->buf.data);
        free(*asn1);
    }
    free(id.x509.chain);

    utarray_done(&send_list);

    json_object_put(root);
    json_object_put(connected);
    xl4bus_free_address(forward_to, 1);

    cjose_jws_release(vot.exp_jws);
    json_object_put(vot.bus_object);
    json_object_put(vot.x5c);
    free(vot.content_type);
    if (vot.data_copy) {
        free(vot.data);
    }
    free(in_msg_id);

    return err;

}

void on_connection_shutdown(xl4bus_connection_t * conn) {

    conn_info_t * ci = conn->custom;

    DL_DELETE(connections, ci);

    DBG("Shutting down connection %p/%p fd %d", ci, ci->conn, ci->conn->fd);

    shutdown(ci->conn->fd, SHUT_RDWR);
    close(ci->conn->fd);

    json_object * disconnected = json_object_new_array();

    if (ci->is_dm_client) {
        REMOVE_FROM_ARRAY(&dm_clients, ci, "Removing CI from DM Client list");
        if (!utarray_len(&dm_clients)) {
            // no more dmclients :(
            json_object * bux = json_object_new_object();
            json_object_object_add(bux, "special", json_object_new_string("dmclient"));
            json_object_array_add(disconnected, bux);
        }
    }

    hash_tree_remove(ci);

    for (int i=0; i< ci->ua_count; i++) {
        int n_len;
        REMOVE_FROM_HASH(ci_by_name2, ci, ua_names[i], n_len, "Removing by UA name");
        if (!n_len) {
            json_object * bux = json_object_new_object();
            json_object_object_add(bux, "update-agent", json_object_new_string(ci->ua_names[i]));
            json_object_array_add(disconnected, bux);
        }

        free(ci->ua_names[i]);
    }

    for (int i=0; i<ci->group_count; i++) {
        int n_len;
        REMOVE_FROM_HASH(ci_by_group, ci, group_names[i], n_len, "Removing by group name");

        if (!n_len) {
            json_object * bux = json_object_new_object();
            json_object_object_add(bux, "group", json_object_new_string(ci->group_names[i]));
            json_object_array_add(disconnected, bux);
        }

        free(ci->group_names[i]);

    }

    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
        int n_len;
#pragma clang diagnostic pop
        if (ci->remote_x5t) {
            REMOVE_FROM_HASH(ci_by_x5t, ci, remote_x5t, n_len, "Removing by x5t");
        }
    }

    if (json_object_array_length(disconnected) > 0) {
        send_presence(0, disconnected, 0); // this consumes disconnected.
    } else {
        json_object_put(disconnected);
    }

    json_object_put(ci->remote_x5c);
    free(ci->remote_x5t);
    free(ci->group_names);
    free(ci->ua_names);
    free(ci->conn);
    free(ci);

}

void send_presence(json_object * connected, json_object * disconnected, conn_info_t * except) {

    json_object *body = json_object_new_object();
    if (connected) {
        json_object_object_add(body, "connected", connected);
    }
    if (disconnected) {
        json_object_object_add(body, "disconnected", disconnected);
    }

    conn_info_t * ci;
    conn_info_t * aux;

    DBG("Broadcasting presence change %s", json_object_get_string(body));

    DL_FOREACH_SAFE(connections, ci, aux) {
        if (ci == except) { continue; }
        send_json_message(ci, "xl4bus.presence", json_object_get(body), ci->out_stream_id+=2, 0, 1);
    }

    json_object_put(body);

}

void gather_destinations(json_object * array, json_object ** x5t, UT_array * conns) {

    int l;
    if (!array || !json_object_is_type(array, json_type_array) || (l = json_object_array_length(array)) <= 0) {
        return;
    }


    str_t * set = 0;

    for (int i=0; i<l; i++) {

        json_object * el = json_object_array_get_idx(array, i);
        if (!json_object_is_type(el, json_type_object)) {
            DBG("BRK : skipping destination - not an object");
            continue;
        }

        json_object * cux;

        xl4bus_address_t addr;
        memset(&addr, 0, sizeof(xl4bus_address_t));
        int ok = 0;

        if (json_object_object_get_ex(el, "update-agent", &cux) &&
            json_object_is_type(cux, json_type_string)) {
            addr.type = XL4BAT_UPDATE_AGENT;
            addr.update_agent = (char *) json_object_get_string(cux);
            ok = 1;
        } else if (json_object_object_get_ex(el, "group", &cux) &&
                   json_object_is_type(cux, json_type_string)) {
            addr.type = XL4BAT_GROUP;
            addr.group = (char *) json_object_get_string(cux);
            ok = 1;
        } else if (json_object_object_get_ex(el, "special", &cux) &&
                   json_object_is_type(cux, json_type_string) &&
                   !strcmp("dmclient",json_object_get_string(cux))) {
            addr.type = XL4BAT_SPECIAL;
            addr.special = XL4BAS_DM_CLIENT;
            ok = 1;
        }

        if (ok) {
            gather_destination(&addr, x5t ? &set : 0, conns);
        }


    }

    if (set) {
        finish_x5t_destinations(x5t, set);
    }

}

static void gather_destination(xl4bus_address_t * addr, str_t ** x5t, UT_array * conns) {

    UT_array * send_list = 0;
    int clear_send_list = 0;

    if (addr->type == XL4BAT_UPDATE_AGENT) {
        utarray_new(send_list, &ut_ptr_icd);
        hash_tree_do_rec(ci_ua_tree, 0, 0, addr->update_agent, XL4_MAX_UA_PATHS, 0, send_list);
        clear_send_list = 1;
    } else if (addr->type == XL4BAT_GROUP) {
        conn_info_hash_list_t * val;
        HASH_FIND(hh, ci_by_group, addr->group, strlen(addr->group)+1, val);
        if (val) {
            send_list = &val->items;
        }
    } else if (addr->type == XL4BAT_SPECIAL && addr->special == XL4BAS_DM_CLIENT) {
        send_list = &dm_clients;
    }

    if (!send_list) {
        return;
    }

    int l = utarray_len(send_list);

    DBG("BRK: Found %d conns", l);

    for (int j=0; j<l; j++) {
        conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(send_list, j);
        if (x5t) {
            str_t * str_el;
            HASH_FIND_STR(*x5t, ci2->conn->remote_x5t, str_el);
            if (!str_el) {
                str_el = f_malloc(sizeof(str_t));
                str_el->str = ci2->conn->remote_x5t;
                HASH_ADD_STR(*x5t, str, str_el);
            }
        }

        if (conns) {
            // conns array must only contain unique elements.
            ADD_TO_ARRAY_ONCE(conns, ci2);
        }

    }

    if (clear_send_list) {
        utarray_free(send_list);
    }


}


static void finish_x5t_destinations(json_object ** x5t, str_t * strings) {

    *x5t = json_object_new_array();

    // 'set' now contains all X5T values that we need to return back
    str_t * str_el;
    str_t * dux;

    HASH_ITER(hh, strings, str_el, dux) {
        HASH_DEL(strings, str_el);
        json_object_array_add(*x5t, json_object_new_string(str_el->str));
        free(str_el);
    }

}
static void gather_all_destinations(xl4bus_address_t * first, UT_array * conns) {
    for (xl4bus_address_t * addr = first; addr; addr = addr->next) {
        gather_destination(addr, 0, conns);
    }
}

int send_json_message(conn_info_t * ci, const char * type, json_object * body,
        uint16_t stream_id, int is_reply, int is_final) {

    int err/* = E_XL4BUS_OK*/;
    json_object * json = 0;
    json_object * bus_object = 0;

    do {

        xl4bus_connection_t * conn = ci->conn;

        json = json_object_new_object();
        bus_object = json_object_new_object();

        json_object_object_add(json, "type", json_object_new_string(type));
        if (body) {
            json_object_object_add(json, "body", body);
        }

        xl4bus_ll_message_t x_msg;
        memset(&x_msg, 0, sizeof(xl4bus_ll_message_t));

        char const * json_str = json_object_get_string(json);

        BOLT_SUB(sign_jws(ci, bus_object, json_str, strlen(json_str) + 1, "application/vnd.xl4.busmessage+json",
                &x_msg.data, &x_msg.data_len));

        // sign_jws always make objects of content type application/jose
#if XL4_DISABLE_JWS
        x_msg.content_type = "application/vnd.xl4.busmessage-trust+json";
#else
        x_msg.content_type = "application/jose";
#endif

        x_msg.stream_id = stream_id;
        x_msg.is_reply = is_reply;
        x_msg.is_final = is_final;

        DBG("Outgoing on %p/%p fd %d : %s", ci, conn, conn->fd, json_object_get_string(json));

        msg_context_t * ctx = f_malloc(sizeof(msg_context_t));
        ctx->magic = MAGIC_SYS_MESSAGE;

        if ((err = xl4bus_send_ll_message(conn, &x_msg, ctx, 0)) != E_XL4BUS_OK) {
            printf("failed to send a message : %s\n", xl4bus_strerr(err));
            xl4bus_shutdown_connection(conn);
        }

    } while(0);

    json_object_put(json);
    json_object_put(bus_object);

    return err;

}

int validate_jws(int trusted, void const * data, size_t data_len, validated_object_t * vo) {

    cjose_err c_err;

    cjose_jws_t *jws = 0;
    json_object *hdr = 0;
    int err = E_XL4BUS_OK;
    char *x5c = 0;
    json_object *x5c_json = 0;
    remote_info_t *remote_info = 0;
    char *content_type = 0;

#if XL4_DISABLE_JWS
    json_object *trust = 0;
#endif

    do {

        BOLT_IF(!data_len || ((char *) data)[--data_len], E_XL4BUS_DATA, "Data is not ASCIIZ");

#if XL4_DISABLE_JWS

        if (trusted) {

            BOLT_IF(!(trust = json_tokener_parse(data)),
                    E_XL4BUS_DATA, "Incoming trust message doesn't parse");

            // is there an x5c entry?
            if (json_object_object_get_ex(trust, "x5c", &x5c_json)) {
                x5c_json = json_object_get(x5c_json);
                BOLT_SUB(accept_x5c(x5c_json, &remote_info));
            } else {
                json_object *x5t_json;
                const char *x5t = "<unspecified>";
                if (json_object_object_get_ex(trust, "x5t#S256", &x5t_json)) {
                    x5t = json_object_get_string(x5t_json);
                    remote_info = find_by_x5t(x5t);
                }
                if (!remote_info) {
                    BOLT_SAY(E_XL4BUS_DATA, "No remote info for tag %s", x5t);
                }
            }

            if (!json_object_object_get_ex(trust, "x-xl4bus", &hdr) ||
                !json_object_is_type(hdr = json_object_get(hdr), json_type_object)) {
                BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus object property in the header");
            }

            json_object *j_aux;
            if (!json_object_object_get_ex(trust, "content-type", &j_aux)) {
                BOLT_MEM(content_type = f_strdup("application/octet-stream"));
            } else {
                BOLT_MEM(content_type = f_strdup(json_object_get_string(j_aux)));
            }

            const char *in_data;
            if (!json_object_object_get_ex(trust, "data", &j_aux)) {
                in_data = "";
            } else {
                in_data = json_object_get_string(j_aux);
            }

            BOLT_CJOSE(cjose_base64_decode(in_data, strlen(in_data), &vo->data, &vo->data_len, &c_err));
            vo->data_copy = 1;

            break;


        }

#endif

        BOLT_CJOSE(jws = cjose_jws_import(data, data_len, &c_err));

        cjose_header_t *p_headers = cjose_jws_get_protected(jws);
        const char *hdr_str;

        // is there an x5c entry?
        BOLT_CJOSE(x5c = cjose_header_get_raw(p_headers, "x5c", &c_err));

        if (x5c) {

            BOLT_IF((!(x5c_json = json_tokener_parse(x5c)) ||
                     !json_object_is_type(x5c_json, json_type_array)),
                    E_XL4BUS_DATA, "x5c attribute is not a json array");

            BOLT_SUB(accept_x5c(x5c_json, &remote_info));

        } else {
            const char *x5t;
            BOLT_CJOSE(x5t = cjose_header_get(p_headers, "x5t#S256", &c_err));
            BOLT_IF(!(remote_info = find_by_x5t(x5t)), E_XL4BUS_SYS, "Could not find JWK for tag %s", NULL_STR(x5t));
        }

        BOLT_CJOSE(hdr_str = cjose_header_get(p_headers, "x-xl4bus", &c_err));

        const char *aux;
        BOLT_CJOSE(aux = cjose_header_get(p_headers, CJOSE_HDR_CTY, &c_err));
        BOLT_MEM(content_type = inflate_content_type(aux));

        hdr = json_tokener_parse(hdr_str);
        if (!hdr || !json_object_is_type(hdr, json_type_object)) {
            BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus property in the header");
        }

        BOLT_IF(!cjose_jws_verify(jws, remote_info->key, &c_err), E_XL4BUS_DATA, "Failed JWS verify");

        // $TODO: check nonce/timestamp!

        BOLT_CJOSE(cjose_jws_get_plaintext(jws, &vo->data, &vo->data_len, &c_err));

    } while (0);

    // free stuff that we used temporary

    free(x5c);

#if XL4_DISABLE_JWS
    json_object_put(trust);
#endif

    if (err == E_XL4BUS_OK) {

        vo->exp_jws = jws;
        vo->bus_object = hdr;
        vo->x5c = x5c_json;
        vo->remote_info = remote_info;
        vo->content_type = content_type;

    } else {

        cjose_jws_release(jws);
        json_object_put(hdr);
        json_object_put(x5c_json);
        free(content_type);

    }

    return err;

}


int accept_x5c(json_object * x5c, remote_info_t ** rmi) {

    int err = E_XL4BUS_OK;
    remote_info_t * entry = 0;
    uint8_t * der = 0;
    cjose_jwk_rsa_keyspec rsa_ks;
    mbedtls_x509_crt crt;

    memset(&rsa_ks, 0, sizeof(cjose_jwk_rsa_keyspec));
    mbedtls_x509_crt_init(&crt);

    if (rmi) { *rmi = 0; }

    do {

        cjose_err c_err;
        int l;

        int is_array = json_object_is_type(x5c, json_type_array);
        if (!is_array && !json_object_is_type(x5c, json_type_string)) {
            BOLT_SAY(E_XL4BUS_DATA, "x5c json is neither an array, nor a string");
        }

        if (is_array) {
            BOLT_IF((l = json_object_array_length(x5c)) <= 0, E_XL4BUS_DATA, "x5c array is empty");
        } else {
            l = 1;
        }

        BOLT_MEM(entry = f_malloc(sizeof(remote_info_t)));

        mbedtls_x509_crt_init(&crt);

        for (int i=0; i<l; i++) {
            const char * str;

            if (is_array) {
                str = json_object_get_string(json_object_array_get_idx(x5c, i));
            } else {
                str = json_object_get_string(x5c);
            }

            size_t chars = strlen(str);

            size_t der_len;
            BOLT_CJOSE(cjose_base64_decode(str, chars, &der, &der_len, &c_err));

            BOLT_MTLS(mbedtls_x509_crt_parse_der(&crt, der, der_len));
            if (!i) {

                BOLT_MEM(entry->x5t = make_cert_hash(der, der_len));

            }
        }
        BOLT_SUB(err);

        uint32_t flags;
        BOLT_MTLS(mbedtls_x509_crt_verify(&crt, &trust, &crl, 0, &flags, 0, 0));

        BOLT_IF(!mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA certs are supported");
        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(crt.pk);

        // for public key, we only have N and E
        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));

        BOLT_CJOSE(entry->key = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));

        const char * eku_oid = "1.3.6.1.4.1.45473.3.1";
        if (!mbedtls_x509_crt_check_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) &&
                !mbedtls_x509_crt_check_extended_key_usage(&crt, eku_oid, strlen(eku_oid))) {
            // HAVE SIGNING FLAG
        }

        eku_oid = "1.3.6.1.4.1.45473.3.2";
        if (!mbedtls_x509_crt_check_key_usage(&crt, MBEDTLS_X509_KU_KEY_ENCIPHERMENT) &&
            !mbedtls_x509_crt_check_extended_key_usage(&crt, eku_oid, strlen(eku_oid))) {
            // HAVE ENCRYPTING FLAG
        }

        {

            mbedtls_asn1_sequence seq;
            seq.next = 0;

            unsigned char * start = crt.v3_ext.p;
            unsigned char * end = start + crt.v3_ext.len;
            xl4bus_address_t * bus_address = 0;
            char * x_oid = 0;

            if (!mbedtls_asn1_get_sequence_of(&start, end, &seq, MBEDTLS_ASN1_SEQUENCE|MBEDTLS_ASN1_CONSTRUCTED)) {

                // each sequence element is sequence of:
                //    Extension  ::=  SEQUENCE  {
                //      extnID      OBJECT IDENTIFIER,
                //      critical    BOOLEAN DEFAULT FALSE,
                //      extnValue   OCTET STRING
                //      -- contains the DER encoding of an ASN.1 value
                //      -- corresponding to the extension type identified
                //      -- by extnID
                //    }

                for (mbedtls_asn1_sequence * cur_seq = &seq; cur_seq; cur_seq = cur_seq->next) {

                    start = cur_seq->buf.p;
                    end = start + cur_seq->buf.len;

                    // because we asked to unwrap sequence of sequences,
                    // the inner sequence is already unpacked into the corresponding
                    // mbedtls_asn1_buf, so we can start plucking sub-sequence items.

                    // next must be OID
                    mbedtls_asn1_buf oid;
                    if (get_oid(&start, end, &oid)) {
                        continue;
                    }

                    free(x_oid);
                    x_oid = make_chr_oid(&oid);
                    // DBG("extension oid %s", NULL_STR(x_oid));

                    int is_xl4bus_addr =  !z_strcmp(x_oid, "1.3.6.1.4.1.45473.1.6");
                    int is_xl4bus_group = !z_strcmp(x_oid, "1.3.6.1.4.1.45473.1.7");

                    // NOTE: we don't expect critical value because we always issue our certs
                    // marking out extensions as not critical, which is default, and therefore
                    // not included in DER. We can't mark is as critical, because any other verification
                    // will have to reject it.

                    if (is_xl4bus_group) {

                        size_t inner_len;

                        if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_OCTET_STRING)) {
                            DBG("xl4group attr : not octet string");
                            continue;
                        }
                        end = start + inner_len;

                        // the extracted octet string should contain SET of UTF8String
                        if (mbedtls_asn1_get_tag(&start, end, &inner_len,
                                MBEDTLS_ASN1_SET|MBEDTLS_ASN1_CONSTRUCTED)) {
                            DBG("Group list is not a constructed set");
                            continue;
                        }

                        end = start + inner_len;

                        while (start < end) {

                            if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {
                                DBG("Group element is not utf-8 string");
                                break;
                            }

                            free(bus_address);
                            bus_address = f_malloc(sizeof(xl4bus_address_t));
                            bus_address->type = XL4BAT_GROUP;
                            BOLT_MEM(bus_address->group = f_strndup((char*)start, inner_len));
                            bus_address->next = entry->addresses;
                            entry->addresses = bus_address;

                            DBG("Identity has group %s", bus_address->group);

                            bus_address = 0;

                            start += inner_len;

                        }

                    }

                    if (is_xl4bus_addr) {

                        size_t inner_len;

                        if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_OCTET_STRING)) {
                            DBG("Addr attribute is not octet string");
                            continue;
                        }
                        end = start + inner_len;

                        // the extracted octet string should contain Xl4-Bus-Addresses

                        mbedtls_asn1_sequence addr;
                        addr.next = 0;

                        if (!mbedtls_asn1_get_sequence_of(&start, end, &addr,
                                MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) {

                            for (mbedtls_asn1_sequence *p_addr = &addr; p_addr; p_addr = p_addr->next) {

                                // ok, address contains of an OID, followed by a parameter.

                                start = p_addr->buf.p;
                                end = start + p_addr->buf.len;

                                if (get_oid(&start, end, &oid)) {
                                    DBG("Address doesn't start with an OID");
                                    continue;
                                }

                                free(x_oid);
                                x_oid = make_chr_oid(&oid);
                                // DBG("extension oid %s", NULL_STR(x_oid));

                                free(bus_address);
                                bus_address = f_malloc(sizeof(xl4bus_address_t));
                                int bus_address_ok = 0;

                                if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.1")) {
                                    bus_address->type = XL4BAT_SPECIAL;
                                    bus_address->special = XL4BAS_DM_BROKER;
                                    bus_address_ok = 1;

                                    DBG("Identity is BROKER");

                                } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.2")) {
                                    bus_address->type = XL4BAT_SPECIAL;
                                    bus_address->special = XL4BAS_DM_CLIENT;
                                    bus_address_ok = 1;

                                    DBG("Identity is DM_CLIENT");

                                } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.3")) {
                                    bus_address->type = XL4BAT_UPDATE_AGENT;
                                    if (!mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {
                                        // $TODO: validate utf-8
                                        BOLT_MEM(bus_address->update_agent = f_strndup((char*)start, inner_len));
                                        bus_address_ok = 1;

                                        DBG("Identity is UA %s", bus_address->update_agent);

                                    } else {
                                        DBG("Address value part is not utf8 string");
                                    }
                                } else {
                                    DBG("Unknown address OID %s", x_oid);
                                }

                                if (bus_address_ok) {
                                    bus_address->next = entry->addresses;
                                    entry->addresses = bus_address;
                                    bus_address = 0;
                                }

                            }

                        } else {
                            DBG("address is not a sequence of constructed sequences");
                        }

                        for (mbedtls_asn1_sequence *f_seq = addr.next; f_seq;) {
                            void *ptr = f_seq;
                            f_seq = f_seq->next;
                            free(ptr);
                        }

                        BOLT_NEST();

                    }

                }

            }

            for (mbedtls_asn1_sequence * f_seq = seq.next; f_seq; ) {
                void * ptr = f_seq;
                f_seq = f_seq->next;
                free(ptr);
            }

            free(x_oid);
            free(bus_address);

        }

        BOLT_NEST();

        remote_info_t * old;
        HASH_FIND_STR(tag_cache, entry->x5t, old);
        if (old) {
            HASH_DEL(tag_cache, old);
        }

        HASH_ADD_KEYPTR(hh, tag_cache, entry->x5t, strlen(entry->x5t), entry);

        if (rmi) {
            *rmi = entry;
        }

    } while (0);

    free(der);
    clean_keyspec(&rsa_ks);
    mbedtls_x509_crt_free(&crt);

    if (err != E_XL4BUS_OK) {
        if (entry) {
            free(entry->x5t);
            cjose_jwk_release(entry->key);
            xl4bus_free_address(entry->addresses, 1);
            free(entry);
        }
    }

    return err;

}

remote_info_t * find_by_x5t(const char * x5t) {

    remote_info_t * entry;
    if (!x5t) { return 0; }
    HASH_FIND_STR(tag_cache, x5t, entry);
    return entry;

}


char * make_cert_hash(void * der, size_t der_len) {

    int err = E_XL4BUS_OK;
    mbedtls_md_context_t mdc;
    char * x5t = 0;
    cjose_err c_err;

    mbedtls_md_init(&mdc);

    do {

        // the top cert is the reference point.
        size_t hash_len = mbedtls_md_get_size(hash_sha256);
        uint8_t hash_val[hash_len];
        size_t out_len;

        // calculate sha-256 of the entire DER
        BOLT_MTLS(mbedtls_md_setup(&mdc, hash_sha256, 0));
        BOLT_MTLS(mbedtls_md_starts(&mdc));
        BOLT_MTLS(mbedtls_md_update(&mdc, der, der_len));
        BOLT_MTLS(mbedtls_md_finish(&mdc, hash_val));

        BOLT_CJOSE(cjose_base64url_encode(hash_val, hash_len, &x5t, &out_len, &c_err));

    } while(0);

    mbedtls_md_free(&mdc);

    return x5t;

}

int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len) {

    *dst = 0;
    *dst_len = mpi->n * sizeof(mbedtls_mpi_uint) + 1;

    while (1) {

        void * aux = realloc(*dst, *dst_len);
        if (!aux) {
            free(*dst);
            *dst = 0;
            return E_XL4BUS_MEMORY;
        }

        *dst = aux;

        if (mbedtls_mpi_write_binary(mpi, *dst, *dst_len) == MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
            DBG("MPI %p, size %d failed to fit into %d raw", mpi, mpi->n, *dst_len);
            *dst_len += 20;
            continue;
        }

        return 0;

    }

}

int get_oid(unsigned char **p, unsigned char *end, mbedtls_asn1_buf *oid) {

    int ret;

    if ((ret = mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID)) != 0) {
        return (ret);
    }

    oid->p = *p;
    *p += oid->len;
    oid->tag = MBEDTLS_ASN1_OID;

    return 0;

}

char * make_chr_oid(mbedtls_asn1_buf * buf) {

    // this is an approximation.
    size_t len = buf->len * 4;

    if (!len) { return 0; }

    while (1) {

        char * chr = f_malloc(len);
        if (!chr) { return 0; }
        int ret = mbedtls_oid_get_numeric_string(chr, len-1, buf);
        if (ret >= 0) { return chr; }
        free(chr);
        if (ret == MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
            // $TODO: this can lead to DoS if there is a bug in mbedtls
            len *= 2;
        } else {
            return 0;
        }

    }

}

void clean_keyspec(cjose_jwk_rsa_keyspec * ks) {

    free(ks->e);
    free(ks->n);
    free(ks->d);
    free(ks->p);
    free(ks->q);
    free(ks->dp);
    free(ks->dq);
    free(ks->qi);

}

int sign_jws(conn_info_t * ci, json_object * bus_object, const void *data, size_t data_len, char const * ct, const void **jws_data, size_t *jws_len) {

    cjose_err c_err;
    cjose_jws_t *jws = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

#if XL4_DISABLE_JWS
    json_object * trust = 0;
    char * base64 = 0;
#endif

    do {

#if XL4_DISABLE_JWS
        BOLT_MEM(trust = json_object_new_object());
        if (!ci->sent_x5c) {
            json_object_object_add(trust, "x5c", json_object_get(my_x5c));
            ci->sent_x5c = 1;
        } else {
            json_object *j_aux;
            BOLT_MEM(j_aux = json_object_new_string(my_x5t));
            json_object_object_add(trust, "x5t#S256", j_aux);
        }
        json_object_object_add(trust, "x-xl4bus", json_object_get(bus_object));

        size_t base64_len;
        BOLT_CJOSE(cjose_base64_encode(data, data_len, &base64, &base64_len, &c_err));

        json_object * j_aux;
        BOLT_MEM(j_aux = json_object_new_string_len(base64, (int)base64_len));
        json_object_object_add(trust, "data", j_aux);

        BOLT_MEM(j_aux = json_object_new_string(ct));
        json_object_object_add(trust, "content-type", j_aux);

        BOLT_MEM(*jws_data = f_strdup(json_object_get_string(trust)));
        *jws_len = strlen(*jws_data) + 1;

#else

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, "RS256", &c_err));

        ct = pack_content_type(ct);

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        if (!ci->sent_x5c) {
            BOLT_CJOSE(cjose_header_set_raw(j_hdr, "x5c", json_object_get_string(my_x5c), &c_err));
            ci->sent_x5c = 1;
        } else {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", my_x5t, &c_err));
        }

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(bus_object), &c_err));

        BOLT_CJOSE(jws = cjose_jws_sign(private_key, j_hdr, data, data_len, &c_err));

        const char *jws_export;

        BOLT_CJOSE(cjose_jws_export(jws, &jws_export, &c_err));

        *jws_data = f_strdup(jws_export);
        *jws_len = strlen(*jws_data) + 1;

#endif

    } while (0);

    cjose_jws_release(jws);
    cjose_header_release(j_hdr);

#if XL4_DISABLE_JWS
    json_object_put(trust);
    free(base64);
#endif

    return err;

}

void on_sent_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, void * arg, int err) {

    msg_context_t * ctx = arg;
    if (ctx->magic == MAGIC_CLIENT_MESSAGE) {

        if (err == E_XL4BUS_OK) {
            e900(f_asprintf("Low level accepted %s as %p-%04x", ctx->in_msg_id, conn,
                    (unsigned int)msg->stream_id), ctx->from, ctx->to);
        } else {
            e900(f_asprintf("Low level rejected %s as %p-%04x : %s", ctx->in_msg_id, conn,
                    (unsigned int)msg->stream_id, xl4bus_strerr(err)), ctx->from, ctx->to);
        }

    } else if (ctx->magic == MAGIC_SYS_MESSAGE) {

        free((void*)msg->data);

    } else {
        printf("Unknown magic %x in call back, something is really wrong", ctx->magic);
        abort();
    }

    free_message_context(ctx);

}

int init_x509_values() {

    int err = E_XL4BUS_OK;
    json_object * json_cert = 0;
    mbedtls_x509_crt chain;

    mbedtls_x509_crl_init(&crl);
    mbedtls_x509_crt_init(&trust);
    mbedtls_x509_crt_init(&chain);

    do {

        BOLT_MEM(my_x5c = json_object_new_array());

        if (broker_identity.type == XL4BIT_X509) {

            cjose_err c_err;

            // load trust
            for (xl4bus_asn1_t ** buf = broker_identity.x509.trust; buf && *buf; buf++) {

                switch ((*buf)->enc) {
                    case XL4BUS_ASN1ENC_DER:
                    case XL4BUS_ASN1ENC_PEM:
                    BOLT_MTLS(mbedtls_x509_crt_parse(&trust, (*buf)->buf.data, (*buf)->buf.len));
                        break;
                    default:
                    BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

            }

            BOLT_NEST();

            int chain_count = 0;

            // load chain
            for (xl4bus_asn1_t ** buf = broker_identity.x509.chain; buf && *buf; buf++) {

                BOLT_SUB(asn1_to_json(*buf, &json_cert));

                switch ((*buf)->enc) {

                    case XL4BUS_ASN1ENC_DER:

                        if (buf == broker_identity.x509.chain) {
                            // first cert, need to build my x5t
                            BOLT_MEM(my_x5t = make_cert_hash((*buf)->buf.data, (*buf)->buf.len));
                        }
                        BOLT_MTLS(mbedtls_x509_crt_parse(&chain, (*buf)->buf.data, (*buf)->buf.len));

                        break;

                    case XL4BUS_ASN1ENC_PEM:
                    {

                        if (buf == broker_identity.x509.chain) {
                            // first cert, need to build my x5t

                            uint8_t * der = 0;

                            do {

                                size_t der_len;

                                const char * pem = json_object_get_string(json_cert);
                                size_t pem_len = strlen(pem);

                                BOLT_CJOSE(cjose_base64_decode(pem, pem_len, &der, &der_len, &c_err));
                                BOLT_MEM(my_x5t = make_cert_hash(der, der_len));

                            } while (0);

                            free(der);
                            BOLT_NEST();

                        }

                        BOLT_MTLS(mbedtls_x509_crt_parse(&chain, (*buf)->buf.data, (*buf)->buf.len));

                    }
                        break;
                    default:
                    BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

                BOLT_MEM(!json_object_array_add(my_x5c, json_cert));
                json_cert = 0;

                chain_count++;

            }

            BOLT_NEST();

            BOLT_IF(!chain_count, E_XL4BUS_ARG,
                    "At least one certificate must be present in the chain");

            // $TODO: do we verify that the provided cert checks out against the provided trust?
            // realistically there are no rules to say it should.

            BOLT_SUB(make_private_key(&broker_identity, &chain.pk, &private_key));

        } else {

            BOLT_SAY(E_XL4BUS_ARG, "Unsupported identity type %d", broker_identity.type);

        }

    } while(0);

    json_object_put(json_cert);
    mbedtls_x509_crt_free(&chain);

    return err;

}


int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to) {

    int err = E_XL4BUS_OK;
    char * base64 = 0;
    size_t base64_len = 0;
    cjose_err c_err;

    do {

        switch (asn1->enc) {

            case XL4BUS_ASN1ENC_DER:

            BOLT_CJOSE(cjose_base64_encode(asn1->buf.data, asn1->buf.len, &base64, &base64_len, &c_err));
                break;

            case XL4BUS_ASN1ENC_PEM: {

                // encoding must be PEM, we already have the base64 data,
                // but we need to remove PEM headers and join the lines.

                base64 = f_malloc(asn1->buf.len);
                base64_len = 0;

                int skipping_comment = 1;

                const char *line_start = (const char *) asn1->buf.data;

                for (int i = 0; i < asn1->buf.len; i++) {

                    char c = asn1->buf.data[i];

                    if (c == '\n') {

                        if (!strncmp("-----BEGIN ", line_start, 11)) {

                            skipping_comment = 0;

                        } else if (!strncmp("-----END ", line_start, 9)) {

                            skipping_comment = 1;

                        } else if (!skipping_comment) {

                            for (const char *cc = line_start; (void *) cc < (void *) asn1->buf.data + i; cc++) {

                                c = *cc;

                                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                    (c == '+') || (c == '/') || (c == '=')) {

                                    base64[base64_len++] = c;

                                }

                            }

                        }

                        line_start = (const char *) (asn1->buf.data + i + 1);

                    }

                }

            }
                break;
            default:
            BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", asn1->enc);
        }

        BOLT_NEST();

        BOLT_MEM(*to = json_object_new_string_len(base64, (int) base64_len));

    } while (0);

    free(base64);

    return err;

}


int make_private_key(xl4bus_identity_t * id, mbedtls_pk_context * pk, cjose_jwk_t ** jwk) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    char * pwd = 0;
    size_t pwd_len = 0;

    mbedtls_pk_context prk;
    mbedtls_pk_init(&prk);

    cjose_jwk_rsa_keyspec rsa_ks;
    memset(&rsa_ks, 0, sizeof(rsa_ks));

    do {

        BOLT_IF(id->type != XL4BIT_X509, E_XL4BUS_ARG, "Only x.509 is supported");
        BOLT_IF(!id->x509.private_key, E_XL4BUS_ARG, "Private key must be supplied");

        int try_pk = mbedtls_pk_parse_key(&prk, id->x509.private_key->buf.data,
                id->x509.private_key->buf.len, 0, 0);

        if (try_pk == MBEDTLS_ERR_PK_PASSWORD_REQUIRED || try_pk == MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {

            if (id->x509.password) {
                pwd = id->x509.password(&id->x509);
                pwd_len = strlen(pwd);
            }

            BOLT_MTLS(mbedtls_pk_parse_key(&prk, id->x509.private_key->buf.data,
                    id->x509.private_key->buf.len, (const unsigned char*)"", 0));

        } else {
            BOLT_MTLS(try_pk);
        }

        BOLT_IF(!mbedtls_pk_can_do(&prk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA keys are supported");

        if (pk) {
            BOLT_MTLS(mbedtls_pk_check_pair(pk, &prk));
        }

        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(prk);

        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->D, &rsa_ks.d, &rsa_ks.dlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->P, &rsa_ks.p, &rsa_ks.plen));
        BOLT_SUB(mpi2jwk(&prk_rsa->Q, &rsa_ks.q, &rsa_ks.qlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->DP, &rsa_ks.dp, &rsa_ks.dplen));
        BOLT_SUB(mpi2jwk(&prk_rsa->DQ, &rsa_ks.dq, &rsa_ks.dqlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->QP, &rsa_ks.qi, &rsa_ks.qilen));

        BOLT_CJOSE(*jwk = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));


    } while (0);

    if (pwd) {
        secure_bzero(pwd, pwd_len);
        free(pwd);
    }

    mbedtls_pk_free(&prk);
    clean_keyspec(&rsa_ks);

    return err;

}

void free_message_context(msg_context_t * ctx) {

    if (!ctx) { return; }

    if (ctx->magic == MAGIC_CLIENT_MESSAGE) {
        xl4bus_free_address(ctx->from, 1);
        xl4bus_free_address(ctx->to, 1);
        free(ctx->in_msg_id);
    }

    free(ctx);

}

void e900(char * msg, xl4bus_address_t * from, xl4bus_address_t * to) {

    char my_time[20];

    my_str_time(my_time);

    int alloc_src = 1;
    int alloc_dst = 1;
    int alloc_msg = 1;

    char * from_str = addr_to_str(from);
    if (!from_str) {
        from_str = "(FAIL)";
        alloc_src = 0;
    }
    char * to_str = addr_to_str(to);
    if (!from_str) {
        to_str = "(FAIL)";
        alloc_dst = 0;
    }

    if (!msg) {
        alloc_msg = 0;
        msg = "(NULL MSG!)";
    }

    printf("E900 %s (%s)->(%s) : %s\n", my_time, from_str, to_str, msg);
    fflush(stdout);

    if (alloc_msg) {
        free(msg);
    }
    if (alloc_src) {
        free(from_str);
    }
    if (alloc_dst) {
        free(to_str);
    }

}

void count(int in, int out) {

    if (!perf.enabled) { return; }

    clockid_t clk =
#ifdef CLOCK_MONOTONIC_COARSE
            CLOCK_MONOTONIC_COARSE
#elif defined(CLOCK_MONOTONIC_RAW)
    CLOCK_MONOTONIC_RAW
#else
    CLOCK_MONOTONIC
#endif
    ;

    struct timespec ts;

    clock_gettime(clk, &ts);
    if (perf.second != ts.tv_sec) {
        if (perf.second) {
            printf("E872 %d IN %d OUT\n", perf.in, perf.out);
        }
        perf.in = 0;
        perf.out = 0;
        perf.second = ts.tv_sec;
    }

    perf.in += in;
    perf.out += out;

}

void hash_tree_add(conn_info_t * ci, const char * ua_name) {

    ci->ua_names = f_realloc(ci->ua_names, sizeof(char *) * (ci->ua_count + 1));
    ci->ua_names[ci->ua_count] = f_strdup(ua_name);
    // HASH_LIST_ADD(ci_by_name, ci, ua_names[ci->ua_count]);

    // we have to deal with root, before calling in recursive tree storage.
    if (!ci_ua_tree) {
        ci_ua_tree = f_malloc(sizeof(conn_info_hash_tree_t));
        utarray_init(&ci_ua_tree->items, &ut_ptr_icd);
    }

    hash_tree_do_rec(ci_ua_tree, ci, ua_name, ua_name, XL4_MAX_UA_PATHS, 0, 0);

#if 0
    // honestly, there is no point to deleting the root.
    if (hash_tree_maybe_delete(ci_ua_tree)) {
        // root died.
        ci_ua_tree = 0;
    }
#endif

}

void hash_tree_do_rec(conn_info_hash_tree_t * current, conn_info_t * ci, const char * full_name,
        const char * ua_name, int ok_more, int is_delete, UT_array * gather) {

    // ESYNC-1155
    // If there is no current (can be called in from main code, before any UA connected)
    // then there is nothing we can do, no matter what the requested operation is.
    if (!current) { return; }

    // NOTE! Gathering - we need to add all conn_info_t objects at each level we encounter.
    if (gather && utarray_len(&current->items)) {
        utarray_concat(gather, &current->items);
    }

    while (*ua_name && (*ua_name == '/')) { ua_name++; }

    if (!*ua_name) {
        // we ran out of name, so this is the place where we need to drop this conn_info.
        if (is_delete) {
            REMOVE_FROM_ARRAY(&current->items, ci, "Removing %s from terminal array", full_name);
        } else if (!gather) {
            ADD_TO_ARRAY_ONCE(&current->items, ci);
        }
        return;
    }

    if (!ok_more) { return; }

    size_t key_len;

    char * ua_name_sep = strchr(ua_name, '/');
    if (ua_name_sep) {
        // there is a separator
        key_len = (size_t)(ua_name_sep - ua_name);
    } else {
        key_len = strlen(ua_name);
    }

    conn_info_hash_tree_t * child;
    HASH_FIND(hh, current->nodes, ua_name, key_len, child);
    if (!child) {
        if (is_delete) {
            printf("While looking for sub-tree %s, for UA %s, next sub-node could not be found", ua_name, full_name);
        } else {
            child = f_malloc(sizeof(conn_info_hash_tree_t));
            child->key = f_strndup(ua_name, key_len);
            child->parent = current;
            HASH_ADD_KEYPTR(hh, current->nodes, child->key, key_len, child);
            utarray_init(&child->items, &ut_ptr_icd);
        }
    }

    ua_name += key_len;

    if (child) {
        hash_tree_do_rec(child, ci, full_name, ua_name, ok_more - 1, is_delete, gather);
    }

    // NOTE! We only check if we can delete the child container, but not current.
    // This is because current can be root, and deleting root without resetting it's
    // address is fatal. So we never delete root (if we did, this would be in hash_tree_add/hash_tree_remove
    // functions.
    if (!gather) {
        // only if !gather, for !!gather, we are not making any changes, only looking
        hash_tree_maybe_delete(child);
    }

}

int hash_tree_maybe_delete(conn_info_hash_tree_t * current) {

    // do I have property at this level?
    if (utarray_len(&current->items)) {
        return 0;
    }

    // no property at this level, but do I have kids?
    if (HASH_COUNT(current->nodes)) {
        // yeah, pesky kids, have to stay on
        return 0;
    }

    // no property, no kids, no reason to live.

    if (current->parent) {
        // if I have a parent, check out from it.
        HASH_DEL(current->parent->nodes, current);
        free(current->key);
    }

    utarray_done(&current->items);

    free(current);
    return 1;

}

static void hash_tree_remove(conn_info_t * ci) {

    for (int i = 0; i<ci->ua_count; i++) {

        const char * ua_name = ci->ua_names[i];

        if (!ci_ua_tree) {
            ERR("Cleaning UA %s - no root UA has tree root!", ua_name);
            continue;
        }

        hash_tree_do_rec(ci_ua_tree, ci, ua_name, ua_name, XL4_MAX_UA_PATHS, 1, 0);

    }

}
