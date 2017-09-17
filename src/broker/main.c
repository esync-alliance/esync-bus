
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

#include <libxl4bus/low_level.h>
#include <uthash.h>
#include <utarray.h>
#include <utlist.h>
#include <dbm.h>

#include "lib/debug.h"
#include "lib/common.h"

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
    PIT_INCOMING,
    PIT_XL4
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

    struct poll_info pit;

    int ll_poll_timeout;

    uint16_t out_stream_id;

    json_object * remote_x5c;
    char * remote_x5t;

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

static int on_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int, int);

static void gather_destinations(json_object * array, json_object ** x5t, UT_array * conns);
static void gather_destination(xl4bus_address_t *, str_t ** x5t, UT_array * conns);
static void finish_x5t_destinations(json_object ** x5t, str_t * strings);
static void gather_all_destinations(xl4bus_address_t * first, UT_array * conns);
static void on_connection_shutdown(xl4bus_connection_t * conn);
static void send_presence(json_object * connected, json_object * disconnected, conn_info_t * except);
static int send_json_message(conn_info_t *, const char *, json_object * body, uint16_t stream_id, int is_reply, int is_final);


int debug = 1;

static conn_info_hash_list_t * ci_by_name = 0;
static conn_info_hash_list_t * ci_by_group = 0;
static conn_info_hash_list_t * ci_by_x5t = 0;
static UT_array dm_clients;
static int poll_fd;
static conn_info_t * connections;
static xl4bus_identity_t broker_identity;

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

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;

    printf("xl4-broker %s\n", xl4bus_version());

#if 0
    ll_cfg.realloc = realloc;
    ll_cfg.malloc = malloc;
    ll_cfg.free = free;
#else
    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = print_out;
#endif

    if (xl4bus_init_ll(&ll_cfg)) {
        printf("failed to initialize xl4bus\n");
        return 1;
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

    load_test_x509_creds(&broker_identity, "broker", argv[0]);

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
    }
#endif

    utarray_init(&dm_clients, &ut_ptr_icd);

    if (bind(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        perror("bind");
        return 1;
    }

    if (listen(fd, 5)) {
        perror("listen");
        return 1;
    }

    if (set_nonblocking(fd)) {
        perror("non-blocking");
        return 1;
    }

    poll_fd = epoll_create1(0);
    if (poll_fd < 0) {
        perror("epoll_create");
        return 1;
    }

    poll_info_t main_pit = {
            .type = PIT_INCOMING,
            .fd = fd
    };

    struct epoll_event ev;
    ev.events = POLLIN;
    ev.data.ptr = &main_pit;

    if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd, &ev)) {
        perror("epoll_ctl");
        return 1;
    }

    int max_ev = 1;
    int timeout = -1;

    while (1) {

        struct epoll_event rev[max_ev];
        uint64_t before;

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
            perror("epoll_wait");
            return 1;
        }

        if (ec == max_ev) { max_ev++; }

        for (int i=0; i<ec; i++) {

            poll_info_t * pit = rev[i].data.ptr;
            if (pit->type == PIT_INCOMING) {

                if (rev[i].events & POLLERR) {
                    get_socket_error(pit->fd);
                    perror("Error on incoming socket");
                    return 1;
                }

                if (rev[i].events & POLLIN) {

                    socklen_t b_addr_len = sizeof(b_addr);
                    int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
                    if (fd2 < 0) {
                        perror("accept");
                        return 1;
                    }

                    xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));
                    conn_info_t * ci = f_malloc(sizeof(conn_info_t));

                    conn->on_message = on_message;
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

                        if (err == E_XL4BUS_OK) {
                            int s_err;
                            if ((s_err = xl4bus_process_connection(conn, -1, 0)) == E_XL4BUS_OK) {
                                timeout = pick_timeout(timeout, ci->ll_poll_timeout);
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
                } else {
                    DBG("xl4bus process (timeout route) returned %d", s_err);
                }
            }

        }

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

    int err = E_XL4BUS_OK;
    json_object * root = 0;
    conn_info_t * ci = conn->custom;
    json_object * connected = 0;

    do {

        if (!ci->remote_x5c && conn->remote_x5c) {
            ci->remote_x5c = json_tokener_parse(conn->remote_x5c);
        }
        if (!ci->remote_x5t && conn->remote_x5t) {
            // we must copy x5t, since we need it when we deallocate
            // things, at which point it would be cleaned up already
            ci->remote_x5t = f_strdup(conn->remote_x5t);
        }

        if (!strcmp("application/vnd.xl4.busmessage+json", msg->message.content_type)) {

            // the json must be ASCIIZ.
            BOLT_IF(((uint8_t *) msg->message.data)[msg->message.data_len - 1], E_XL4BUS_CLIENT,
                    "Incoming message is not ASCIIZ");

            BOLT_IF(!(root = json_tokener_parse(msg->message.data)),
                    E_XL4BUS_CLIENT, "Not valid json: %s", msg->message.data);

            json_object *aux;
            BOLT_IF(!json_object_object_get_ex(root, "type", &aux) || !json_object_is_type(aux, json_type_string),
                    E_XL4BUS_CLIENT, "No/non-string type property in %s", msg->message.data);

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

                        ci->ua_names = f_realloc(ci->ua_names, sizeof(char *) * (ci->ua_count + 1));
                        ci->ua_names[ci->ua_count] = f_strdup(r_addr->update_agent);
                        HASH_LIST_ADD(ci_by_name, ci, ua_names[ci->ua_count]);
                        ci->ua_count++;

                        json_object *cel;
                        json_object *sel;
                        BOLT_MEM(cel = json_object_new_object());
                        json_object_array_add(connected, cel);
                        BOLT_MEM(sel = json_object_new_string(r_addr->update_agent));
                        json_object_object_add(cel, "update-agent", sel);

                    }

                }

                HASH_LIST_ADD(ci_by_x5t, ci, remote_x5t);

                BOLT_NEST();

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

                    HASH_ITER(hh, ci_by_name, cti, tmp) {
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
                    printf("failed to send a message : %s\n", xl4bus_strerr(err));
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

                if (json_object_object_get_ex(root, "body", &aux) && json_object_is_type(aux, json_type_object)) {
                    json_object *array;
                    if (json_object_object_get_ex(aux, "destinations", &array)) {
                        gather_destinations(array, &x5t, 0);
                    }
                }

                // send destination list
                // https://gitlab.excelfore.com/schema/json/xl4bus/destination-info.json
                json_object *body = json_object_new_object();
                if (x5t) {
                    json_object_object_add(body, "x5t#S256", x5t);
                }

                send_json_message(ci, "xl4bus.destination-info", body, msg->stream_id, 1,
                        json_object_array_length(x5t) == 0);

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

                            for (int j=0; j<l2; j++) {

                                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(send_list, j);
                                if (!ci2->remote_x5c) {
                                    json_object_array_add(x5c, ci2->remote_x5c);
                                }

                            }

                        }

                    }
                }

                json_object * body = json_object_new_object();
                json_object_object_add(body, "x5c", x5c);
                send_json_message(ci, "xl4.cert-details", body, msg->stream_id, 1, 0);

                break;

            }

            BOLT_SAY(E_XL4BUS_CLIENT, "Don't know what to do with message %s", type);

        } else {

            UT_array send_list;

            utarray_init(&send_list, &ut_ptr_icd);

            gather_all_destinations(msg->message.address, &send_list);

            int l = utarray_len(&send_list);

            DBG("Received application message, has %d send list elements", l);

            uint16_t stream_id = msg->stream_id;

            for (int i=0; i<l; i++) {
                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(&send_list, i);
                if (ci2 == ci) {
                    DBG("Ignored one sender - loopback");
                    // prevent loopback
                    continue;
                }

                msg->is_final = 1;
                msg->is_reply = 0;
                msg->stream_id = ci2->out_stream_id+=2;

                if (xl4bus_send_ll_message(ci2->conn, msg, 0, 0)) {
                    printf("failed to send a message : %s\n", xl4bus_strerr(err));
                    xl4bus_shutdown_connection(ci2->conn);
                    i--;
                    l--;
                }

                DBG("application message forwarded to connection %p", ci2);

            }

            send_json_message(ci, "xl4bus.message-confirm", 0, stream_id, 1, 1);

        }

    } while (0);

    json_object_put(root);
    json_object_put(connected);


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

    for (int i=0; i< ci->ua_count; i++) {
        int n_len;
        REMOVE_FROM_HASH(ci_by_name, ci, ua_names[i], n_len, "Removing by UA name");
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
    conn_info_hash_list_t * use_hl = 0;
    char const * key = 0;

    if (addr->type == XL4BAT_UPDATE_AGENT) {
        use_hl = ci_by_name;
        key = addr->update_agent;
    } else if (addr->type == XL4BAT_GROUP) {
        use_hl = ci_by_group;
        key = addr->group;
    } else if (addr->type == XL4BAT_SPECIAL && addr->special == XL4BAS_DM_CLIENT) {
        send_list = &dm_clients;
    }

    if (use_hl) {
        conn_info_hash_list_t * val;
        HASH_FIND(hh, use_hl, key, strlen(key)+1, val);
        if (val) {
            send_list = &val->items;
        }
    }

    if (!send_list) {
        return;
    }

    int l2 = utarray_len(send_list);

    DBG("BRK: Found %d conns", l2);

    for (int j=0; j<l2; j++) {
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

    int err;

    xl4bus_connection_t * conn = ci->conn;

    // confirm the message to the caller.
    // https://gitlab.excelfore.com/schema/json/xl4bus/message-confirm.json
    json_object * json = json_object_new_object();
    json_object_object_add(json, "type", json_object_new_string(type));
    if (body) {
        json_object_object_add(json, "body", body);
    }

    xl4bus_ll_message_t x_msg;
    memset(&x_msg, 0, sizeof(xl4bus_ll_message_t));

    const char * bux = json_object_get_string(json);
    x_msg.message.data = bux;
    x_msg.message.data_len = strlen(bux) + 1;
    x_msg.message.content_type = "application/vnd.xl4.busmessage+json";

    x_msg.stream_id = stream_id;
    x_msg.is_reply = is_reply;
    x_msg.is_final = is_final;

    DBG("Outgoing on %p/%p fd %d : %s", ci, conn, conn->fd, json_object_get_string(json));

    if ((err = xl4bus_send_ll_message(conn, &x_msg, 0, 0)) != E_XL4BUS_OK) {
        printf("failed to send a message : %s\n", xl4bus_strerr(err));
        xl4bus_shutdown_connection(conn);
    }

    json_object_put(json);

    return err;

}
