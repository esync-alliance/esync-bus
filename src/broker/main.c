
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
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
#include "json.h"

#include <libxl4bus/low_level.h>
#include <uthash.h>
#include <utarray.h>
#include <utlist.h>

#include "broker/debug.h"
#include "broker/common.h"

typedef enum terminal_type {
    TT_DM_CLIENT,
    TT_UPDATE_AGENT
} terminal_type_t;

#define ADD_TO_ARRAY_ONCE(array, item) do {\
    if (!utarray_find(array, item, void_cmp_fun)) { \
        utarray_push_back(array, item); \
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
        HASH_ADD_KEYPTR(hh, root, __keyval, __keylen, __list); \
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

typedef struct stream_info {
    UT_hash_handle hh;
    uint16_t stream_id;
    json_object * destinations;
} stream_info_t;

typedef struct conn_info {

    struct pollfd pfd;
    int reg_req;

    terminal_type_t terminal;
    char * ua_name;
    int group_count;
    char ** groups;

    int poll_modes;

    xl4bus_connection_t * conn;

    struct conn_info * next;
    struct conn_info * prev;

    struct poll_info pit;

    stream_info_t * open_streams;

    uint16_t out_stream_id;

} conn_info_t;

typedef struct conn_info_hash_list {
    UT_hash_handle hh;
    UT_array items;
} conn_info_hash_list_t;

static int in_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int, int);
static int pick_timeout(int t1, int t2);
static void dismiss_connection(conn_info_t * ci, int need_shutdown);
static void cleanup_stream(conn_info_t * ci, stream_info_t * si);

static inline int void_cmp_fun(const void * a, const void * b) {
    if ((uintptr_t)b > (uintptr_t)a) {
        return 1;
    } else if (a == b) {
        return 0;
    }
    return -1;
}

int debug = 1;

static conn_info_hash_list_t * ci_by_name = 0;
static conn_info_hash_list_t * ci_by_group = 0;
static UT_array dm_clients;
static int poll_fd;
conn_info_t * connections;

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;

#if 0
    ll_cfg.realloc = realloc;
    ll_cfg.malloc = malloc;
    ll_cfg.free = free;
#else
    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = print_out;
#endif

    xl4bus_init_ll(&ll_cfg);

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

#if 0
    while (1) {

        socklen_t b_addr_len = sizeof(b_addr);
        int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
        if (fd2 < 0) {
            perror("accept");
            return 1;
        }

        xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));

        memset(conn, 0, sizeof(xl4bus_connection_t));

        conn->on_message = in_message;
        conn->fd = fd2;

        conn->set_poll = set_poll;

        pthread_t nt;

        if (pthread_create(&nt, 0, run_conn, conn)) {
            perror("pthread_create");
            return 1;
        }

    }

#endif

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

                    conn->on_message = in_message;
                    conn->fd = fd2;
                    conn->set_poll = set_poll;

                    conn->custom = ci;
                    ci->conn = conn;
                    ci->pit.ci = ci;
                    ci->pit.type = PIT_XL4;
                    ci->pit.fd = fd2;
                    ci->out_stream_id = 1;

                    DBG("Created connection %p/%p fd %d", ci, ci->conn, fd2);

                    int err = xl4bus_init_connection(conn);

                    if (err == E_XL4BUS_OK) {

                        DL_APPEND(connections, ci);

                        // send initial message - alg-supported
                        // https://gitlab.excelfore.com/schema/json/xl4bus/alg-supported.json
                        json_object *json = json_object_new_object();
                        json_object *aux;
                        json_object *body;
                        json_object_object_add(json, "body", body = json_object_new_object());

                        json_object_object_add(body, "signature", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RS256"));
                        json_object_object_add(body, "encryption-key", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RSA-OAEP"));
                        json_object_object_add(body, "encryption-alg", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("A128CBC-HS256"));

                        json_object_object_add(json, "type", json_object_new_string("xl4bus.alg-supported"));

                        xl4bus_ll_message_t msg;
                        memset(&msg, 0, sizeof(xl4bus_ll_message_t));

                        const char *bux = json_object_get_string(json);
                        msg.message.data = bux;
                        msg.message.data_len = strlen(bux) + 1;
                        msg.message.content_type = "application/vnd.xl4.busmessage+json";
                        msg.stream_id = ci->out_stream_id += 2;

                        if ((err = xl4bus_send_ll_message(conn, &msg, 0, 0)) != E_XL4BUS_OK) {
                            printf("failed to send a message : %s\n", xl4bus_strerr(err));
                            dismiss_connection(ci, 1);
                        }

                        json_object_put(json);

                        if (err == E_XL4BUS_OK) {
                            int my_timeout;
                            int s_err;
                            if ((s_err = xl4bus_process_connection(conn, -1, 0, &my_timeout)) == E_XL4BUS_OK) {
                                timeout = pick_timeout(timeout, my_timeout);
                            } else {
                                DBG("xl4bus process (initial) returned %d", s_err);
                                dismiss_connection(ci, 0);
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

                int my_timeout;
                int s_err;
                if ((s_err = xl4bus_process_connection(ci->conn, pit->fd, flags, &my_timeout)) == E_XL4BUS_OK) {
                    timeout = pick_timeout(timeout, my_timeout);
                } else {
                    DBG("xl4bus process (fd up route) returned %d", s_err);
                    dismiss_connection(ci, 0);
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
                int my_timeout;
                int s_err;
                if ((s_err = xl4bus_process_connection(ci->conn, -1, 0, &my_timeout)) != E_XL4BUS_OK) {
                    timeout = pick_timeout(timeout, my_timeout);
                } else {
                    DBG("xl4bus process (timeout route) returned %d", s_err);
                    dismiss_connection(ci, 0);
                }
            }

        }

    }

}

int set_poll(xl4bus_connection_t * conn, int fd, int flg) {

    // $TODO: because we use non-mt only, fd is bound to
    // only be fd for the network connection. However, there is
    // no promise it is, which means that conn_info must support
    // multiple poll_info entries.

#if 0
    conn_info_t * ci = conn->custom;

    ci->pfd.events = 0;

    if (flg & XL4BUS_POLL_READ) {
        ci->pfd.events = POLLIN;
    }
    if (flg & XL4BUS_POLL_WRITE) {
        ci->pfd.events |= POLLOUT;
    }
    return E_XL4BUS_OK;
#endif

    conn_info_t * ci = conn->custom;

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

int in_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int err = E_XL4BUS_OK;
    json_object * root = 0;
    conn_info_t * ci = conn->custom;

    do {


        if (!strcmp("application/vnd.xl4.busmessage+json", msg->message.content_type)) {

            // the json must be ASCIIZ.
            BOLT_IF(((uint8_t*)msg->message.data)[msg->message.data_len-1], E_XL4BUS_CLIENT,
                    "Incoming message is not ASCIIZ");

            BOLT_IF(!(root = json_tokener_parse(msg->message.data)),
                    E_XL4BUS_CLIENT, "Not valid json: %s", msg->message.data);

            json_object * aux;
            BOLT_IF(!json_object_object_get_ex(root, "type", &aux) || !json_object_is_type(aux, json_type_string),
                    E_XL4BUS_CLIENT, "No/non-string type property in %s", msg->message.data);

            const char * type = json_object_get_string(aux);

            DBG("LLP message type %s", type);

            if (!strcmp(type, "xl4bus.registration-request")) {

                BOLT_IF(ci->reg_req, E_XL4BUS_CLIENT, "already registered");
                ci->reg_req = 1;

#if 1 /* throw this code out the window, must use x-509 ID only */
                BOLT_IF(!json_object_object_get_ex(root, "xxx-id", &aux) || !json_object_is_type(aux, json_type_object),
                        E_XL4BUS_CLIENT, "Missing xxx-id property");
                {
                    json_object * bux;
                    if (json_object_object_get_ex(aux, "is_dmclient", &bux) &&
                            json_object_is_type(bux, json_type_boolean) && json_object_get_boolean(bux)) {
                        ci->terminal = TT_DM_CLIENT;
                        ADD_TO_ARRAY_ONCE(&dm_clients, ci);
                    } else if (json_object_object_get_ex(aux, "is_update_agent", &bux) &&
                            json_object_is_type(bux, json_type_boolean) && json_object_get_boolean(bux)) {
                        ci->terminal = TT_UPDATE_AGENT;
                        BOLT_IF(!json_object_object_get_ex(aux, "update_agent", &bux) ||
                                !json_object_is_type(bux, json_type_string), E_XL4BUS_CLIENT,
                                "No update agent name present");
                        ci->ua_name = f_strdup(json_object_get_string(bux));
                        BOLT_IF(!*ci->ua_name, E_XL4BUS_CLIENT, "empty update agent name");

                        HASH_LIST_ADD(ci_by_name, ci, ua_name);
                    } else {
                        BOLT_SAY(E_XL4BUS_CLIENT, "Can't accept/identify terminal type");
                    }

                    if (json_object_object_get_ex(root, "groups", &bux) &&
                            json_object_is_type(bux, json_type_array)) {

                        int l = json_object_array_length(bux);
                        for (int i=0; i<l; i++) {
                            json_object * cux = json_object_array_get_idx(bux, i);
                            if (!json_object_is_type(cux, json_type_string)) { continue; }
                            ci->groups = f_realloc(ci->groups, sizeof(char*) * (ci->group_count+1));
                            ci->groups[ci->group_count] = f_strdup(json_object_get_string(cux));
                            HASH_LIST_ADD(ci_by_group, ci, groups[ci->group_count]);
                            ci->group_count++;
                        }
                    }
                }

#endif

                // send registration response
                // https://gitlab.excelfore.com/schema/json/xl4bus/registration-confirmation.json
                json_object * json = json_object_new_object();
                json_object_object_add(json, "type", json_object_new_string("xl4bus.registration-confirmation"));

                xl4bus_ll_message_t x_msg;
                memset(&x_msg, 0, sizeof(xl4bus_ll_message_t));

                const char * bux = json_object_get_string(json);
                x_msg.message.data = bux;
                x_msg.message.data_len = strlen(bux) + 1;
                x_msg.message.content_type = "application/vnd.xl4.busmessage+json";

                x_msg.stream_id = msg->stream_id;
                x_msg.is_final = 1;
                x_msg.is_reply = 1;

                if ((err = xl4bus_send_ll_message(conn, &x_msg, 0, 0)) != E_XL4BUS_OK) {
                    printf("failed to send a message : %s\n", xl4bus_strerr(err));
                    dismiss_connection(ci, 1);
                }

                json_object_put(json);

                break;

            } else if (!strcmp("xl4bus.request-destinations", type)) {

                stream_info_t * si;
                HASH_FIND(hh, ci->open_streams, &msg->stream_id, 2, si);
                if (si) {
                    // one shall not request destinations on existing stream.
                    DBG("request-destinations on existing stream %d", msg->stream_id);
                    xl4bus_abort_stream(conn, msg->stream_id);
                    cleanup_stream(ci, si);
                    break;
                }

                si = f_malloc(sizeof(stream_info_t));
                si->stream_id = msg->stream_id;
                HASH_ADD(hh, ci->open_streams, stream_id, 2, si);

                if (json_object_object_get_ex(root, "body", &aux) && json_object_is_type(aux, json_type_object)) {
                    json_object * bux;
                    if (json_object_object_get_ex(root, "destinations", &bux) && json_object_is_type(aux, json_type_array) &&
                            json_object_array_length(bux) > 0) {
                        si->destinations = json_object_get(bux);
                    }
                }

                // send destination list
                // https://gitlab.excelfore.com/schema/json/xl4bus/destination-info.json
                json_object * json = json_object_new_object();
                json_object_object_add(json, "type", json_object_new_string("xl4bus.destination-info"));

                xl4bus_ll_message_t x_msg;
                memset(&x_msg, 0, sizeof(xl4bus_ll_message_t));

                const char * bux = json_object_get_string(json);
                x_msg.message.data = bux;
                x_msg.message.data_len = strlen(bux) + 1;
                x_msg.message.content_type = "application/vnd.xl4.busmessage+json";

                x_msg.stream_id = msg->stream_id;
                x_msg.is_reply = 1;
                x_msg.is_final = !si->destinations;

                if ((err = xl4bus_send_ll_message(conn, &x_msg, 0, 0)) != E_XL4BUS_OK) {
                    printf("failed to send a message : %s\n", xl4bus_strerr(err));
                    dismiss_connection(ci, 1);
                }

                json_object_put(json);

                break;

            }

            BOLT_SAY(E_XL4BUS_CLIENT, "Don't know what to do with message %s", type);

        } else {

            stream_info_t * si;
            HASH_FIND(hh, ci->open_streams, &msg->stream_id, 2, si);
            if (!si) {
                DBG("Message of c/t %s ignored", msg->message.content_type);
                break;
            }

            // confirm the message to the caller.
            // https://gitlab.excelfore.com/schema/json/xl4bus/message-confirm.json
            json_object * json = json_object_new_object();
            json_object_object_add(json, "type", json_object_new_string("xl4bus.message-confirm"));

            xl4bus_ll_message_t x_msg;
            memset(&x_msg, 0, sizeof(xl4bus_ll_message_t));

            const char * bux = json_object_get_string(json);
            x_msg.message.data = bux;
            x_msg.message.data_len = strlen(bux) + 1;
            x_msg.message.content_type = "application/vnd.xl4.busmessage+json";

            x_msg.stream_id = msg->stream_id;
            x_msg.is_reply = 1;
            x_msg.is_final = 1;

            if ((err = xl4bus_send_ll_message(conn, &x_msg, 0, 0)) != E_XL4BUS_OK) {
                printf("failed to send a message : %s\n", xl4bus_strerr(err));
                dismiss_connection(ci, 1);
            }

            json_object_put(json);

            // let's send to all possible destinations.


        }

    } while (0);

    if (msg->is_final) {
        // if there is a final message on stream we track,
        // make sure to clean up.
        stream_info_t * si;
        HASH_FIND(hh, ci->open_streams, &msg->stream_id, 2, si);
        if (si) {
            cleanup_stream(ci, si);
        }
    }

    json_object_put(root);

    return err;

}

int pick_timeout(int t1, int t2) {
    if (t1 < 0) { return t2; }
    if (t2 < 0) { return t1; }
    if (t1 < t2) { return t1; }
    return t2;
}

void dismiss_connection(conn_info_t * ci, int need_shutdown) {

    if (need_shutdown) {
        xl4bus_shutdown_connection(ci->conn);
    }

    DL_DELETE(connections, ci);

    DBG("Dismissing connection %p/%p fd %d", ci, ci->conn, ci->conn->fd);

    shutdown(ci->conn->fd, SHUT_RDWR);
    close(ci->conn->fd);

    stream_info_t *si, *aux;

    HASH_ITER(hh, ci->open_streams, si, aux) {
        cleanup_stream(ci, si);
    }

    free(ci);
    free(ci->conn);

}

static void cleanup_stream(conn_info_t * ci, stream_info_t * si) {

    HASH_DEL(ci->open_streams, si);
    json_object_put(si->destinations);
    free(si);

}