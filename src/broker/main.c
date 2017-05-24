
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h>
#include "json.h"

#include <libxl4bus/low_level.h>
#include <uthash.h>
#include <utarray.h>

#include "broker/debug.h"
#include "broker/common.h"

static int in_message(xl4bus_connection_t *, xl4bus_ll_message_t *);
static void * run_conn(void *);
static int set_poll(xl4bus_connection_t *, int);

static inline int void_cmp_fun(const void * a, const void * b) {
    if ((uintptr_t)b > (uintptr_t)a) {
        return 1;
    } else if (a == b) {
        return 0;
    }
    return -1;
}

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
        utarray_new(__list->items, &ut_ptr_icd); \
    } \
    ADD_TO_ARRAY_ONCE(__list->items, obj); \
} while(0)

typedef struct conn_info {

    struct pollfd pfd;
    int reg_req;

    terminal_type_t terminal;
    char * ua_name;
    int group_count;
    char ** groups;

} conn_info_t;



typedef struct conn_info_hash_list {
    UT_hash_handle hh;
    UT_array * items;
} conn_info_hash_list_t;

int debug = 1;

static conn_info_hash_list_t * ci_by_name = 0;
static conn_info_hash_list_t * ci_by_group = 0;
UT_array * dm_clients;

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

    if (bind(fd, (struct sockaddr*)&b_addr, sizeof(b_addr))) {
        perror("bind");
        return 1;
    }

    if (listen(fd, 5)) {
        perror("listen");
        return 1;
    }

    while (1) {

        socklen_t b_addr_len = sizeof(b_addr);
        int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
        if (fd2 < 0) {
            perror("accept");
            return 1;
        }

        xl4bus_connection_t * conn = malloc(sizeof(xl4bus_connection_t));
        if (!conn) {
            perror("malloc");
            return 1;
        }

        memset(conn, 0, sizeof(xl4bus_connection_t));

        conn->ll_message = in_message;
        conn->fd = fd2;

        conn->set_poll = set_poll;

        pthread_t nt;

        if (pthread_create(&nt, 0, run_conn, conn)) {
            perror("pthread_create");
            return 1;
        }

    }
}

void * run_conn(void * _arg) {

    xl4bus_connection_t * conn = (xl4bus_connection_t*)_arg;

    conn_info_t ci;

    memset(&ci, 0, sizeof(ci));

    ci.pfd.fd = conn->fd;
    conn->custom = &ci;

    int err = xl4bus_init_connection(conn);

    if (err == E_XL4BUS_OK) {

        // send initial message - alg-supported
        // https://gitlab.excelfore.com/schema/json/xl4bus/alg-supported.json
        json_object * json = json_object_new_object();
        json_object * aux;
        json_object * body;
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

        const char * bux = json_object_get_string(json);
        msg.message.data = bux;
        msg.message.data_len = strlen(bux) + 1;
        msg.message.content_type = "application/vnd.xl4.busmessage+json";

        if ((err = xl4bus_send_ll_message(conn, &msg, 0)) != E_XL4BUS_OK) {
            printf("failed to send a message : %s\n", xl4bus_strerr(err));
        }

        json_object_put(json);

    }

    int timeout = -1;

    while (1) {

        if (err != E_XL4BUS_OK) { break; }

        int rc = poll(&ci.pfd, 1, timeout);
        if (rc < 0) {
            perror("poll");
            break;
        }

        int flags = 0;
        if (ci.pfd.revents & (POLLIN | POLLPRI)) {
            flags = XL4BUS_POLL_READ;
        } else if (ci.pfd.revents & POLLOUT) {
            flags |= XL4BUS_POLL_WRITE;
        } else if (ci.pfd.revents & (POLLHUP | POLLNVAL)) {
            flags |= XL4BUS_POLL_ERR;
        }

        if (xl4bus_process_connection(conn, flags, &timeout) != E_XL4BUS_OK) {
            break;
        }

    }

    printf("Shutting down connection %d\n", conn->fd);
    shutdown(conn->fd, SHUT_RDWR);
    close(conn->fd);
    free(conn);

    return 0;

}

int set_poll(xl4bus_connection_t * conn, int flg) {

    conn_info_t * ci = conn->custom;

    ci->pfd.events = 0;

    if (flg & XL4BUS_POLL_READ) {
        ci->pfd.events = POLLIN;
    }
    if (flg & XL4BUS_POLL_WRITE) {
        ci->pfd.events |= POLLOUT;
    }
    return E_XL4BUS_OK;

}

int in_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int err = E_XL4BUS_OK;
    json_object * root = 0;

    do {

        conn_info_t * ci = conn->custom;

        if (!strcmp("application/vnd.xl4.busmessage+json", msg->message.content_type)) {

            // the json must be ASCIIZ.
            BOLT_IF(((uint8_t*)msg->message.data)[msg->message.data_len-1], E_XL4BUS_CLIENT,
                    "Incoming message is not ASCIIZ");

            BOLT_IF(!(root = json_tokener_parse(msg->message.data)), E_XL4BUS_CLIENT, "Not valid json: %s", msg->message.data);

            json_object * aux;
            BOLT_IF(!json_object_object_get_ex(root, "type", &aux) || !json_object_is_type(aux, json_type_string),
                    E_XL4BUS_CLIENT, "No/non-string type property in %s", msg->message.data);

            const char * type = json_object_get_string(aux);

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
                        ADD_TO_ARRAY_ONCE(dm_clients, ci);
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

                if ((err = xl4bus_send_ll_message(conn, &x_msg, 0)) != E_XL4BUS_OK) {
                    printf("failed to send a message : %s\n", xl4bus_strerr(err));
                }

                json_object_put(json);

                break;

            }

            BOLT_SAY(E_XL4BUS_CLIENT, "Don't know what to do with message %s", type);

        } else {

            BOLT_SAY(E_XL4BUS_CLIENT, "Message of c/t %s ignored", msg->message.content_type);

        }


    } while (0);

    json_object_put(root);

    return err;

}
