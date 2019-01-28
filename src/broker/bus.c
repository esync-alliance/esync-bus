
#include <sys/socket.h>
#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>
#include "utlist.h"

#include "hash_list.h"

#include "broker.h"
#include "lib/common.h"
#include "lib/debug.h"
#include "lib/poll_help.h"

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

static void free_message_context(msg_context_t *);

static conn_info_hash_list_t * ci_by_name = 0;
static conn_info_hash_list_t * ci_by_x5t = 0;

int brk_on_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

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

        DBG("Incoming BUS object: %p-%04x %s", conn, msg->stream_id, json_object_get_string(vot.bus_object));

        if (vot.x5c) {

            id.type = XL4BIT_X509;

            size_t certs = json_object_array_length(vot.x5c);

            id.x509.chain = f_malloc(sizeof(void*) * (certs+1));

            for (size_t i=0; i<certs; i++) {
                id.x509.chain[i] = f_malloc(sizeof(xl4bus_asn1_t));
                id.x509.chain[i]->enc = XL4BUS_ASN1ENC_DER;
                const char * in = json_object_get_string(json_object_array_get_idx(vot.x5c, i));
                size_t in_len = strlen(in);
                BOLT_CJOSE(cjose_base64_decode(in, in_len, &id.x509.chain[i]->buf.data, &id.x509.chain[i]->buf.len, &c_err));
            }

            BOLT_NEST();

            BOLT_SUB(xl4bus_set_remote_identity(conn, &id));

            if (debug) {
                char * json_addr;
                int addr_err;
                if ((addr_err = xl4bus_address_to_json(conn->remote_address_list, &json_addr)) != E_XL4BUS_OK) {
                    json_addr = f_asprintf("Failed to stringify address: %d", addr_err);
                }
                DBG("Connection %p - identity set to %s", conn, json_addr);
                free(json_addr);
            }

            E900(f_asprintf("Connection %p identified", conn), conn->remote_address_list, 0);

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

        // DBG("Incoming message content type %s", vot.content_type);

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

            // DBG("LLP message type %s", type);

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
                    E900(f_asprintf("%p-%04x has no viable destinations for %s", conn, msg->stream_id, req_dest), conn->remote_address_list, 0);
                }

                break;

            } else if (!strcmp("xl4bus.request-cert", type)) {

                json_object * x5c = json_object_new_array();

                if (json_object_object_get_ex(root, "body", &aux) && json_object_is_type(aux, json_type_object)) {
                    json_object *array;
                    if (json_object_object_get_ex(aux, "x5t#S256", &array) &&
                        json_object_is_type(array, json_type_array)) {

                        size_t l = json_object_array_length(array);
                        for (size_t i=0; i<l; i++) {

                            json_object * x5t_json = json_object_array_get_idx(array, i);
                            if (!json_object_is_type(x5t_json, json_type_string)) { continue; }

                            const char * x5t = json_object_get_string(x5t_json);

                            UT_array * items = 0;

                            conn_info_hash_list_t * val;
                            HASH_FIND(hh, ci_by_x5t, x5t, strlen(x5t)+1, val);
                            if (val) {
                                items = &val->items;
                            }

                            if (!items) { continue; }

                            int l2 = utarray_len(items);

                            // because these must be the same x5t, we only need
                            // to send out one x5c, because they all must be the same

                            if (l2 > 1) { l2 = 1; }

                            for (int j=0; j<l2; j++) {

                                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(items, j);
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

                E900(f_asprintf("Confirmed receipt of %p-%04x", conn, msg->stream_id), conn->remote_address_list, 0);

                BOLT_IF(!msg->is_final, E_XL4BUS_CLIENT, "Message confirmation must be final");
                break;
            }

            BOLT_SAY(E_XL4BUS_CLIENT, "Don't know what to do with XL4 message type %s", type);

        } else {

            json_object * destinations;

            uint16_t stream_id = msg->stream_id;

            in_msg_id = f_asprintf("%p-%04x", conn, (unsigned int)stream_id);

            if (!json_object_object_get_ex(vot.bus_object, "destinations", &destinations)) {
                E900(f_asprintf("Rejected message %s - no destinations", in_msg_id), conn->remote_address_list, 0);
                BOLT_SAY(E_XL4BUS_DATA, "Not XL4 message, no destinations in bus object");
            }

            BOLT_SUB(xl4bus_json_to_address(json_object_get_string(destinations), &forward_to));

            gather_all_destinations(forward_to, &send_list);

            int l = utarray_len(&send_list);

            // DBG("Received application message, has %d send list elements", l);

            E900(f_asprintf("Incoming message %s", in_msg_id), conn->remote_address_list, forward_to);

            count(1, 0);

            int sent_to_any = 0;

            for (int i=0; i<l; i++) {
                conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(&send_list, i);
                if (ci2 == ci) {
                    // DBG("Ignored one sender - loopback");
                    // prevent loopback
                    continue;
                }

                sent_to_any = 1;

                // the message is not final, the other side may return a certificate request.
                msg->is_final = 0;
                msg->is_reply = 0;

                count(0, 1);

                // note: we are sending data that is inside the incoming message.
                // this only works so far because we are not using multi-threading
                // but eventually we should not do that, nor use incoming message
                // structure for anything.

                msg_context_t * ctx = f_malloc(sizeof(msg_context_t));

                do {


                    BOLT_SUB(xl4bus_get_next_outgoing_stream(ci2->conn, &msg->stream_id));

                    ctx->magic = MAGIC_CLIENT_MESSAGE;
                    // $TODO: we should respond to failures
                    BOLT_SUB(xl4bus_copy_address(conn->remote_address_list, 1, &ctx->from));
                    BOLT_SUB(xl4bus_copy_address(forward_to, 1, &ctx->to));
                    BOLT_MEM(ctx->in_msg_id = f_strdup(in_msg_id));

                    int sub_err = xl4bus_send_ll_message(ci2->conn, msg, ctx, 0);

                    if (sub_err) {
                        // printf("failed to send a message : %s\n", xl4bus_strerr(err));
                        E900(f_asprintf("Failed to send message %s as %p-%04x: %s", in_msg_id, ci2->conn,
                                (unsigned int)msg->stream_id, xl4bus_strerr(sub_err)),
                                conn->remote_address_list, forward_to);
                        xl4bus_shutdown_connection(ci2->conn);
                    }

                    ctx = 0;

                    // ESYNC-1345 - the on_sent_message is always called in m/t model.
                    // so the context will be cleaned up in callback.

                } while (0);

                free_message_context(ctx);

            }

            if (!sent_to_any) {
                E900(f_asprintf("Message %s perished - no effective destinations", in_msg_id),
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

#if XL4_HAVE_EPOLL
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
#endif

void on_sent_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, void * arg, int err) {

    msg_context_t * ctx = arg;
    if (ctx->magic == MAGIC_CLIENT_MESSAGE) {

        if (err == E_XL4BUS_OK) {
            E900(f_asprintf("Low level accepted %s as %p-%04x", ctx->in_msg_id, conn,
                    (unsigned int)msg->stream_id), ctx->from, ctx->to);
        } else {
            E900(f_asprintf("Low level rejected %s as %p-%04x : %s", ctx->in_msg_id, conn,
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

void free_message_context(msg_context_t * ctx) {

    if (!ctx) { return; }

    if (ctx->magic == MAGIC_CLIENT_MESSAGE) {
        xl4bus_free_address(ctx->from, 1);
        xl4bus_free_address(ctx->to, 1);
        free(ctx->in_msg_id);
    }

    free(ctx);

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

        DBG("Outgoing on %p-%04x : %s", conn, stream_id, json_object_get_string(json));

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

int on_stream_close(struct xl4bus_connection * conn, uint16_t stream, xl4bus_stream_close_reason_t scr) {

    DBG("Stream %p-%04x closed, reason: %d", conn, stream, (int)scr);

}
