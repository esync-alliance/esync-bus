
#include <libxl4bus/high_level.h>
#include <libxl4bus/low_level.h>
#include <netdb.h>
#include "internal.h"
#include "misc.h"
#include "basics.h"
#include "lib/hash_list.h"
#include "lib/url_decode.h"
#include "bus-test-support.h"
#include "client_message.h"
#include "itc.h"

#if WITH_UNIT_TEST
xl4bus_pause_callback test_pause_callback = 0;
xl4bus_handle_ll_message test_message_interceptor = 0;
control_message_interceptor test_control_message_interceptor = 0;
connect_interceptor test_connect_interceptor = 0;
#endif

#if XL4_PROVIDE_THREADS

typedef struct aes_search_data {
    char * missing_kid;
    char * missing_x5t;
    remote_info_t * remote;
    xl4bus_connection_t * conn;
    cjose_jwk_t * key;
} aes_search_data_t;

typedef struct ll_message_container {

    xl4bus_ll_message_t msg;

    void * data;
    char * content_type;
    json_object * json;
    json_object * bus_object;

} ll_message_container_t;

static void client_thread(void *);

/**
 * If remove request is issued, client's poll_info is modified to have the fd found, and set to -1.
 * Otherwise, poll_info is scanned for the fd, or a free slot. If none are found, array is extended by 1.
 * The modes intended for the descriptor are set in the corresponding element.
 * @param clt client that requested the poll change
 * @param fd fd to change
 * @param modes modes, request read or write events, or remove the fd
 * @return
 */
static int internal_set_poll(xl4bus_client_t * clt, int fd, int modes);
static int apply_timeouts(xl4bus_client_t *, int need_timeout);
static void clean_expired_things(xl4bus_client_t *);

#endif

#if XL4_PROVIDE_DEBUG
static char * state_str(client_state_t);
#endif

#if XL4_SUPPORT_THREADS
#define SEND_LL(a,b,c,d) xl4bus_send_ll_message(a,b,c,(a)->mt_support && !(d))
#else
#define SEND_LL(a,b,c,d) xl4bus_send_ll_message(a,b,c)
#endif

#if XL4_SUPPORT_RESOLVER
static void ares_gethostbyname_cb(void *, int, int unused0, struct hostent*);
#endif

static int accept_resolved_address(xl4bus_client_t * clt, struct hostent*);
static void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t);

/**
 * Default implementation of the xl4bus_set_ll_poll function type for the high
 * level client. The implementation sets the last known timeout (for timeout operations),
 * otherwise ensures (if poll modes are !0) the descriptor is ensured to be registered in client->known_fd,
 * and client->set_poll() is called for the affected file descriptor.
 * @param fd file descriptor to set poll for, or timeout indicator
 * @param mode_or_timeout poll mode, or timeout value
 * @return E_XL4BUS_OK or errors of the caller's set poll failed, or memory could not be allocated if needed.
 */
static int ll_poll_cb(struct xl4bus_connection*, int fd, int mode_or_timeout);
static int ll_msg_cb(struct xl4bus_connection*, xl4bus_ll_message_t *);
static void ll_send_cb(struct xl4bus_connection*, xl4bus_ll_message_t *, void *, int);
static void ll_shutdown_cb(xl4bus_connection_t *);
static int create_ll_connection(xl4bus_client_t *);
static void process_message_out(xl4bus_client_t *, message_internal_t *, int on_internal_thread);
static int get_xl4bus_message_dav(decrypt_and_verify_data_t * dav, json_object **, char const **);
static int get_xl4bus_message(char const * data, size_t data_len, char const * ct, json_object **, char const **);
static void release_message(xl4bus_client_t *, message_internal_t *, int);
static int handle_presence(xl4bus_client_t * clt, json_object*);
static int pick_timeout(int t1, int t2);
static int send_json_message(xl4bus_client_t * clt, int use_session, int is_reply, int is_final, uint16_t stream_id,
        const char * type, /* copies */ json_object * body, int thread_safe);
static int send_main_message(xl4bus_client_t * clt, message_internal_t * mint);
static int send_client_json_message(xl4bus_client_t * clt, remote_info_t * remote,
        int is_reply, int is_final, uint16_t stream_id, const char * type, /* copies */ json_object * body);
static const cjose_jwk_t * rsa_key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void *data);
static const cjose_jwk_t * aes_key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void *data);
static void stop_client_ts(xl4bus_client_t * clt, xl4bus_client_condition_t how);
static int to_broker(xl4bus_client_t *, ll_message_container_t * msg, xl4bus_address_t * addr, int, int);
static void free_outgoing_message(ll_message_container_t *);
static int receive_cert_details(xl4bus_client_t *, message_internal_t *, xl4bus_ll_message_t *, json_object *);
static int send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg, int on_internal_thread);
static int record_mint(xl4bus_client_t * clt, message_internal_t * mint, int is_add, int with_list,
        int with_hash, int with_kid_hash_list);
static void record_mint_nl(xl4bus_client_t * clt, message_internal_t * mint, int is_add, int with_list,
        int with_hash, int with_kid_list);
static void dispose_message(xl4bus_client_t *clt, message_internal_t *mint);
static void release_remotes(message_internal_t * mint);
static int is_expired(message_internal_t *);
static void reattempt_pending_message(xl4bus_connection_t *, message_internal_t *, int * need_reconnect);
static int handle_state_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, message_internal_t * mint, int * need_reconnect);
int handle_client_message(message_internal_t * mint, xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, int * need_reconnect);
static int is_mint_incoming(message_internal_t *mint);

#if !WITH_UNIT_TEST
static int xl4bus_process_ll_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg);
static int get_xl4bus_message_msg(xl4bus_ll_message_t const *, json_object **, char const **);
static int xl4bus_process_client_message(xl4bus_client_t * clt, xl4bus_ll_message_t *, decrypt_and_verify_data_t  *, json_object *, char const * type, int * need_reconnect);
#endif

#define CHANGE_MIS(mint,__mis, how, c...) do { \
    DBG("mint %p state %d->%d : " how, mint, mint->mis, __mis, ## c); \
    mint->mis = __mis; \
} while(0)

MAKE_REF_FUNCTION(message_internal) {
    STD_REF_FUNCTION(message_internal);
}

MAKE_UNREF_FUNCTION(message_internal) {

    STD_UNREF_FUNCTION(message_internal);

    release_remotes(obj);
    json_object_put(obj->addr);

    cfg.free((void*)obj->ll_msg.data);
    cfg.free((void*)obj->ll_msg.content_type);

    cfg.free(obj->needs_kid);

    cfg.free(obj);

}


int xl4bus_init_client(xl4bus_client_t * clt, char * url) {

    int err = E_XL4BUS_OK;
    client_internal_t * i_clt = 0;
    char * url_copy = 0;

    do {

        BOLT_MALLOC(clt->_private, sizeof(client_internal_t));
        i_clt = clt->_private;

        DBG("Connecting to %s", SAFE_STR(url));

        BOLT_IF(!url || strncmp("tcp://", url, 6), E_XL4BUS_ARG, "invalid url schema");
        size_t l = strlen(url+6);
        BOLT_MALLOC(url_copy, l+1);
        strcpy(url_copy, url+6);
        char * colon = strchr(url_copy, ':');
        BOLT_IF(!colon, E_XL4BUS_ARG, "no port separator");
        BOLT_IF(colon == url_copy, E_XL4BUS_ARG, "no host name");
        *(colon++) = 0;

        char * qm = strchr(colon+1, '?');
        if (qm) {
            *qm = 0;
            qm++;
        }

        while (qm) {
            char * qp = qm;
            qm = strchr(qm, '&');
            if (qm) {
                *qm = 0;
                qm++;
            }

            char * val = strchr(qp, '=');
            if (val) {
                *val = 0;
                val++;
            }

            decode_url(qp);
            decode_url(val);

            if (!val) { val = ""; }

            if (!z_strcmp("if", qp) && *val) {
                i_clt->net_if = val;
                if (!pf_is_feature_supported(PF_FEATURE_IF_ADDR)) {
                    DBG("Your implementation doesn't support setting source interface");
                }
            } else {
                DBG("Unrecognized URL parameter: name: %s, value: %s", qp, val);
            }

        }

        int port = atoi(colon);
        BOLT_IF(port <= 0 || port > 65535, E_XL4BUS_ARG, "invalid port value");
        i_clt->port = port;
        i_clt->host = url_copy;
        i_clt->state = CS_DOWN;
        i_clt->tcp_fd = -1;

#if XL4_SUPPORT_RESOLVER
        BOLT_ARES(ares_init(&i_clt->ares));
#endif

#if XL4_PROVIDE_THREADS
        BOLT_SYS(pf_init_lock(&i_clt->hash_lock), "");
        if (clt->use_internal_thread) {
            clt->mt_support = 1;
            clt->set_poll = internal_set_poll;
        }
        if (clt->mt_support) {
            int pair[2];
            BOLT_SYS(pf_dgram_pair(pair), "creating DGRAM pair");
            BOLT_SYS(pf_set_nonblocking(i_clt->mt_read_socket = pair[0]), "setting non-blocking");
            i_clt->mt_write_socket = pair[1];
            BOLT_SUB(clt->set_poll(clt, i_clt->mt_read_socket, XL4BUS_POLL_READ));
        }
        if (clt->use_internal_thread) {
            BOLT_SYS(pf_start_thread(client_thread, clt), "starting client thread");
        } else {
#endif
            if (clt->on_status) {
                clt->on_status(clt, XL4BCC_CLIENT_START);
            }
#if XL4_PROVIDE_THREADS
        }
#endif

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    // note, the caller must call process_client right away.

    if (err != E_XL4BUS_OK) {

#if XL4_SUPPORT_RESOLVER
        if (i_clt) {
            ares_destroy(i_clt->ares);
        }
#endif
        cfg.free(i_clt);
        cfg.free(url_copy);
        clt->_private = 0;
    }

    return err;

}

int xl4bus_flag_poll(xl4bus_client_t * clt, int fd, int modes) {

    int err = E_XL4BUS_OK;

    do {

        client_internal_t * i_clt = clt->_private;
        if (i_clt->pending_len == i_clt->pending_cap) {
            BOLT_REALLOC(i_clt->pending, pending_fd_t, i_clt->pending_cap + 1, i_clt->pending_cap);
        }
        pending_fd_t * pfd = i_clt->pending + i_clt->pending_len++;
        pfd->fd = fd;
        pfd->flags = modes;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}

void xl4bus_run_client(xl4bus_client_t * clt, int * timeout) {

    client_internal_t * i_clt = clt->_private;
    // if somebody wants to set the timeout, they better do it.
    *timeout = -1;
    int err = E_XL4BUS_OK;

    while (1) {

        // DBG("Run processing state %s", state_str(i_clt->state));

        int old_state = i_clt->state;

        if (i_clt->state == CS_DOWN) {

            // did we expire the "down" counter?
            uint64_t left;
            if (!i_clt->down_target) {
                left = 0;
            } else {
                uint64_t now = pf_ms_value();
                if (now >= i_clt->down_target) {
                    left = 0;
                } else {
                    left = i_clt->down_target - now;
                }
            }

            if (left > 0) {

                *timeout = pick_timeout(*timeout, (int) left);

            } else {

                int family;

#if XL4_SUPPORT_IPV4
                family = AF_INET;
#elif XL4_SUPPORT_IPV6
                family = AF_INET6;
#else
#error  No address family configured, please configure at least one
#endif

                // we are ready to come out of DOWN state.
                // first need we need to do is to resolve our broker address.
                i_clt->state = CS_RESOLVING;
                DBG("Resolving host %s, family %d", i_clt->host, family);

#if XL4_SUPPORT_IPV6 && XL4_SUPPORT_IPV4
                // if we need both addresses
                i_clt->dual_ip = 1;
#endif

#if XL4_SUPPORT_RESOLVER
                ares_gethostbyname(i_clt->ares, i_clt->host,
                        family, ares_gethostbyname_cb, clt);
#else
                struct addrinfo * addrs = 0;
                if (is_ip_addr(i_clt->host, family)) {
                    if (create_addrinfo(i_clt->host, family, &addrs)) {
                        DBG("Failed to create addrinfo");
                    }
                } else {
                    int res;
                    struct addrinfo hints = {.ai_family = family,
                                             .ai_socktype = SOCK_STREAM };
                    if ((res = getaddrinfo(i_clt->host, 0, &hints, &addrs))) {
                        DBG("getaddrinfo() failed: %s", gai_strerror(res));
                    }
                }
                if (!addrs) {
                    drop_client(clt, XL4BCC_RESOLUTION_FAILED);
                    continue;
                }

                struct addrinfo * next = addrs;
                int addr_count = 0;
                while (next) {
                    char * addr_list[2] = { 0, 0};
                    struct hostent ent = {
                            .h_addrtype = next->ai_family,
                            .h_addr_list = addr_list,
                    };

                    int addr_ok = 0;

#if XL4_SUPPORT_IPV4
                    if (next->ai_family == AF_INET) {
                        addr_ok = 1;
                        ent.h_length = 4;
                        addr_list[0] = (char*)&((struct sockaddr_in*)next->ai_addr)->sin_addr;
                    }
#endif
#if XL4_SUPPORT_IPV6
                    if (next->ai_family == AF_INET6) {
                        addr_ok = 1;
                        ent.h_length = 16;
                        addr_list[0] = (char*)&((struct sockaddr_in6*)next->ai_addr)->sin6_addr;
                    }
#endif

                    if (!addr_ok) {
                        DBG("Unsupported address family %d", next->ai_family);
                    }

                    if (addr_ok && accept_resolved_address(clt, &ent) == E_XL4BUS_OK) {
                        addr_count++;
                    }
                    next = next->ai_next;
                }

                freeaddrinfo(addrs);

                if (!addr_count) {
                    DBG("No addresses could be used");
                    drop_client(clt, XL4BCC_RESOLUTION_FAILED);
                    continue;
                }

                i_clt->state = CS_CONNECTING;
                continue;
#endif

            }

        }

        // we may have requested c-ares FDs to be polled.
        fd_set read;
        fd_set write;
        FD_ZERO(&read);
        FD_ZERO(&write);

        known_fd_t * fdi;
        int ll_called = 0;

        for (int i=0; i<i_clt->pending_len; i++) {

            pending_fd_t * pfd = i_clt->pending + i;
            HASH_FIND_INT(i_clt->known_fd, &pfd->fd, fdi);

            if (fdi && fdi->is_ll_conn) {

                if (i_clt->state == CS_CONNECTING) {

                    if (pfd->flags & XL4BUS_POLL_READ) {
                        // this should not happen.
                        BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_WRITE));
                    }

                    // Use of XL4BUS_POLL_ERR is just in case, it should never
                    // happen.
                    if (pfd->flags & (XL4BUS_POLL_WRITE|XL4BUS_POLL_ERR)) {

                        // no matter what, we should remove that
                        // socket. When needed, the poll request from the low-level
                        // will put it back.
                        BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_REMOVE));
                        HASH_DEL(i_clt->known_fd, fdi);
                        cfg.free(fdi);

                        // if it's the write event, and we are connecting, it can either
                        // indicate an error, or successful connection.
                        if (pf_get_socket_error(i_clt->tcp_fd)) {
                            pf_close(i_clt->tcp_fd);
                            i_clt->tcp_fd = -1;
                        } else {
                            create_ll_connection(clt);
                        }
                    }

                } else if (i_clt->ll) {

                    // no need to process error condition here, xl4bus_process_connection
                    // will do it.

                    ll_called = 1;
                    if (xl4bus_process_connection(i_clt->ll, pfd->fd, pfd->flags) != E_XL4BUS_OK) {
                        cfg.free(i_clt->ll);
                        i_clt->ll = 0;
                        drop_client(clt, XL4BCC_CONNECTION_BROKE);
                        continue;
                    }
                    *timeout = pick_timeout(i_clt->ll_timeout, *timeout);

                }

#if XL4_SUPPORT_THREADS

            } else if (pfd->fd == i_clt->mt_read_socket) {

                int abort = 0;

                if (pfd->flags & XL4BUS_POLL_ERR) {
                    int sock_err = pf_get_socket_error(pfd->fd);
                    pf_set_errno(sock_err);
                    DBG_SYS("error on internal datagram socket, aborting client");
                    abort = 1;
                } else if (pfd->flags & XL4BUS_POLL_WRITE) {
                    DBG("write event on read-only internal socket");
                    abort = 1;
                }

                if (!abort) {

                    void *ctl_buf = 0;

                    ssize_t buf_read = pf_recv_dgram(pfd->fd, &ctl_buf, f_malloc);
                    if (buf_read <= 0) {
                        DBG_SYS("recv() EOF/error");
                        abort = 1;
                    } else if (buf_read != sizeof(itc_message_t)) {
                        DBG("Invalid IT message size, needed %d, got %d",
                                sizeof(itc_message_t), (int) buf_read);
                        abort = 1;

                    } else {

                        itc_message_t *itc = ctl_buf;

                        if (itc->magic == ITC_STOP_CLIENT_MAGIC) {
                            ((client_internal_t *) ((itc->client))->_private)->stop = 1;
                        } else if (itc->magic == ITC_CLIENT_MESSAGE_MAGIC) {

                            process_message_out(itc->client_msg.client, itc->client_msg.mint, 1);
                            unref_message_internal(itc->client_msg.mint);

                        } else

#if WITH_UNIT_TEST

                            if (itc->magic == ITC_PAUSE_RCV_MAGIC) {
                                xl4bus_client_t * clt2 = itc->pause.client;
                                ((client_internal_t *) clt2->_private)->rcv_paused = itc->pause.pause;
                                if (test_pause_callback) {
                                    test_pause_callback(clt2, itc->pause.pause);
                                }
                            } else
#endif

                            do {
                                DBG("Unknown ITC message %"PRIx32, itc->magic);
                                abort = 1;
                            } while (0);
                    }

                    free(ctl_buf);

                    if (abort) {
                        stop_client_ts(clt, XL4BCC_CONNECTION_ABORTED);
                        break;
                    }

                }

            }

#endif
            else {

                // this is ARES socket then.

                if (pfd->flags & XL4BUS_POLL_ERR) {

                    // there is no clear answer on what to do if there is an error
                    // (see https://c-ares.haxx.se/mail/c-ares-archive-2017-05/0014.shtml)
                    // so, for now, let's clear the socket error, and trigger both
                    // read/write. Note that we must at least gobble up the error,
                    // otherwise the poll will keep waking us up forever (ESYNC-700)

                    int sock_err = pf_get_socket_error(pfd->fd);
                    if (cfg.debug_f) {
                        pf_set_errno(sock_err);
                        DBG_SYS("error on ares socket %d, cleared", pfd->fd);
                    }
                    FD_SET(pfd->fd, &read);
                    FD_SET(pfd->fd, &write);
                }

                if (pfd->flags & XL4BUS_POLL_READ) {
                    FD_SET(pfd->fd, &read);
                }
                if (pfd->flags & XL4BUS_POLL_WRITE) {
                    FD_SET(pfd->fd, &write);
                }
            }

        }

        BOLT_SUB(err);

#if XL4_SUPPORT_RESOLVER
        ares_process(i_clt->ares, &read, &write);
#endif

        // reset any polled events.
        i_clt->pending_len = 0;

        FD_ZERO(&read);
        FD_ZERO(&write);

#if XL4_SUPPORT_RESOLVER
        int mfd = ares_fds(i_clt->ares, &read, &write);
#endif

        known_fd_t * aux;

        HASH_ITER(hh, i_clt->known_fd, fdi, aux) {

            int reason = 0;

            if (fdi->is_ll_conn) {
                // callback must set the reason for the ll conn!
                reason = fdi->modes;
            } else {
                if (FD_ISSET(fdi->fd, &read)) {
                    reason |= XL4BUS_POLL_READ;
                    FD_CLR(fdi->fd, &read);
                }

                if (FD_ISSET(fdi->fd, &write)) {
                    reason |= XL4BUS_POLL_WRITE;
                    FD_CLR(fdi->fd, &write);
                }
            }

            if (!reason) {
                BOLT_SUB(clt->set_poll(clt, fdi->fd, XL4BUS_POLL_REMOVE));
                HASH_DEL(i_clt->known_fd, fdi);
                free(fdi);
            } else {
                if (fdi->modes != reason) {
                    BOLT_SUB(clt->set_poll(clt, fdi->fd, reason));
                    fdi->modes = reason;
                }
            }
        }

#if XL4_SUPPORT_RESOLVER
        // now make sure we add all C-ARES pollers.
        for (int i=0; i<mfd; i++) {
            int reason = 0;

            if (FD_ISSET(i, &read)) {
                reason |= XL4BUS_POLL_READ;
            }

            if (FD_ISSET(i, &write)) {
                reason |= XL4BUS_POLL_WRITE;
            }

            if (reason) {
                BOLT_MALLOC(fdi, sizeof(known_fd_t));
                fdi->fd = i;
                fdi->modes = reason;
                HASH_ADD_INT(i_clt->known_fd, fd, fdi);
                BOLT_SUB(clt->set_poll(clt, i, reason));
            }

        }

        {
            // let's get c-ares timeout into the mix.
            struct timeval tv;
            struct timeval * rtv = ares_timeout(i_clt->ares, 0, &tv);
            if (rtv) {
                *timeout = pick_timeout(*timeout, timeval_to_millis(&tv));
            }

        }
#endif

        if (i_clt->state == CS_CONNECTING) {

            if (i_clt->tcp_fd < 0) {
                // socket has not been established, or we have failed.
                // try next address, or go down.
                ip_addr_t * addr = 0;

                DBG("Connecting to address #%d", i_clt->net_addr_current);

                if (i_clt->addresses) {
                    addr = &i_clt->addresses[i_clt->net_addr_current++];
                }
                if (!addr || addr->family == AF_UNSPEC) {
                    // no (more) addresses to try.
                    drop_client(clt, addr ? XL4BCC_CONNECTION_FAILED : XL4BCC_RESOLUTION_FAILED);
                    continue;
                }

                void * ip_addr = 0;
                size_t ip_len = 0;
#if XL4_SUPPORT_IPV6
                if (addr->family == AF_INET6) {
                    ip_addr = addr->ipv6;
                    ip_len = 16;
                }
#endif
#if XL4_SUPPORT_IPV4
                if (addr->family == AF_INET) {
                    ip_addr = addr->ipv4;
                    ip_len = 4;
                }
#endif

                DBG("Address family: %d", addr->family);

#if WITH_UNIT_TEST
                if (test_connect_interceptor) {
                    test_connect_interceptor(clt, ip_addr, ip_len, i_clt->port, i_clt->net_if);
                }
#endif

                int async;
                i_clt->tcp_fd = pf_connect_tcp(ip_addr, ip_len, (uint16_t) i_clt->port, i_clt->net_if, &async);

                if (i_clt->tcp_fd < 0) {
                    // failed right away, ugh. Let's move on then.
                    i_clt->repeat_process = 1;
                } else {
                    // connected, or going to connect
                    if (!async) {
                        BOLT_SUB(create_ll_connection(clt));
                    } else {
                        BOLT_MALLOC(fdi, sizeof(known_fd_t));
                        fdi->is_ll_conn = 1;
                        fdi->fd = i_clt->tcp_fd;
                        HASH_ADD_INT(i_clt->known_fd, fd, fdi);
                        BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_WRITE));
                    }
                }
            }
        }

        if (i_clt->ll && !ll_called) {
            // means we are calling low-level process_connection
            // because we timed out; this means we should reset the timeout
            i_clt->ll_timeout = -1;
            BOLT_SUB(xl4bus_process_connection(i_clt->ll, -1, 0));
            *timeout = apply_timeouts(clt, *timeout);
        }

        // if there is no change, let's get out.
        if (i_clt->state == old_state) {
            // but if somebody said it's OK, then sure.
            if (i_clt->repeat_process) {
                i_clt->repeat_process = 0;
                continue;
            }
            break;
        }

    }

    // DBG("Run exited, state %s, err %d", state_str(i_clt->state), err);

    if (err != E_XL4BUS_OK) {
        xl4bus_client_condition_t reason = XL4BCC_RUNNING;
        int do_drop = 1;
        switch (i_clt->state) {
            case CS_DOWN:
                do_drop = 0;
                break;
            case CS_RESOLVING:
                reason = XL4BCC_RESOLUTION_FAILED;
                break;
            case CS_CONNECTING:
                reason = XL4BCC_CONNECTION_FAILED;
                break;
            default:
            case CS_EXPECTING_ALGO:
            case CS_EXPECTING_CONFIRM:
                reason = XL4BCC_REGISTRATION_FAILED;
                break;
            case CS_RUNNING:
                reason = XL4BCC_CONNECTION_BROKE;
                break;
        }

        if (do_drop) {
            drop_client(clt, reason);
        }
    }

}

#if XL4_PROVIDE_THREADS

void client_thread(void * arg) {

    xl4bus_client_t * clt = arg;
    client_internal_t * i_clt = clt->_private;

    if (clt->on_status) {
        clt->on_status(clt, XL4BCC_CLIENT_START);
    }

    int timeout;
    xl4bus_run_client(clt, &timeout);

    while (1) {

        /*
        DBG("Clt %p: after run : poll requested timeout %d, poll_info has %d entries", clt, timeout,
                poll_info.polls_len);
        */

#if WITH_UNIT_TEST
        if (i_clt->rcv_paused) {
            // if the reception is paused, we can just not poll the corresponding
            // file descriptor for data
            for (int i=0; i<i_clt->poll_info.polls_len; i++) {
                if (i_clt->poll_info.polls[i].fd == i_clt->ll->fd) {
                    i_clt->poll_info.polls[i].events &= ~XL4BUS_POLL_READ;
                }
            }
        }
#endif

        int res = pf_poll(i_clt->poll_info.polls, i_clt->poll_info.polls_len, timeout);
        if (res < 0) {
            break;
        }

        // it's possible that while we were polling, we got an
        // instruction to stop.
        // $TODO: is it really possible, though?
        if (i_clt->stop) { break; }

        int poll_flag_failure = 0;

        for (int i=0; res && i<i_clt->poll_info.polls_len; i++) {
            pf_poll_t * pp = i_clt->poll_info.polls + i;
            if (pp->revents) {
                res--;
                // DBG("Clt %p : flagging %x for fd %d", clt, pp->revents, pp->fd);
                if (xl4bus_flag_poll(clt, pp->fd, pp->revents) != E_XL4BUS_OK) {
                    poll_flag_failure = 1;
                    break;
                }
            }
        }

        if (poll_flag_failure) { break; }

        xl4bus_run_client(clt, &timeout);

        if (i_clt->stop) {
            break;
        }

    }

    free(i_clt->poll_info.polls);

    stop_client_ts(clt, XL4BCC_CLIENT_STOPPED);

}

// prototype documented
int internal_set_poll(xl4bus_client_t *clt, int fd, int modes) {

    client_internal_t * i_clt = clt->_private;
    poll_info_t * poll_info = &i_clt->poll_info;

    // DBG("Clt %p requested to set poll %x for fd %d", clt, modes, fd);

    if (modes & XL4BUS_POLL_REMOVE) {

        // if mode has REMOVE, nothing else is valid.
        for (int i=0; i<poll_info->polls_len; i++) {
            if (poll_info->polls[i].fd == fd) {
                poll_info->polls[i].fd = -1;
                break;
            }
        }

    } else {

        // we first must find the poor fd.
        pf_poll_t * found = 0;
        pf_poll_t * free = 0;
        for (int i=0; i<poll_info->polls_len; i++) {
            pf_poll_t * poll = poll_info->polls + i;
            if (poll->fd == fd) {
                found = poll;
                break;
            } else if (poll->fd < 0) {
                free = poll;
            }
        }

        if (!found) {
            if (free) {
                found = free;
            } else {
                void * v = cfg.realloc(poll_info->polls, (poll_info->polls_len + 1) * sizeof(pf_poll_t));
                if (!v) {
                    return E_XL4BUS_MEMORY;
                }
                poll_info->polls = v;
                found = poll_info->polls + poll_info->polls_len++;
            }
            found->fd = fd;
        }

        found->events = (short)modes;
    }

    return E_XL4BUS_OK;

}

#endif

int  accept_resolved_address(xl4bus_client_t * clt, struct hostent* hent) {

    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    do {

        int addr_count;
        int addr_start;
        for (addr_count = 0; hent && hent->h_addr_list[addr_count]; addr_count++);

        if (!addr_count) {
            DBG("Hostent result has 0 addresses?");
            break;
        }

        addr_start = 0;
        if (i_clt->addresses) {
            for (; i_clt->addresses[addr_start].family != AF_UNSPEC; addr_start++);
        }

        int family = AF_UNSPEC;

#if XL4_SUPPORT_IPV6
        if (hent->h_addrtype == AF_INET6) {
            if (hent->h_length != 16) {
                DBG("Invalid address length %d for AF_INET6", hent->h_length);
            } else {
                family = AF_INET6;
            }
        }
#endif
#if XL4_SUPPORT_IPV4
        if (hent->h_addrtype == AF_INET) {
            family = AF_INET;
            if (hent->h_length != 4) {
                DBG("Invalid address length %d for AF_INET", hent->h_length);
            } else {
                family = AF_INET;
            }
        }
#endif

        if (family == AF_UNSPEC) {
            DBG("Unknown family %d", hent->h_addrtype);
            break;
        }

        BOLT_REALLOC_NS(i_clt->addresses, ip_addr_t, addr_start + addr_count + 1);
        for (int i=0; i <= addr_count; i++) {
            ip_addr_t * ip = i_clt->addresses + i + addr_start;
            if (i == addr_count) {
                ip->family = AF_UNSPEC; // last
            } else {
                ip->family = family;
#if XL4_SUPPORT_IPV4
                if (family == AF_INET) {
                    memcpy(ip->ipv4, hent->h_addr_list[i], 4);
                }
#endif
#if XL4_SUPPORT_IPV6
                if (family == AF_INET6) {
                    memcpy(ip->ipv6, hent->h_addr_list[i], 16);
                }
#endif

            }
        }


    } while (0);

    return err;

}

#if XL4_SUPPORT_RESOLVER

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void ares_gethostbyname_cb(void * arg, int status, int unused0, struct hostent* hent) {
#pragma clang diagnostic pop

    xl4bus_client_t * clt = arg;
    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    do {

        DBG("ARES reported status %d, hostent at %p, dual IP:%s", status, hent,
#if XL4_SUPPORT_IPV4 && XL4_SUPPORT_IPV6
            BOOL_STR(i_clt->dual_ip)
#else
            "N/A"
#endif
        );
        if (status != ARES_SUCCESS) {
            DBG("ARES query failed");
            break;
        }

        err = accept_resolved_address(clt, hent);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (err != E_XL4BUS_OK) {
        // realistically, this only happens if we ran out of memory
        drop_client(clt, XL4BCC_RESOLUTION_FAILED);
        return;
    }

#if XL4_SUPPORT_IPV6 && XL4_SUPPORT_IPV4
    if (i_clt->dual_ip) {
        DBG("Resolving host %s, force IPv6", i_clt->host);
        i_clt->repeat_process = 1;
        i_clt->dual_ip = 0;
        ares_gethostbyname(i_clt->ares, i_clt->host,
                AF_INET6, ares_gethostbyname_cb, clt);
        return;
    }
#endif

    // we are switching to the connecting state unconditionally,
    // but it's possible that we haven't received any names
    // post resolution. If there are no addresses known, then
    // connecting phase will fail rather quickly.
    i_clt->state = CS_CONNECTING;

}

#endif

void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t how) {

    DBG("Disconnecting client %p : %d", clt, how);

    client_internal_t * i_clt = clt->_private;
    if (!i_clt) {
        return;
    }
    i_clt->down_target = pf_ms_value() + XL4_CLIENT_RECONNECT_INTERVAL_MS;
    i_clt->state = CS_DOWN;
    i_clt->net_addr_current = 0;

    if (i_clt->tcp_fd >= 0) {
        pf_shutdown_rdwr(i_clt->tcp_fd);
        if (!i_clt->stop) {
            clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_REMOVE);
        }
        pf_close(i_clt->tcp_fd);
        i_clt->tcp_fd = -1;
    }

    if (i_clt->addresses) {
        cfg.free(i_clt->addresses);
        i_clt->addresses = 0;
    }

    cjose_jwk_release(i_clt->private_key);
    i_clt->private_key = 0;

    int dismiss_count = 0;
    message_internal_t ** to_dismiss = 0;

#if XL4_SUPPORT_THREADS
    if (!pf_lock(&i_clt->hash_lock)) {
#endif

#define FOR_DISPOSAL(a, how) do { \
    int err = E_XL4BUS_OK; \
    BOLT_REALLOC(to_dismiss, message_internal_t*, dismiss_count + 1, dismiss_count); \
    if (err == E_XL4BUS_OK) { \
        DBG("mint %p marked for disposal: %s", mint, how); \
        to_dismiss[dismiss_count-1] = ref_message_internal(a); \
    } \
} while(0)

        message_internal_t * mint;
        DL_FOREACH(i_clt->message_list, mint) {
            if (i_clt->stop) {
                FOR_DISPOSAL(mint, "client stopped");
                continue;
            }

            if (!is_mint_incoming(mint)) {
                if (is_expired(mint)) {
                    FOR_DISPOSAL(mint, "expired");
                } else {
                    CHANGE_MIS(mint, MIS_VIRGIN, "connection drop");
                    record_mint_nl(clt, mint, 0, 0, 1, 0);
                    mint->expired_count++;
                }
            } else {
                // ESYNC-4841 this code here used to preserve those messages
                // and attempt to process them when connection is re-established.
                // It's a bad idea because that requires messages to be sent on
                // the original stream the message came on, and that stream is not
                // available anymore.
                // record_mint_nl(clt, mint, 0, 0, 1, 0);
                FOR_DISPOSAL(mint, "incomplete incoming message");
            }

        }

#if XL4_SUPPORT_THREADS
    }
    pf_unlock(&i_clt->hash_lock);
#endif

    if (to_dismiss) {

        for (int i=0; i < dismiss_count; i++) {
            message_internal_t * mint = to_dismiss[i];
            if (is_mint_incoming(mint)) {
                dispose_message(clt, mint);
            } else {
                release_message(clt, mint, E_XL4BUS_UNDELIVERABLE);
            }
            unref_message_internal(mint);
        }

        cfg.free(to_dismiss);

    }

    if (i_clt->ll) {
        DBG("LLC shutting down %p in %p", i_clt->ll, clt);
        xl4bus_shutdown_connection(i_clt->ll);
        // $TODO: Is this safe to do from this (any) thread at this point?
        xl4bus_process_connection(i_clt->ll, -1, 0);
    }

    if (clt->on_status) {
        clt->on_status(clt, how);
    }

}

int is_mint_incoming(message_internal_t *mint) {

    return mint->mis == MIS_NEED_REMOTE || mint->mis == MIS_WAITING_KEY;

}


int create_ll_connection(xl4bus_client_t * clt) {

    int err;

    client_internal_t * i_clt = clt->_private;

    do {

        BOLT_MALLOC(i_clt->ll, sizeof(xl4bus_connection_t));

        i_clt->ll->fd = i_clt->tcp_fd;
        i_clt->ll->set_poll = ll_poll_cb;
        i_clt->ll->custom = clt;
        i_clt->ll->is_client = 1;
        i_clt->ll->on_message = ll_msg_cb;
        i_clt->ll->on_sent_message = ll_send_cb;
        i_clt->ll->cache = &i_clt->cache;
        i_clt->ll->on_shutdown = ll_shutdown_cb;

#if XL4_SUPPORT_THREADS

        i_clt->ll->mt_support = clt->mt_support;

#endif

        memcpy(&i_clt->ll->identity, &clt->identity, sizeof(clt->identity));

        // $TODO: The problem here is that we will ask for the private key
        // when this happens. If the user types it, it will be asked for
        // numerously, it's especially bad in case of the broker.
        BOLT_SUB(make_private_key(&i_clt->ll->identity, 0, &i_clt->private_key));

        BOLT_SUB(xl4bus_init_connection(i_clt->ll));
        DBG("LLC created %p in %p, my x5t is %s", i_clt->ll, clt, i_clt->ll->my_x5t);

        i_clt->state = CS_EXPECTING_ALGO;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}

// prototype documented
int ll_poll_cb(struct xl4bus_connection* conn, int fd, int modes_or_timeout) {

    int err = E_XL4BUS_OK;
    do {

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;
        BOLT_IF(i_clt->stop, E_XL4BUS_EOF, "Stopped client");

        clean_expired_things(clt);

        if (fd == XL4BUS_POLL_TIMEOUT_MS) {

            apply_timeouts(clt, modes_or_timeout);

        } else {

            // DBG("Clt %p: set poll to %x", conn, modes);

            known_fd_t * fdi;

            HASH_FIND_INT(i_clt->known_fd, &fd, fdi);
            if (!fdi && modes_or_timeout) {
                BOLT_MALLOC(fdi, sizeof(known_fd_t));
                fdi->fd = fd;
                fdi->is_ll_conn = 1;
                HASH_ADD_INT(i_clt->known_fd, fd, fdi);
            }

            if (fdi) {
                fdi->modes = modes_or_timeout;
                BOLT_SUB(clt->set_poll(clt, fdi->fd, modes_or_timeout));
            }

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}

int send_client_json_message(xl4bus_client_t * clt, remote_info_t * remote,
        int is_reply, int is_final, uint16_t stream_id, const char * type, json_object * body) {

    int err /*= E_XL4BUS_OK*/;
    ll_message_container_t * msg = 0;
    json_object * j_type = 0;
    char * jws_data = 0;
    size_t jws_data_len;
    char * jwe_data = 0;
    size_t jwe_data_len;
    json_object * bus_object = 0;

    do {

        DBG("XCHG %05x Sending client system message %s", stream_id, type);

        client_internal_t * i_clt = clt->_private;
        xl4bus_connection_t * conn = i_clt->ll;

        BOLT_MALLOC(msg, sizeof(ll_message_container_t));
        // DBG("--> alloc %p", msg);

        BOLT_MEM(msg->json = json_object_new_object());
        if (body) {
            BOLT_MEM(!json_object_object_add(msg->json, "body", body));
            json_object_get(body);
        }

        BOLT_MEM(j_type = json_object_new_string(type));
        BOLT_MEM(!json_object_object_add(msg->json, "type", j_type));
        j_type = 0;

        const char * bux = json_object_get_string(msg->json);
        BOLT_MEM(bus_object = json_object_new_object());

        BOLT_SUB(sign_jws(i_clt->private_key, conn->my_x5t, 0, bus_object, bux, strlen(bux) + 1, FCT_BUS_MESSAGE,
                &jws_data, &jws_data_len));

        BOLT_SUB(encrypt_jwe(remote->remote_public_key, remote->x5t, 0, jws_data, jws_data_len, FCT_JOSE_COMPACT,
                &jwe_data, &jwe_data_len));

        msg->msg.stream_id = stream_id;
        msg->msg.is_reply = is_reply;
        msg->msg.is_final = is_final;
        msg->msg.data = msg->data = jwe_data;
        jwe_data = 0;
        msg->msg.data_len = jwe_data_len;

        msg->msg.content_type = FCT_JOSE_COMPACT;
        msg->msg.uses_validation = 1;
        msg->msg.uses_encryption = 1;
        msg->msg.uses_session_key = 1;

        xl4bus_address_t to_addr = {
                .type = XL4BAT_X5T_S256,
                .x5ts256 = remote->x5t
        };

        BOLT_SUB(to_broker(clt, msg, &to_addr, 1, 1));
        msg = 0;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    json_object_put(j_type);
    json_object_put(bus_object);
    free(jws_data);
    free(jwe_data);

    DBG("--> clean up %p", msg);
    free_outgoing_message(msg);

    return err;

}

int send_main_message(xl4bus_client_t * clt, message_internal_t * mint) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    cjose_jwe_t * encrypted = 0;
    cjose_header_t * hdr = 0;
    cjose_jwe_recipient_t recipients[mint->key_idx];
    ll_message_container_t * msg = 0;
    cjose_jwk_t * key = 0;
    json_object * bus_object = json_object_new_object();

    do {

        client_internal_t * i_clt = clt->_private;

        BOLT_MALLOC(msg, sizeof(ll_message_container_t));

        msg->msg.stream_id = mint->stream_id;
        msg->msg.is_reply = 1;

        DBG("XCHG %05x Main message, will encrypt with %d keys", mint->stream_id, mint->key_idx);

        // encrypt the original message to all destinations

        // memset(recipients, 0, mint->key_idx * sizeof(cjose_jwe_recipient));
        for (int i=0; i<mint->key_idx; i++) {
            BOLT_SUB(update_remote_symmetric_key(i_clt->ll->my_x5t, mint->remotes[i]));
            BOLT_CJOSE(recipients[i].unprotected_header = cjose_header_new(&c_err));
            BOLT_CJOSE(cjose_header_set(recipients[i].unprotected_header, CJOSE_HDR_KID, mint->remotes[i]->to_kid, &c_err));
            recipients[i].jwk = mint->remotes[i]->to_key;
        }

        BOLT_NEST();

        json_object_object_add(bus_object, "destinations", json_object_get(mint->addr));

        BOLT_CJOSE(hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_A256KW, &c_err));
        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &c_err));
        BOLT_CJOSE(cjose_header_set(hdr, HDR_XL4BUS, json_object_get_string(bus_object), &c_err));

        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_CTY, deflate_content_type(mint->msg->content_type), &c_err));

        BOLT_CJOSE(encrypted =
                cjose_jwe_encrypt_multi(recipients, mint->key_idx, hdr, 0, mint->msg->data, mint->msg->data_len, &c_err));

        BOLT_CJOSE(msg->data = cjose_jwe_export_json(encrypted, &c_err));
        msg->msg.data = msg->data;
        msg->msg.data_len = strlen(msg->msg.data) + 1;
        msg->msg.content_type = FCT_JOSE_JSON;

        msg->msg.uses_encryption = 1;
        msg->msg.uses_session_key = 1;
        msg->msg.uses_validation = 1;

        CHANGE_MIS(mint, MIS_WAIT_CONFIRM, "sending main message");
        BOLT_SUB(to_broker(clt, msg, mint->msg->address, 1, 1));
        msg = 0;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    cjose_jwe_release(encrypted);
    cjose_header_release(hdr);
    for (int i=0; i<mint->key_idx; i++) {
        cjose_header_release(recipients[i].unprotected_header);
    }
    cjose_jwk_release(key);
    json_object_put(bus_object);

    free_outgoing_message(msg);

    return err;

}

int xl4bus_process_ll_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int err = E_XL4BUS_OK;
    json_object * root = 0;
    cjose_err c_err;

    xl4bus_identity_t id = {};
    message_internal_t * mint = 0;
    char * key_base64 = 0;
    size_t key_base64_len = 0;

    do {

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;
        char const * type;

        // every time this method returns not OK, the connection is dropped (and then re-established).
        // we should be careful about when we drop or don't drop the connection, otherwise we can be
        // easily DoSed by our own bugs.

        // it's OK to reconnect for this, since this means we can't trust broker message(s), something
        // must be really wrong (with the broker), but essentially we can't function as a client anymore.
        BOLT_IF(!msg->uses_validation, E_XL4BUS_DATA, "Incoming message is not validated, refusing to process");

        if (i_clt->state == CS_RUNNING) {

            int need_reconnect = 0;

            do {

                // this block generally doesn't cause returning non-OK, except for the cases when used
                // functions asked for that explicitly. The reason to drop a connection if the problem
                // is related to being able to send a message back, i.e. it's actually a network problem
                // of some kind.

#if XL4_SUPPORT_THREADS
                BOLT_SYS(pf_lock(&i_clt->hash_lock), "");
#endif

                HASH_FIND(hh, i_clt->stream_hash, &msg->stream_id, 2, mint);
                mint = ref_message_internal(mint);

#if XL4_SUPPORT_THREADS
                pf_unlock(&i_clt->hash_lock);
#endif

                DBG("XCHG: %05x Incoming stream, mint %p", msg->stream_id, mint);

                if (mint) {

                    BOLT_SUB(handle_state_message(conn, msg, mint, &need_reconnect));

                } else {

                    if (!z_strcmp(msg->content_type, FCT_BUS_MESSAGE)) {

                        BOLT_IF(!msg->uses_validation || !msg->uses_encryption, E_XL4BUS_DATA,
                                "System messages must be signed and encrypted");

                        BOLT_SUB(get_xl4bus_message_msg(msg, &root, &type));

                        DBG("System message from broker : %s", json_object_get_string(root));

                        if (!strcmp(type, MSG_TYPE_PRESENCE)) {

                            handle_presence(clt, root);

                        } else {

                            DBG("Unknown message type %s received : %s", type, json_object_get_string(root));

                        }

                    } else {
                        DBG("Incoming message, expecting client encryption");
                        handle_client_message(0, conn, msg, &need_reconnect);
                    }

                }

            } while (0);

            if (err != E_XL4BUS_OK) {
                DBG("Message on stream %04x could not be processed, will reconnect: %s",
                        msg->stream_id, BOOL_STR(need_reconnect));
                if (!need_reconnect) {
                    xl4bus_abort_stream(conn, msg->stream_id);
                    err = E_XL4BUS_OK;
                }
            }

            break;

        }

        BOLT_SUB(get_xl4bus_message_msg(msg, &root, &type));

        if (i_clt->state == CS_EXPECTING_ALGO && !strcmp(type, MSG_TYPE_ALG_SUPPORTED)) {

            // $TODO: check the algorithms!

            i_clt->state = CS_EXPECTING_CONFIRM;

            int64_t protocol;

            // DBG("root:%s", json_object_get_string(root));
            BOLT_SUB(xl4json_get_pointer(root, "/body/protocol-version", json_type_int, &protocol));
            BOLT_IF(protocol != 2, E_XL4BUS_DATA, "Unsupported protocol version %" PRId64, protocol);

            xl4bus_key_t key = {
                    .type = XL4KT_AES_256,
            };

            json_object * body = 0;

            do {

                pf_random(key.aes_256, sizeof(key.aes_256));

                BOLT_SUB(xl4bus_set_session_key(conn, &key, 0));

                BOLT_CJOSE(cjose_base64url_encode(key.aes_256, sizeof(key.aes_256), &key_base64, &key_base64_len, &c_err));

                BOLT_MEM(body = xl4json_make_obj(0,
                        "M", "session-key", xl4json_make_obj(0,
                                "S", "kty", "oct",
                                "S", "k", key_base64,
                                NULL),
                        NULL));

                // send registration request.
                // https://gitlab.excelfore.com/schema/json/xl4bus/registration-request.json
                BOLT_SUB(send_json_message(clt, 0, 1, 0, msg->stream_id,
                        MSG_TYPE_REG_REQUEST, body, 1));

            } while (0);

            zero_s(key.aes_256, sizeof(key.aes_256));
            json_object_put(body);

            BOLT_NEST();

        } else if (i_clt->state == CS_EXPECTING_CONFIRM &&
                   !strcmp(type, MSG_TYPE_PRESENCE) && msg->is_final) {

            BOLT_IF(!msg->uses_session_key || !msg->uses_validation,
                    E_XL4BUS_DATA, "Presence message must use session key");

            i_clt->state = CS_RUNNING;
            if (clt->on_status) {
                clt->on_status(clt, XL4BCC_RUNNING);
            }

            DBG("Presence contents : %s", json_object_get_string(root));

            handle_presence(clt, root);

            // if there are any pending messages, let's
            // kick them off.

#if XL4_SUPPORT_THREADS
            BOLT_SYS(pf_lock(&i_clt->hash_lock), "");
#endif
            int msg_count;
            DL_COUNT(i_clt->message_list, mint, msg_count);

            message_internal_t * mints[msg_count];
            int i = 0;

            DL_FOREACH(i_clt->message_list, mint) {
                mints[i++] = ref_message_internal(mint);
            }

#if XL4_SUPPORT_THREADS
            pf_unlock(&i_clt->hash_lock);
#endif

            for (i=0; i < msg_count; i++) {
                if (is_mint_incoming(mints[i])) {
                    DBG("Found incoming message state %p after (re)connect, please file a bug", mints[i]);
                    dispose_message(clt, mints[i]);
                } else {
                    process_message_out(clt, mints[i], 1);
                }
                unref_message_internal(mints[i]);
            }

        } else {

            // $TODO: well, nothing is actually being reset here...
            DBG("Resetting handshake. State: %s, incoming typ: %s, is_final: %d", state_str(i_clt->state),
                    type, msg->is_final);

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    for (xl4bus_asn1_t ** asn1 = id.x509.chain; asn1 && *asn1; asn1++) {
        cfg.free((*asn1)->buf.data);
        cfg.free(*asn1);
    }
    cfg.free(id.x509.chain);

    unref_message_internal(mint);

    json_object_put(root);

    free_s(key_base64, key_base64_len);

    return err;

}

int handle_client_message(message_internal_t * mint, xl4bus_connection_t * conn, xl4bus_ll_message_t * msg,
        int * need_reconnect) {

    int err /*= E_XL4BUS_OK*/;

    xl4bus_client_t * clt = conn->custom;
    client_internal_t * i_clt = clt->_private;
    json_object * root = 0;
    xl4bus_address_t * to_addr = 0;
    mint = ref_message_internal(mint);

    // OK, the incoming message must have come from another client (and not from the broker).
    // In this case, it must be W4, W5 or W6 type.

    aes_search_data_t asd = {.conn =  conn};
    decrypt_and_verify_data_t dav = {0};
    int confirm_message = 1;

    do {

        dav.in_data = msg->data;
        dav.in_data_len = msg->data_len;

        BOLT_SUB(get_numeric_content_type(msg->content_type, &dav.in_ct));

        dav.asymmetric_key_locator = rsa_key_locator;
        dav.asymmetric_locator_data = clt;

        dav.symmetric_key_locator = aes_key_locator;
        dav.symmetric_locator_data = &asd;
        dav.cache = conn->cache;

        BOLT_SUB(decrypt_and_verify(&dav));

        if (!dav.remote) {
            dav.remote = ref_remote_info(asd.remote);
        }

        if (dav.missing_x5t || asd.missing_kid) {

            char const * missing_x5t = dav.missing_x5t;
            if (asd.missing_kid) {
                missing_x5t = asd.missing_x5t;
            }

            BOLT_IF(dav.missing_x5t && msg->is_final, E_XL4BUS_DATA, "Can not follow up, and no remote");

            message_info_state_t mis;
            if (dav.missing_x5t || asd.missing_x5t) {
                mis = MIS_NEED_REMOTE;
            } else {
                mis = MIS_WAITING_KEY;
            }

            // $TODO: the check below doesn't account for circular issues, i.e.
            // requesting cert is OK, but no key, then here is key, but no cert,
            // this state will keep requesting forever...
            BOLT_IF(mint && mis == mint->mis, E_XL4BUS_DATA,
                    "Remote request %d already made, still can not decrypt, dumping message", mis);

            // $TODO: this is bad. We are un-referencing it because we are about to create a new one,
            // but if it gets freed here, the message will be freed as well, but we are using it right below.
            // This only works because our caller keep their own reference to mint.
            unref_message_internal(mint);

            BOLT_MALLOC(mint, sizeof(message_internal_t));
            mint = ref_message_internal(mint);
            mint->stream_id = msg->stream_id;
            mint->mis = mis;

            memcpy(&mint->ll_msg, msg, sizeof(mint->ll_msg));

            BOLT_MEM(mint->ll_msg.content_type = f_strdup(msg->content_type));
            BOLT_MALLOC(mint->ll_msg.data, msg->data_len);
            memcpy((void*)mint->ll_msg.data, msg->data, msg->data_len);

            if (missing_x5t) {

                BOLT_MEM(root = json_object_new_object());
                json_object * aux;
                json_object * bux;
                BOLT_MEM(aux = json_object_new_string(missing_x5t));
                BOLT_MEM(bux = json_object_new_array());
                BOLT_MEM(!json_object_array_add(bux, aux));
                json_object_object_add(root, "x5t#S256", bux);
                BOLT_SUB(send_json_message(clt, 1, 1, 0, msg->stream_id,
                        MSG_TYPE_REQUEST_CERT, root, 1));

                record_mint(clt, mint, 1, 1, 1, 0);

            } else {

                uint16_t stream_id;
                BOLT_SUB(xl4bus_get_next_outgoing_stream(i_clt->ll, &stream_id));

                BOLT_MEM(root = xl4json_make_obj(0,
                        "S", "kid", asd.missing_kid,
                        NULL));

                BOLT_MEM(mint->needs_kid = f_strdup(asd.missing_kid));

                if ((err = send_client_json_message(clt, asd.remote, 0, 1, stream_id,
                        MSG_TYPE_REQ_KEY, root)) != E_XL4BUS_OK) {

                    *need_reconnect = 1;
                    BOLT_NEST();

                }

                record_mint(clt, mint, 1, 1, 0, 1);

            }

            confirm_message = 0;

            break;

        }

        BOLT_IF(!dav.was_verified, E_XL4BUS_DATA, "Message could not be verified");

        if (!z_strcmp(dav.out_ct, FCT_BUS_MESSAGE)) {

            confirm_message = 0;
            char const * type;

            BOLT_SUB(get_xl4bus_message_dav(&dav, &root, &type));
            DBG("Received client system message of type %s", type);

#if WITH_UNIT_TEST
            if (test_control_message_interceptor) {
                BOLT_SUB(test_control_message_interceptor(clt, msg, &dav, root, type, need_reconnect));
                break;
            }
#endif

            BOLT_SUB(xl4bus_process_client_message(clt, msg, &dav, root, type, need_reconnect));

        } else {

            xl4bus_message_t message;
            memset(&message, 0, sizeof(message));

            message.content_type = dav.out_ct;
            message.data = dav.out_data;
            message.data_len = dav.out_data_len;
            message.was_encrypted = dav.was_encrypted;

            json_object * destinations;
            if (json_object_object_get_ex(dav.bus_object, "destinations", &destinations)) {
                BOLT_SUB(xl4bus_json_to_address(json_object_get_string(destinations), &to_addr));
            }

            BOLT_IF(!dav.remote, E_XL4BUS_INTERNAL, "No remote determined when doing DAV");

            message.source_address = dav.remote->addresses;
            message.sender_data = dav.remote->sender_data;
            message.sender_data_count = dav.remote->sender_data_count;
            message.address = to_addr;

            clt->on_message(clt, &message);

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    clean_decrypt_and_verify(&dav);
    free(asd.missing_kid);
    cjose_jwk_release(asd.key);
    unref_remote_info(asd.remote);
    free(asd.missing_x5t);
    json_object_put(root);
    xl4bus_free_address(to_addr, 1);
    unref_message_internal(mint);

    if (err == E_XL4BUS_OK && confirm_message) {
        // tell broker we are done
        send_json_message(clt, 1, 1, 1, msg->stream_id,
                MSG_TYPE_MESSAGE_CONFIRM, 0, 1);
    }

    return err;

}

int xl4bus_process_client_message(xl4bus_client_t * clt, xl4bus_ll_message_t * msg, decrypt_and_verify_data_t * dav,
        json_object * root, char const * type, int * need_reconnect) {

    int err = E_XL4BUS_OK;

    client_internal_t * i_clt = clt->_private;
    xl4bus_connection_t * conn = i_clt->ll;
    cjose_err c_err = {0};
    json_object * body = 0;
    char * key_base64 = 0;
    size_t key_base64_len = 0;

    int locked = 0;

    do {

        if (!z_strcmp(type, MSG_TYPE_KEY_INFO)) {

            BOLT_IF(!dav->was_encrypted, E_XL4BUS_DATA, "Key info message must have been encrypted");

            char const * kid;
            BOLT_SUB(process_remote_key(conn->cache, root, conn->my_x5t, dav->remote, &kid));

#if XL4_SUPPORT_THREADS
            BOLT_SYS(pf_lock(&i_clt->hash_lock), "");
            locked = 1;
#endif

            hash_list_t * pending;
            HASH_FIND(hh, i_clt->mint_by_kid, kid, strlen(kid) + 1, pending);
            size_t len;
            if (pending && (len = utarray_len(&pending->items))) {

                DBG("%d messages waiting for KID %s", len, kid);

                // the whole business of copying the array here is because
                // record_mint(with deletion) will yank elements from the array,
                // and it's going to be complicated to maintain the loop. So we first
                // go through all elements, and then delete all of them out.
                message_internal_t * copy[len];

                for (size_t i = 0; i<len; i++) {
                    message_internal_t * mint = ref_message_internal(*(message_internal_t**)utarray_eltptr(&pending->items, i));
                    copy[i] = mint;
                }

#if XL4_SUPPORT_THREADS
                pf_unlock(&i_clt->hash_lock);
                locked = 0;
#endif

                for (size_t i = 0; i<len; i++) {
                    reattempt_pending_message(conn, copy[i], need_reconnect);
                    record_mint(clt, copy[i], 0, 0, 0, 1);
                    unref_message_internal(copy[i]);
                }

            } else {

                DBG("No messages waiting for KID %s", kid);

            }

            xl4bus_abort_stream(conn, msg->stream_id);

        } else if (!z_strcmp(type, MSG_TYPE_REQ_KEY)) {

            char const * kid;
            BOLT_SUB(xl4json_get_pointer(root, "/body/kid", json_type_string, &kid));
            BOLT_IF(!dav->remote, E_XL4BUS_INTERNAL, "Remote not identified");
            BOLT_IF(dav->was_symmetric, E_XL4BUS_INTERNAL, "Asymmetric encryption must be used");

            cjose_jwk_t * used_key = 0;
            uint64_t now = pf_ms_value();

            if (!z_strcmp(kid, dav->remote->to_kid) && now < dav->remote->to_key_use_expiration) {

                used_key = dav->remote->to_key;

            } else if (!z_strcmp(kid, dav->remote->old_to_kid) && now < dav->remote->old_to_key_use_expiration) {

                used_key = dav->remote->old_to_key;

            }

            if (!used_key) {

                void const * key_data;
                size_t key_data_len;

                BOLT_CJOSE(key_data = cjose_jwk_get_keydata(dav->remote->to_key, &c_err));
                BOLT_CJOSE(key_data_len = cjose_jwk_get_keysize(dav->remote->to_key, &c_err) / 8);

                BOLT_CJOSE(cjose_base64url_encode(key_data, key_data_len,
                        &key_base64, &key_base64_len, &c_err));

                body = xl4json_make_obj(0,
                        "S", "kty", "oct",
                        "S", "k", key_base64,
                        NULL);

                BOLT_MEM(body);
                // $TODO: body must be disposed of securely somehow.

                if ((err = send_client_json_message(clt, dav->remote, 1, 1,
                        msg->stream_id, MSG_TYPE_KEY_INFO, body)) != E_XL4BUS_OK) {
                    *need_reconnect = 1;
                    BOLT_NEST();
                }

            } else {
                DBG("Requested KID %s does not match neither recent KID %s nor old KID %s",
                        kid, dav->remote->to_kid, dav->remote->old_to_kid);
            }

        } else {

            DBG("Unknown message type %s received : %s", type, json_object_get_string(root));

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

#if XL4_SUPPORT_THREADS
    if (locked) {
        pf_unlock(&i_clt->hash_lock);
    }
#endif

    json_object_put(body);
    free_s(key_base64, key_base64_len);

    return err;

}

int ll_msg_cb(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    xl4bus_client_t * clt = conn->custom;
    clean_expired_things(clt);

#if WITH_UNIT_TEST
    if (test_message_interceptor) {
        return test_message_interceptor(conn, msg);
    }
#endif

    return xl4bus_process_ll_message(conn, msg);

}

int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg) {

    return send_message(clt, msg, arg, 0);

}

int xl4bus_send_message2(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg, int app_thread) {

    return send_message(clt, msg, arg, !app_thread);

}

int send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg, int on_internal_thread) {

    int err /* = E_XL4BUS_OK */;
    message_internal_t * mint = 0;

    do {

        BOLT_MALLOC(mint, sizeof(message_internal_t));
        mint = ref_message_internal(mint);
        BOLT_IF(!msg->address, E_XL4BUS_ARG, "No message address");
        BOLT_SUB(make_json_address(msg->address, &mint->addr));

        mint->msg = msg;
        CHANGE_MIS(mint, MIS_VIRGIN, "new message");
        mint->custom = arg;

        record_mint(clt, mint, 1, 1, 0, 0);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (err != E_XL4BUS_OK) {
        dispose_message(clt, mint);
    } else {
        process_message_out(clt, mint, on_internal_thread);
    }

    unref_message_internal(mint);

    return err;

}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
int xl4bus_stop_client(xl4bus_client_t *clt) {
#pragma clang diagnostic pop

    client_internal_t *i_clt = clt->_private;

#if XL4_PROVIDE_THREADS
    if (clt->mt_support) {

        int err = E_XL4BUS_OK;
        do {

            itc_message_t itc = {0};
            itc.magic = ITC_STOP_CLIENT_MAGIC;
            itc.client = clt;
            BOLT_SYS(pf_send(i_clt->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc), "pf_send");

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
        } while (0);
#pragma clang diagnostic pop

        return err;

    }
#endif

    stop_client_ts(clt, XL4BCC_CLIENT_STOPPED);
    return E_XL4BUS_OK;

}

#if WITH_UNIT_TEST

void xl4bus_pause_client_receive(xl4bus_client_t *clt, int is_pause) {

#if !XL4_PROVIDE_THREADS
#error threads are required
#endif

    if (!clt->use_internal_thread) { abort(); }

    client_internal_t *i_clt = clt->_private;

    itc_message_t itc = {
            .magic = ITC_PAUSE_RCV_MAGIC,
            .pause = {
                    .pause = is_pause,
                    .client = clt
            }
    };
    pf_send(i_clt->mt_write_socket, &itc, sizeof(itc));

}

#endif

void stop_client_ts(xl4bus_client_t * clt, xl4bus_client_condition_t how) {

    drop_client(clt, how);

    // $TODO: we must clean up a ton of stuff
    // that's attached to this client, if it is stopped!!!

    client_internal_t * i_clt = clt->_private;

#if XL4_PROVIDE_THREADS

    if (i_clt) { // that's probably always so
        pf_release_lock(i_clt->hash_lock);
        pf_close(i_clt->mt_read_socket);
        pf_close(i_clt->mt_write_socket);
    }

#endif

    if (i_clt) {

#if XL4_SUPPORT_RESOLVER
        ares_destroy(i_clt->ares);
#endif

        // $TODO: should we hold cache lock?

        xl4bus_release_cache(&i_clt->cache);
        Z(cfg.free, i_clt->pending);
        Z(cfg.free, i_clt->host);
        // Z(cfg.free, i_clt->net_if);

        known_fd_t *fdi, *aux;
        HASH_ITER(hh, i_clt->known_fd, fdi, aux) {
            HASH_DEL(i_clt->known_fd, fdi);
            free(fdi);
        }

        Z(cfg.free, clt->_private);

    }

    // clt->on_release must be the last call, clt
    // should be freed after that.
    if (clt->on_release) {
        clt->on_release(clt);
    }

}

#if XL4_PROVIDE_DEBUG
char * state_str(client_state_t state) {

    switch (state) {
        case CS_DOWN: return "DOWN";
        case CS_RESOLVING: return "RESOLVING";
        case CS_CONNECTING: return "CONNECTING";
        case CS_EXPECTING_ALGO: return "EXPECTING_ALGO";
        case CS_EXPECTING_CONFIRM: return "EXPECTING_CONFIRM";
        case CS_RUNNING: return "RUNNING";
        default: return "??INVALID??";
    }
}
#endif

void process_message_out(xl4bus_client_t * clt, message_internal_t * mint, int on_internal_thread) {

    int err = E_XL4BUS_OK;

    client_internal_t * i_clt = clt->_private;
    json_object *json = 0;

    do {

        if (!on_internal_thread) {
#if XL4_PROVIDE_THREADS
            if (clt->mt_support) {
                do {
                    itc_message_t itc = {0};
                    itc.magic = ITC_CLIENT_MESSAGE_MAGIC;
                    itc.client_msg.client = clt;
                    itc.client_msg.mint = ref_message_internal(mint);
                    BOLT_SYS(pf_send(i_clt->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc), "pf_send");
                    return;
                } while (0);
            }
#endif

            // if we are here, it's either because there was
            // an error, or because we couldn't even schedule the message

            BOLT_IF(err != E_XL4BUS_OK, E_XL4BUS_ARG, "Can support external thread messages");

        }

        if (i_clt->state != CS_RUNNING) {
            // once connection is established, the message will be attempted delivery
            // so we can just return.
            break;
        }

        if (mint->mis == MIS_VIRGIN) {

            BOLT_SUB(xl4bus_get_next_outgoing_stream(i_clt->ll, &mint->stream_id));
            mint->msg->tracking_id = mint->stream_id;
            BOLT_SUB(record_mint(clt, mint, 1, 0, 1, 0));

            BOLT_MEM(json = json_object_new_object());
            json_object_object_add(json, "destinations", json_object_get(mint->addr));

            CHANGE_MIS(mint, MIS_WAIT_DESTINATIONS, "virgin message out on stream %05x", mint->stream_id);
            send_json_message(clt, 1, 0, 0, mint->stream_id, MSG_TYPE_REQ_DESTINATIONS, json, 1);
        }

    } while (0);

    json_object_put(json);

    if (err != E_XL4BUS_OK) {
        release_message(clt, mint, err);
    }

}

int get_xl4bus_message_msg(xl4bus_ll_message_t const * msg, json_object ** json, char const ** type) {

    return get_xl4bus_message(msg->data, msg->data_len, msg->content_type, json, type);

}

int get_xl4bus_message_dav(decrypt_and_verify_data_t * dav, json_object ** json, char const ** type) {

    return get_xl4bus_message(dav->out_data, dav->out_data_len, dav->out_ct, json, type);

}

int get_xl4bus_message(char const * data, size_t data_len, char const* ct, json_object ** json, char const ** type) {

    int err = E_XL4BUS_OK;
    *json = 0;

    do {
        BOLT_IF(z_strcmp(FCT_BUS_MESSAGE, ct),
                E_XL4BUS_CLIENT, "Invalid content type %s", SAFE_STR(ct));

        // the json must be ASCIIZ.
        BOLT_IF(data[data_len-1], E_XL4BUS_CLIENT, "Incoming XL4 message is not ASCIIZ");

        // $TODO: distinguish out of memory
        BOLT_IF(!(*json = json_tokener_parse(data)), E_XL4BUS_CLIENT, "Not valid json: %s", data);

        json_object * aux;
        BOLT_IF(!json_object_object_get_ex(*json, "type", &aux) || !json_object_is_type(aux, json_type_string),
                E_XL4BUS_CLIENT, "No/non-string type property in %s", json_object_get_string(*json));

        *type = json_object_get_string(aux);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (err != E_XL4BUS_OK) {
        json_object_put(*json);
        *json = 0;
    }

    return err;

}

int is_expired(message_internal_t * mint) {

    // $TODO: the count here is rather arbitrary, and should
    // be made as part of configuration or something like that.

    return mint && mint->expired_count > 3;

}

void dispose_message(xl4bus_client_t *clt, message_internal_t *mint) {

    if (mint) {
        DBG("Disposing of message %p", mint);
        record_mint(clt, mint, 0, 1, 1, 1);
    }

}

void release_message(xl4bus_client_t * clt, message_internal_t * mint, int err) {

    if (mint->msg) {
        mint->msg->err = err;
        clt->on_delivered(clt, mint->msg, mint->custom, err == E_XL4BUS_OK);
    }

    dispose_message(clt, mint);

}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void ll_send_cb(struct xl4bus_connection* conn, xl4bus_ll_message_t * msg, void * ref, int err) {
#pragma clang diagnostic pop
    free_outgoing_message((ll_message_container_t*)msg);
}

void ll_shutdown_cb(xl4bus_connection_t * c) {
    xl4bus_client_t * clt = c->custom;
    client_internal_t * i_clt = clt->_private;
    DBG("LLC freeing %p in %p", i_clt->ll, clt);
    Z(free, i_clt->ll);
}

int xl4bus_address_to_json(xl4bus_address_t *addr, char **json) {

    int err /*= E_XL4BUS_OK*/;
    char * res = 0;
    json_object * j_res = 0;

    do {

        BOLT_IF(!addr, E_XL4BUS_ARG, "Empty address");
        BOLT_SUB(make_json_address(addr, &j_res));
        BOLT_MEM(res = f_strdup(json_object_get_string(j_res)));

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    json_object_put(j_res);

    if (err) {
        free(res);
    } else {
        *json = res;
    }

    return err;

}

int handle_presence(xl4bus_client_t * clt, json_object * root) {

    int err = E_XL4BUS_OK;

    DBG("Handling incoming presence");

    if (!clt->on_presence) { return err; }

    xl4bus_address_t *connected_top = 0;
    xl4bus_address_t *disconnected_top = 0;

    do {

        json_object *body;

        BOLT_IF(!json_object_object_get_ex(root, "body", &body) ||
                !json_object_is_type(body, json_type_object), E_XL4BUS_CLIENT, "");

        json_object *list;
        if (json_object_object_get_ex(body, "connected", &list) && json_object_is_type(list, json_type_array)) {
            BOLT_SUB(build_address_list(list, &connected_top));
        }

        if (json_object_object_get_ex(body, "disconnected", &list) && json_object_is_type(list, json_type_array)) {
            BOLT_SUB(build_address_list(list, &disconnected_top));
        }

        clt->on_presence(clt, connected_top, disconnected_top);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

#define FREE_LIST(a) do { \
    while (a) { \
        xl4bus_address_t * aux = a->next; \
        if (a->type == XL4BAT_UPDATE_AGENT) { cfg.free(a->update_agent); } \
        if (a->type == XL4BAT_GROUP) { cfg.free(a->group); } \
        cfg.free(a); \
        a = aux; \
    } \
} while(0)

    FREE_LIST(connected_top);
    FREE_LIST(disconnected_top);

    return err;

}

int pick_timeout(int t1, int t2) {
    if (t1 < 0) { return t2; }
    if (t2 < 0) { return t1; }
    if (t1 < t2) { return t1; }
    return t2;
}

int send_json_message(xl4bus_client_t * clt, int use_session_key, int is_reply, int is_final,
        uint16_t stream_id, const char * type, json_object * body, int thread_safe) {

    int err /* = E_XL4BUS_OK */;

    ll_message_container_t * msg = 0;
    json_object * j_type = 0;

    do {

        BOLT_MALLOC(msg, sizeof(ll_message_container_t));

        BOLT_MEM(msg->json = json_object_new_object());
        if (body) {
            BOLT_MEM(!json_object_object_add(msg->json, "body", body));
            json_object_get(body);
        }

        BOLT_MEM(j_type = json_object_new_string(type));
        BOLT_MEM(!json_object_object_add(msg->json, "type", j_type));
        j_type = 0;

        const char * bux = json_object_get_string(msg->json);

        msg->msg.data = bux;
        msg->msg.data_len = strlen(bux) + 1;
        msg->msg.content_type = FCT_BUS_MESSAGE;
        msg->msg.stream_id = stream_id;
        msg->msg.is_reply = is_reply;
        msg->msg.is_final = is_final;

        if (!z_strcmp(MSG_TYPE_REG_REQUEST, type)) {
            DBG("XCHG: %05x sending json message type %s (secret) on stream", msg->msg.stream_id, type);
        } else {
            DBG("XCHG: %05x sending json on stream : %s",
                    msg->msg.stream_id, bux);
        }

        BOLT_SUB(to_broker(clt, msg, 0, use_session_key, thread_safe));
        msg = 0;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    // DBG("--> clean up %p", msg);
    free_outgoing_message(msg);

    json_object_put(j_type);

    return err;

}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
const cjose_jwk_t * rsa_key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void * data) {
#pragma clang diagnostic pop

    const char * x5t = cjose_header_get(hdr, HDR_X5T256, 0);
    if (!x5t) {

        x5t = cjose_header_get(cjose_jwe_get_protected(jwe), HDR_X5T256, 0);

        if (!x5t) {

            DBG("No x5t hash");
            return 0;

        }

    }

    xl4bus_client_t * clt = data;
    client_internal_t * i_clt = clt->_private;
    xl4bus_connection_t * conn = i_clt->ll;

    if (z_strcmp(x5t, conn->my_x5t)) {
        DBG("Hash %s is not my hash", x5t);
        return 0;
    }

    DBG("Returning my private key");
    return i_clt->private_key;

}

const cjose_jwk_t * aes_key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void * data) {

    const char * kid = cjose_header_get(hdr, CJOSE_HDR_KID, 0);
    if (!kid) {
        DBG("No kid, returning 0");
        return 0;
    }

    aes_search_data_t * asd = data;

    // let's see if I simply have this key in the hash
    remote_key_t * rmi = find_by_kid(asd->conn->cache, kid);
    if (rmi) {
        cjose_jwk_release(asd->key);
        asd->key = cjose_jwk_retain(rmi->from_key, 0);
        DBG("Found symmetric key %p, ri %p, for %s", rmi->from_key, rmi->remote_info, kid);
        unref_remote_info(asd->remote);
        asd->remote = ref_remote_info(rmi->remote_info);
        unref_remote_key(rmi);
        return asd->key;
    }

    // is this even my KID?
    // unfortunately, to understand this, we need to extract my x5t piece from it

    cjose_err c_err;
    int err /*= E_XL4BUS_OK*/;
    uint8_t * kid_raw = 0;
    size_t kid_len;
    char * remote_x5t = 0;
    size_t remote_x5t_len = 0;

    xl4bus_connection_t * conn = asd->conn;

    size_t hash_len = conn->my_x5t_bin.len;
    remote_info_t * remote = 0;

    do {

        BOLT_CJOSE(cjose_base64url_decode(kid, strlen(kid), &kid_raw, &kid_len, &c_err));
        BOLT_IF(kid_len < hash_len * 2, E_XL4BUS_DATA, "KID len %zd too small", kid_len);
        if (memcmp(conn->my_x5t_bin.data, kid_raw + hash_len, hash_len)) {
            DBG("KID %s does not target my x5t", kid);
        } else {
            DBG("KID %s targets my x5t, populating missing KID", kid);
            free(asd->missing_kid);
            asd->missing_kid = f_strdup(kid);
        }

        // I also need to know who did this request come from, there is a chance I don't even know that guy.
        BOLT_CJOSE(cjose_base64url_encode(kid_raw, hash_len, &remote_x5t, &remote_x5t_len, &c_err));
        remote = find_by_x5t(asd->conn->cache, remote_x5t);
        if (!remote) {
            if (!asd->missing_x5t) {
                DBG("X5T %s is unknown, requesting discovery", remote_x5t);
                asd->missing_x5t = remote_x5t;
                remote_x5t = 0;
            }
        } else {
            if (!asd->remote) {
                DBG("X5T %s is recognized", remote_x5t);
                asd->remote = remote;
                remote = 0;
            }
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    free(kid_raw);
    free(remote_x5t);
    unref_remote_info(remote);
    return 0;

}

int to_broker(xl4bus_client_t * clt, ll_message_container_t * msg, xl4bus_address_t * addr,
        int use_session_key, int thread_safe) {

    // we must clean up msg, if it didn't make it to the lower level!

    json_object *array = 0;

    int err = 0;

    client_internal_t * i_clt = clt->_private;

    do {

        // $TODO: for messages bound to the broker, the address is always 0,
        // so there is no need to attach the "destinations" object with an empty array
        // make sure the remote doesn't have any expectations for the presence of this array
        // and make this block conditional on address being set at all.
        BOLT_MEM(msg->bus_object = json_object_new_object());
        BOLT_SUB(make_json_address(addr, &array));
        BOLT_MEM(!json_object_object_add(msg->bus_object, "destinations", array));
        array = 0;

        DBG("Attaching BUS object: %s", json_object_get_string(msg->bus_object));

        msg->msg.bus_data = json_object_get_string(msg->bus_object);

        msg->msg.uses_validation = 1;
        msg->msg.uses_encryption = 1;
        if (use_session_key) {
            msg->msg.uses_session_key = 1;
        }

        BOLT_SUB(SEND_LL(i_clt->ll, &msg->msg, 0, thread_safe));
        msg = 0;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    json_object_put(array);

    // DBG("--> clean up %p", msg);
    free_outgoing_message(msg);

    return err;

}

void free_outgoing_message(ll_message_container_t * msg) {

    if (!msg) { return; }

    // DBG("--> Cleaning up %p", msg);

    cfg.free(msg->data);
    cfg.free(msg->content_type);
    json_object_put(msg->json);
    json_object_put(msg->bus_object);

    cfg.free(msg);

}

int receive_cert_details(xl4bus_client_t * clt, message_internal_t * mint, xl4bus_ll_message_t * msg, json_object * root) {

    int err = E_XL4BUS_OK;

    client_internal_t * i_clt = clt->_private;
    xl4bus_connection_t * conn = i_clt->ll;

    int outgoing = mint->mis != MIS_NEED_REMOTE;

    do {

        json_object *body;
        json_object *tags;
        size_t l;

        if (!json_object_object_get_ex(root, "body", &body) ||
            !json_object_is_type(body, json_type_object) ||
            !json_object_object_get_ex(body, "x5c", &tags) ||
            !json_object_is_type(tags, json_type_array) ||
            (l = json_object_array_length(tags)) <= 0) {

            DBG("XCHG: %05x can't find any certificates in %s", mint->stream_id, json_object_get_string(root));
            if (outgoing) {
                xl4bus_abort_stream(conn, msg->stream_id);
                release_message(clt, mint, E_XL4BUS_UNDELIVERABLE);
            }
            break;

        }

        for (int i=0; i<l; i++) {

            json_object * single = json_object_array_get_idx(tags, i);

            if (outgoing) {
                if (mint->key_idx == mint->key_count) {
                    DBG("XCHG: %05x requested certificate response overflows key count?", mint->stream_id);
                    break;
                }

                if (accept_remote_x5c(single, conn, &mint->remotes[mint->key_idx]) == E_XL4BUS_OK) {
                    mint->key_idx++;
                }

            } else {

                accept_remote_x5c(single, conn, 0);

            }

        }

        if (outgoing) {
            if (mint->key_idx) {
                BOLT_SUB(send_main_message(clt, mint));
            } else {
                DBG("No keys were constructed for encrypting payload");
                xl4bus_abort_stream(conn, mint->stream_id);
                release_message(clt, mint, E_XL4BUS_UNDELIVERABLE);
            }
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}

void record_mint_nl(xl4bus_client_t * clt, message_internal_t * mint, int is_add, int with_list, int with_hash,
        int with_kid_list) {

    client_internal_t * i_clt = clt->_private;

    if (is_add) {

        if (with_hash && !mint->in_hash) {
            DBG("Adding mint %p to hash for stream %04x", mint, mint->stream_id);
            HASH_ADD(hh, i_clt->stream_hash, stream_id, 2, mint);
            mint->in_hash = 1;
            ref_message_internal(mint);
        }

        if (with_list && !mint->in_list) {
            DBG("Adding mint %p to message list", mint);
            DL_APPEND(i_clt->message_list, mint);
            mint->in_list = 1;
            ref_message_internal(mint);
        }

        if (with_kid_list && !mint->in_kid_list) {
            DBG("Adding mint %p to KID list", mint);
            HASH_LIST_ADD(i_clt->mint_by_kid, mint, needs_kid);
            mint->in_kid_list = 1;
            ref_message_internal(mint);
        }

    } else {

        if (with_hash && mint->in_hash) {
            DBG("Adding mint %p from hash for stream %04x", mint, mint->stream_id);
            HASH_DEL(i_clt->stream_hash, mint);
            mint->in_hash = 0;
            unref_message_internal(mint);
        }

        if (with_list && mint->in_list) {
            DBG("Removing mint %p from message list", mint);
            DL_DELETE(i_clt->message_list, mint);
            mint->in_list = 0;
            unref_message_internal(mint);
        }

        if (with_kid_list && mint->in_kid_list) {
            DBG("Removing mint %p from KID list", mint);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
            int aux;
#pragma clang diagnostic pop
            REMOVE_FROM_HASH(i_clt->mint_by_kid, mint, needs_kid, aux, "Removing mint %p from KID list", mint);
            mint->in_kid_list = 0;
            unref_message_internal(mint);
        }


    }

}

int record_mint(xl4bus_client_t * clt, message_internal_t * mint, int is_add, int with_list, int with_hash, int with_kid_hash_list) {

    client_internal_t * i_clt = clt->_private;

#if XL4_SUPPORT_THREADS
    int locked = 0;
#endif

    int err = E_XL4BUS_OK;

    do {

#if XL4_SUPPORT_THREADS
        BOLT_SYS(pf_lock(&i_clt->hash_lock), "");
        locked = 1;
#endif

        record_mint_nl(clt, mint, is_add, with_list, with_hash, with_kid_hash_list);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

#if XL4_SUPPORT_THREADS
    if (locked) {
        pf_unlock(&i_clt->hash_lock);
    }
#endif

    return err;

}

void reattempt_pending_message(xl4bus_connection_t * conn, message_internal_t * mint, int * need_reconnect) {

    // int err = ll_msg_cb(conn, &mint->ll_msg);
    int err = handle_client_message(mint, conn, &mint->ll_msg, need_reconnect);
    if (err != E_XL4BUS_OK) {
        xl4bus_abort_stream(conn, mint->stream_id);
    }

}

void release_remotes(message_internal_t * mint) {

    for (int i=0; i<mint->key_count; i++) {
        unref_remote_info(mint->remotes[i]);
    }
    cfg.free(mint->remotes);
    mint->key_count = 0;
    mint->remotes = 0;
    mint->key_idx = 0;

}

int apply_timeouts(xl4bus_client_t * clt, int need_timeout) {

    client_internal_t * i_clt = clt->_private;
    int ret = i_clt->ll_timeout = pick_timeout(i_clt->ll_timeout, need_timeout);
    global_cache_t * cache = &i_clt->cache;

    if (!LOCK(cache->cert_cache_lock)) {

        if (cache->remote_key_expiration) {

            uint64_t exp_timeout;

            rb_tree_nav_t nav = {0};
            rb_tree_start(&nav, cache->remote_key_expiration);
            uint64_t now = pf_ms_value();
            uint64_t expires_at = TO_RB_NODE2(remote_key_t, nav.node, rb_expiration)->from_key_expiration;
            if (now >= expires_at) {
                exp_timeout = 1;
            } else {
                exp_timeout = expires_at - now;
            }

            ret = i_clt->ll_timeout = pick_timeout(i_clt->ll_timeout, exp_timeout);

        }

        UNLOCK(cache->cert_cache_lock);

    }

    return ret;

}

void clean_expired_things(xl4bus_client_t * clt) {

    uint64_t now = pf_ms_value();

    client_internal_t * i_clt = clt->_private;
    global_cache_t * cache = &i_clt->cache;

    if (!LOCK(cache->cert_cache_lock)) {

        rb_tree_nav_t nav = {0};

        for (rb_tree_start(&nav, cache->remote_key_expiration); nav.node; rb_tree_next(&nav)) {

            remote_key_t * key = TO_RB_NODE2(remote_key_t, nav.node, rb_expiration);
            if (key->from_key_expiration <= now) {
                DBG("Key %s expired, releasing", key->from_kid);
                release_remote_key_nl(cache, key);
            } else {
                break;
            }

        }

        UNLOCK(cache->cert_cache_lock);

    }

}

int handle_state_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, message_internal_t * mint,
        int * need_reconnect) {

    int err /*= E_XL4BUS_OK*/;
    json_object * in_root = 0;
    json_object * req_destinations = 0;

    do {

        char const * in_type;

        xl4bus_client_t * clt = conn->custom;

        BOLT_SUB(get_xl4bus_message_msg(msg, &in_root, &in_type));

        DBG("mint %p state %d, received %s", mint, mint->mis, json_object_get_string(in_root));

        if (mint->mis == MIS_NEED_REMOTE && !strcmp(MSG_TYPE_CERT_DETAILS, in_type)) {

            DBG("XCHG: %05x got remote certificate details", mint->stream_id);

            record_mint(clt, mint, 0, 1, 1, 0);

            // we think we got the certificate for a message pending delivery.
            receive_cert_details(clt, mint, msg, in_root);
            reattempt_pending_message(conn, mint, need_reconnect);

        } else if (mint->mis == MIS_WAIT_DESTINATIONS && !strcmp(MSG_TYPE_DESTINATION_INFO, in_type)) {

            if (msg->is_final) {

                // the broker saying it's not deliverable.
                DBG("XCHG: %05x no destinations", mint->stream_id);
                release_message(clt, mint, E_XL4BUS_UNDELIVERABLE);
                break;

            }

            DBG("XCHG: %05x got destination info", mint->stream_id);

            json_object *tags;
            size_t l;

            if (xl4json_get_pointer(in_root, "/body/x5t#S256", json_type_array, &tags) != E_XL4BUS_OK ||
                    (l = (size_t) json_object_array_length(tags)) <= 0) {

                DBG("XCHG: %05x can't find any destinations in %s", mint->stream_id,
                        json_object_get_string(in_root));
                xl4bus_abort_stream(conn, msg->stream_id);
                release_message(clt, mint, E_XL4BUS_UNDELIVERABLE);
                break;

            }

            release_remotes(mint);
            BOLT_MALLOC(mint->remotes, sizeof(void *) * (mint->key_count = l));

            for (int i = 0; i < l; i++) {

                json_object *item = json_object_array_get_idx(tags, i);
                const char * x5t = json_object_get_string(item);
                remote_info_t *rmi = find_by_x5t(conn->cache, x5t);
                if (rmi) {
                    mint->remotes[mint->key_idx++] = rmi;
                } else {
                    if (!req_destinations) {
                        BOLT_MEM(req_destinations = json_object_new_array());
                    }
                    json_object_array_add(req_destinations, json_object_get(item));
                }

            }


            if (req_destinations) {

                // request destinations
                // https://gitlab.excelfore.com/schema/json/xl4bus/request-destinations.json

                json_object * body = 0;

                do {

                    BOLT_MEM(body = json_object_new_object());
                    json_object_object_add(body, "x5t#S256", json_object_get(req_destinations));

                    CHANGE_MIS(mint, MIS_WAIT_DETAILS, "requested certificates");

                    if ((err = send_json_message(clt, 1, 1, 0, mint->stream_id,
                            MSG_TYPE_REQ_CERT, body, 1)) != E_XL4BUS_OK) {

                        *need_reconnect = 1;
                        BOLT_NEST();

                    }

                } while (0);

                json_object_put(body);

                BOLT_NEST();

            } else {
                if ((err = send_main_message(clt, mint)) != E_XL4BUS_OK) {
                    *need_reconnect = 1;
                    BOLT_NEST();
                }
            }

        } else if (mint->mis == MIS_WAIT_DETAILS && !strcmp(MSG_TYPE_CERT_DETAILS, in_type)) {

            DBG("XCHG: %05x got certificate details", mint->stream_id);

            BOLT_SUB(receive_cert_details(clt, mint, msg, in_root));

        } else if (mint->mis == MIS_WAIT_CONFIRM && !strcmp(MSG_TYPE_MESSAGE_CONFIRM, in_type)) {

            DBG("XCHG: %05x got confirmation", mint->stream_id);

            if (!msg->is_final) {
                DBG("Message confirmation was not a final stream message!");
                xl4bus_abort_stream(conn, mint->stream_id);
            }
            release_message(clt, mint, E_XL4BUS_OK);

        } else {

            DBG("XCHG: %05x state not applicable to incoming message", mint->stream_id);
            if (!msg->is_final) {
                xl4bus_abort_stream(conn, mint->stream_id);
            }
            release_message(clt, mint, E_XL4BUS_INTERNAL);
            break;

        }


#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    json_object_put(in_root);
    json_object_put(req_destinations);

    return err;

}

#if WITH_UNIT_TEST

int e_test_is_mint_incoming(message_internal_t *mint) {
    return is_mint_incoming(mint);
}

#endif
