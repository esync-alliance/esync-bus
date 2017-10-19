
#include <libxl4bus/high_level.h>
#include <libxl4bus/low_level.h>
#include <netdb.h>
#include "internal.h"
#include "misc.h"

#if XL4_PROVIDE_THREADS

typedef struct poll_info {
    pf_poll_t * polls;
    int polls_len;
} poll_info_t;

static void client_thread(void *);
static int internal_set_poll(xl4bus_client_t *, int fd, int modes);

#endif

#if XL4_PROVIDE_DEBUG
static char * state_str(client_state_t);
#endif

#if XL4_SUPPORT_THREADS
#define SEND_LL(a,b,c,d) xl4bus_send_ll_message(a,b,c,(a)->mt_support && !(d))
#else
#define SEND_LL(a,b,c,d) xl4bus_send_ll_message(a,b,c)
#endif

static void ares_gethostbyname_cb(void *, int, int, struct hostent*);
static void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t);
static int ll_poll_cb(struct xl4bus_connection*, int, int);
static int ll_msg_cb(struct xl4bus_connection*, xl4bus_ll_message_t *);
static int create_ll_connection(xl4bus_client_t *);
static int process_message_out(xl4bus_client_t *, message_internal_t *, int);
static int get_xl4bus_message(validated_object_t const *, json_object **, char const **);
static void release_message(xl4bus_client_t *, message_internal_t *, int);
static int handle_presence(xl4bus_client_t * clt, json_object*);
static int pick_timeout(int t1, int t2);
static int send_json_message(xl4bus_client_t * clt, int is_reply, int is_final, uint16_t stream_id, const char * type, json_object * body, int);
static const cjose_jwk_t * key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void *);
static void stop_client_ts(xl4bus_client_t * clt);
static int to_broker(xl4bus_client_t *, xl4bus_ll_message_t *, xl4bus_address_t * addr, int, int);
static void free_outgoing_message(xl4bus_ll_message_t *);
static int receive_cert_details(xl4bus_client_t *, message_internal_t *, xl4bus_ll_message_t *, json_object *);

#if XL4_SUPPORT_THREADS
static int handle_mt_message(struct xl4bus_connection *, void *, size_t);
#endif

static void ll_send_cb(struct xl4bus_connection*, xl4bus_ll_message_t *, void *, int);

int xl4bus_init_client(xl4bus_client_t * clt, char * url) {

    int err = E_XL4BUS_OK;
    client_internal_t * i_clt = 0;
    char * url_copy = 0;

    do {

        BOLT_IF(!url || strncmp("tcp://", url, 6), E_XL4BUS_ARG, "invalid url schema");
        size_t l = strlen(url+6);
        BOLT_MALLOC(url_copy, l+1);
        strcpy(url_copy, url+6);
        char * colon = strchr(url_copy, ':');
        BOLT_IF(!colon, E_XL4BUS_ARG, "no port separator");
        BOLT_IF(colon == url_copy, E_XL4BUS_ARG, "no host name");
        *(colon++) = 0;

        int port = atoi(colon);
        BOLT_IF(port <= 0 || port > 65535, E_XL4BUS_ARG, "invalid port value");

        BOLT_MALLOC(clt->_private, sizeof(client_internal_t));

        i_clt = clt->_private;
        i_clt->host = url_copy;
        i_clt->port = port;
        i_clt->state = CS_DOWN;
        i_clt->tcp_fd = -1;

        BOLT_ARES(ares_init(&i_clt->ares));

#if XL4_PROVIDE_THREADS
        if (clt->use_internal_thread) {
            clt->set_poll = internal_set_poll;
            clt->mt_support = 1;
            BOLT_SYS(pf_start_thread(client_thread, clt), "starting client thread");
        }
#endif

    } while (0);

    // note, the caller must call process_client right away.

    if (err != E_XL4BUS_OK) {

        if (i_clt) {
            ares_destroy(i_clt->ares);
        }
        cfg.free(i_clt);
        free(url_copy);
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

    } while (0);

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
                uint64_t now = pf_msvalue();
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
                ares_gethostbyname(i_clt->ares, i_clt->host,
                        family, ares_gethostbyname_cb, clt);

#if XL4_SUPPORT_IPV6 && XL4_SUPPORT_IPV4
                // if we need both addresses
                i_clt->dual_ip = 1;
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

            } else {

                // there is no clear answer on what to do if there is an error
                // (see https://c-ares.haxx.se/mail/c-ares-archive-2017-05/0014.shtml)
                // so, for now, let's clear the socket error, and trigger both
                // read/write. Note that we must at least gobble up the error,
                // otherwise the poll will keep waking us up forever (ESYNC-700)

                if (pfd->flags & XL4BUS_POLL_ERR) {
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

        ares_process(i_clt->ares, &read, &write);

        // reset any polled events.
        i_clt->pending_len = 0;

        FD_ZERO(&read);
        FD_ZERO(&write);

        int mfd = ares_fds(i_clt->ares, &read, &write);

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
            } else {
                if (fdi->modes != reason) {
                    BOLT_SUB(clt->set_poll(clt, fdi->fd, reason));
                    fdi->modes = reason;
                }
            }
        }

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

        if (i_clt->state == CS_CONNECTING) {

            if (i_clt->tcp_fd < 0) {
                // socket has not been established, or we have failed.
                // try next address, or go down.
                ip_addr_t * addr = 0;
                if (i_clt->addresses) {
                    addr = &i_clt->addresses[i_clt->net_addr_current++];
                }
                if (!addr || addr->family == AF_UNSPEC) {
                    // no (more) addresses to try.
                    drop_client(clt, addr ? XL4BCC_CONNECTION_FAILED : XL4BCC_RESOLUTION_FAILED);
                    continue;
                }

                void * ip_addr;
                int ip_len;
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
                int async;
                i_clt->tcp_fd = pf_connect_tcp(ip_addr, ip_len, (uint16_t) i_clt->port, &async);

                if (i_clt->tcp_fd < 0) {
                    // failed right away, ugh. Let's move on then.
                    i_clt->repeat_process = 1;
                } else {
                    // connected, or going to connected
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
            *timeout = pick_timeout(i_clt->ll_timeout, *timeout);
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
        xl4bus_client_condition_t reason;
        switch (i_clt->state) {
            case CS_DOWN:
                return;
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

        drop_client(clt, reason);
    }

}

#if XL4_PROVIDE_THREADS

void client_thread(void * arg) {

    poll_info_t poll_info = { .polls = 0, .polls_len = 0};
    xl4bus_client_t * clt = arg;
    client_internal_t * i_clt = clt->_private;
    i_clt->xl4_thread_space = &poll_info;

    int timeout;
    xl4bus_run_client(clt, &timeout);

    while (1) {

        /*
        DBG("Clt %p: after run : poll requested timeout %d, poll_info has %d entries", clt, timeout,
                poll_info.polls_len);
        */

        int res = pf_poll(poll_info.polls, poll_info.polls_len, timeout);
        if (res < 0) {
            stop_client_ts(clt);
            return;
        }

        for (int i=0; res && i<poll_info.polls_len; i++) {
            pf_poll_t * pp = poll_info.polls + i;
            if (pp->revents) {
                res--;
                // DBG("Clt %p : flagging %x for fd %d", clt, pp->revents, pp->fd);
                if (xl4bus_flag_poll(clt, pp->fd, pp->revents) != E_XL4BUS_OK) {
                    stop_client_ts(clt);
                    return;
                }
            }
        }

        xl4bus_run_client(clt, &timeout);

        // xl4bus_run_client may have called handle_mt_message, that could have raised stop flag.

        if (i_clt->stop) {
            stop_client_ts(clt);
            return;
        }

    }

}

int internal_set_poll(xl4bus_client_t *clt, int fd, int modes) {

    client_internal_t * i_clt = clt->_private;
    poll_info_t * poll_info = i_clt->xl4_thread_space;

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

static void ares_gethostbyname_cb(void * arg, int status, int timeouts, struct hostent* hent) {

    xl4bus_client_t * clt = arg;
    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    do {

        DBG("ARES reported status %d, hent at %p", status, hent);
        if (status != ARES_SUCCESS) {
            DBG("ARES query failed");
            break;
        }

        int addr_count;
        int addr_start;
        for (addr_count = 0; hent && hent->h_addr_list[addr_count]; addr_count++);

        if (!addr_count) {
            DBG("Ares hostent result has 0 addresses?");
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

    if (err != E_XL4BUS_OK) {
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

    i_clt->state = CS_CONNECTING;

}

static void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t how) {
    client_internal_t * i_clt = clt->_private;
    // $TODO: 2sec here is an arbitrary constant, and probably should
    // be a configuration value.
    i_clt->down_target = pf_msvalue() + 2000;
    i_clt->state = CS_DOWN;
    i_clt->net_addr_current = 0;

    if (i_clt->ll) {
        cfg.free(i_clt->ll);
        i_clt->ll = 0;
    }

    if (i_clt->tcp_fd >= 0) {
        pf_shutdown_rdwr(i_clt->tcp_fd);
        pf_close(i_clt->tcp_fd);
        clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_REMOVE);
        i_clt->tcp_fd = -1;
    }

    if (i_clt->addresses) {
        cfg.free(i_clt->addresses);
        i_clt->addresses = 0;
    }

    if (clt->on_status) {
        clt->on_status(clt, how);
    }

    cjose_jwk_release(i_clt->private_key);
    i_clt->private_key = 0;

}
static int create_ll_connection(xl4bus_client_t * clt) {

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

#if XL4_SUPPORT_THREADS

        i_clt->ll->mt_support = clt->mt_support;
        i_clt->ll->on_mt_message = handle_mt_message;

#endif

        memcpy(&i_clt->ll->identity, &clt->identity, sizeof(clt->identity));

        BOLT_SUB(make_private_key(&i_clt->ll->identity, 0, &i_clt->private_key));

        BOLT_SUB(xl4bus_init_connection(i_clt->ll));

        i_clt->state = CS_EXPECTING_ALGO;

    } while (0);

    return err;

}

int ll_poll_cb(struct xl4bus_connection* conn, int fd, int modes) {

    int err = E_XL4BUS_OK;
    do {

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;

        if (fd == XL4BUS_POLL_TIMEOUT_MS) {

            i_clt->ll_timeout = pick_timeout(i_clt->ll_timeout, modes);

        } else {

            // DBG("Clt %p: set poll to %x", conn, modes);

            known_fd_t * fdi;

            HASH_FIND_INT(i_clt->known_fd, &fd, fdi);
            if (!fdi && modes) {
                BOLT_MALLOC(fdi, sizeof(known_fd_t));
                fdi->fd = fd;
                fdi->is_ll_conn = 1;
                HASH_ADD_INT(i_clt->known_fd, fd, fdi);
            }

            if (fdi) {
                fdi->modes = modes;
                BOLT_SUB(clt->set_poll(clt, fdi->fd, modes));
            }

        }

    } while(0);

    return err;

}

int send_main_message(xl4bus_client_t * clt, message_internal_t * mint) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    cjose_jwe_t * encrypted = 0;
    cjose_header_t * hdr = 0;
    cjose_header_t * unprotected_headers [mint->key_idx];
    xl4bus_ll_message_t * x_msg = 0;

    do {

        BOLT_MALLOC(x_msg, sizeof(xl4bus_ll_message_t));

        x_msg->stream_id = mint->stream_id;
        x_msg->is_reply = 1;

#if !XL4_DISABLE_ENCRYPTION

        DBG("Will encrypt with %d keys", mint->key_idx);

        // encrypt the original message to all destinations

        // memset(unprotected_headers, 0, mint->key_idx * sizeof(void*));
        for (int i=0; i<mint->key_idx; i++) {
            BOLT_CJOSE(unprotected_headers[i] = cjose_header_new(&c_err));
            BOLT_CJOSE(cjose_header_set(unprotected_headers[i], "x5t#S256", mint->remotes[i]->x5t, &c_err));
        }

        BOLT_NEST();

        BOLT_CJOSE(hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &c_err));
        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &c_err));
        // BOLT_CJOSE(cjose_header_set(hdr, "x5t#S256", x5t, &c_err));

        BOLT_CJOSE(cjose_header_set(hdr, CJOSE_HDR_CTY, pack_content_type(mint->msg->content_type), &c_err));

        cjose_jwk_t const * keys[mint->key_idx];
        for (int i=0; i<mint->key_idx; i++) {
            keys[i] = mint->remotes[i]->key;
        }

        BOLT_CJOSE(encrypted =
                cjose_jwe_encrypt_full(keys, unprotected_headers,
                        mint->key_idx, hdr, 0, mint->msg->data, mint->msg->data_len, &c_err));

        BOLT_CJOSE(x_msg->data = cjose_jwe_export_json(encrypted, &c_err));
        x_msg->data_len = strlen(x_msg->data) + 1;
        BOLT_MEM(x_msg->content_type = f_strdup("application/jose+json"));

#else

        // we don't need to copy the data, but this code path should not be normally used,
        // and if we don't copy, then we need to implement logic for freeing the data with discrimination
        // on whether it's allocated or not.

        memset(unprotected_headers, 0, sizeof(void*) * mint->key_idx);
        BOLT_MALLOC(x_msg->data, x_msg->data_len = mint->msg->data_len);
        memcpy((void*)x_msg->data, mint->msg->data, x_msg->data_len);
        BOLT_MEM(x_msg->content_type = f_strdup(mint->msg->content_type));

#endif

        BOLT_SUB(to_broker(clt, x_msg, mint->msg->address, 1, 1));

        mint->mis = MIS_WAIT_CONFIRM;

        x_msg = 0; /* will be released later */

    } while (0);

    cjose_jwe_release(encrypted);
    cjose_header_release(hdr);
    for (int i=0; i<mint->key_idx; i++) {
        cjose_header_release(unprotected_headers[i]);
    }

    free_outgoing_message(x_msg);

    return err;

}

int ll_msg_cb(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int err/* = E_XL4BUS_OK*/;
    json_object * root = 0;
    json_object * req_destinations = 0;
    cjose_err c_err;

    validated_object_t vot;
    xl4bus_identity_t id;
    message_internal_t * mint;
    int clean_mint = 0;

    char * missing_remote = 0;

    memset(&vot, 0, sizeof(vot));
    memset(&id, 0, sizeof(id));

    do {

        // $TODO: a lot of errors here will lead to client dropping the connection
        // all together. In most of the cases, this should be just dropping a stream

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;
        char const * type;
        int ct = CT_JOSE_COMPACT;

#if XL4_DISABLE_JWS
        if (!z_strcmp(msg->content_type, "application/vnd.xl4.busmessage-trust+json")) {
            ct = CT_TRUST_MESSAGE;
        } else {

#endif
            // all incoming messages must pass JWS validation, and hence must be JWS messages.
            // note, since validate_jws only supports compact serialization, we only expect compact serialization here.
            BOLT_IF(z_strcmp(msg->content_type, "application/jose"), E_XL4BUS_DATA,
                    "JWS compact message required, got %s", NULL_STR(msg->content_type));


#if XL4_DISABLE_JWS
        }
#endif

        err = validate_jws(msg->data, msg->data_len, ct, i_clt->ll, &vot, &missing_remote);
        if (err != E_XL4BUS_OK) {
            if (missing_remote) {
                err = E_XL4BUS_OK;
            } else {
                BOLT_NEST();
            }
        }

        if (vot.x5c) {

            id.type = XL4BIT_X509;

            int certs = json_object_array_length(vot.x5c);

            BOLT_MALLOC(id.x509.chain, sizeof(void*) * (certs+1));

            for (int i=0; i<certs; i++) {
                BOLT_MALLOC(id.x509.chain[i], sizeof(xl4bus_asn1_t));
                id.x509.chain[i]->enc = XL4BUS_ASN1ENC_DER;
                const char * in = json_object_get_string(json_object_array_get_idx(vot.x5c, i));
                size_t in_len = strlen(in);
                BOLT_CJOSE(cjose_base64_decode(in, in_len, &id.x509.chain[i]->buf.data, &id.x509.chain[i]->buf.len, &c_err));
            }

            BOLT_NEST();

            BOLT_SUB(xl4bus_set_remote_identity(i_clt->ll, &id));

        }

        if (i_clt->state == CS_RUNNING) {

            DBG("XCHG: Incoming stream %d", msg->stream_id);

            HASH_FIND(hh, i_clt->stream_hash, &msg->stream_id, 2, mint);

            if (mint && !mint->in_restart) {

                BOLT_IF(missing_remote, E_XL4BUS_DATA,
                        "Can not cope with missing remote in internal message exchange");

                BOLT_SUB(get_xl4bus_message(&vot, &root, &type));

                DBG("mint state %d, received %s", mint->mis, json_object_get_string(root));

                if (mint->mis == MIS_NEED_REMOTE && !strcmp("xl4bus.cert-details", type)) {

                    clean_mint = 1;
                    HASH_DEL(i_clt->stream_hash, mint);

                    // we thing we got the certificate for a message pending delivery.
                    receive_cert_details(clt, mint, msg, root);
                    mint->in_restart = 1;
                    err = ll_msg_cb(conn, &mint->ll_msg);
                    if (err != E_XL4BUS_OK) {
                        xl4bus_abort_stream(conn, msg->stream_id);
                    }

                    BOLT_NEST();

                } else if (mint->mis == MIS_WAIT_DESTINATIONS && !strcmp("xl4bus.destination-info", type)) {

                    if (msg->is_final) {

                        // the broker saying it's not deliverable.
                        DBG("XCHG: no destinations");
                        release_message(clt, mint, 0);
                        break;

                    }

                    DBG("XCHG: got destination info");

                    json_object *body;
                    json_object *tags;
                    size_t l;

                    if (!json_object_object_get_ex(root, "body", &body) ||
                        !json_object_is_type(body, json_type_object) ||
                        !json_object_object_get_ex(body, "x5t#S256", &tags) ||
                        !json_object_is_type(tags, json_type_array) ||
                        (l = (size_t) json_object_array_length(tags)) <= 0) {

                        DBG("XCHG: can't find any destinations in %s", json_object_get_string(root));
                        xl4bus_abort_stream(conn, msg->stream_id);
                        release_message(clt, mint, 0);
                        break;

                    }

                    BOLT_MALLOC(mint->remotes, sizeof(void *) * (mint->key_count = l));

                    for (int i = 0; i < l; i++) {

                        json_object *item = json_object_array_get_idx(tags, i);
                        const char * x5t = json_object_get_string(item);
                        remote_info_t *rmi = find_by_x5t(x5t);
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

                        body = 0;

                        do {

                            BOLT_MEM(body = json_object_new_object());
                            json_object_object_add(body, "x5t#S256", json_object_get(req_destinations));

                            BOLT_SUB(send_json_message(clt, 1, 0, mint->stream_id,
                                    "xl4bus.request-cert", body, 1));

                            mint->mis = MIS_WAIT_DETAILS;

                        } while (0);

                        json_object_put(body);
                        BOLT_NEST();

                    } else {

                        BOLT_SUB(send_main_message(clt, mint));

                    }

                } else if (mint->mis == MIS_WAIT_DETAILS && !strcmp("xl4bus.cert-details", type)) {

                    DBG("XCHG: got certificate details");

                    BOLT_SUB(receive_cert_details(clt, mint, msg, root));

                } else if (mint->mis == MIS_WAIT_CONFIRM && !strcmp("xl4bus.message-confirm", type)) {

                    DBG("XCHG: got confirmation");

                    if (!msg->is_final) {
                        DBG("Message confirmation was not a final stream message!");
                        xl4bus_abort_stream(conn, mint->stream_id);
                    }
                    release_message(clt, mint, 1);

                }

            } else {

                if (!z_strcmp(vot.content_type, "application/vnd.xl4.busmessage+json")) {

                    BOLT_IF(missing_remote, E_XL4BUS_DATA,
                            "Remote must not be missing for system messages");

                    BOLT_SUB(get_xl4bus_message(&vot, &root, &type));

                    if (!strcmp(type, "xl4bus.presence")) {
                        handle_presence(clt, root);
                    } else {

                        DBG("Unknown message type %s received : %s", type, json_object_get_string(root));

                    }

                } else {

                    // if remote is missing, we must ask for the key, and table the message for now.

                    if (missing_remote) {

                        BOLT_IF(msg->is_final, E_XL4BUS_DATA, "Can not follow up, and no remote");
                        BOLT_IF(mint, E_XL4BUS_DATA, "No remote after remote request");

                        clean_mint = 1;

                        BOLT_MALLOC(mint, sizeof(message_internal_t));
                        mint->mis = MIS_NEED_REMOTE;

                        BOLT_MEM(mint->ll_msg.content_type = f_strdup(msg->content_type));
                        mint->ll_msg.data_len = msg->data_len;
                        BOLT_MALLOC(mint->ll_msg.data, msg->data_len);
                        memcpy((void*)mint->ll_msg.data, msg->data, msg->data_len);
                        mint->ll_msg.was_encrypted = msg->was_encrypted;
                        mint->ll_msg.stream_id = msg->stream_id;
                        mint->ll_msg.is_reply = msg->is_reply;
                        mint->ll_msg.is_final = 0;

                        BOLT_MEM(root = json_object_new_object());
                        json_object * aux;
                        json_object * bux;
                        BOLT_MEM(aux = json_object_new_string(missing_remote));
                        BOLT_MEM(bux = json_object_new_array());
                        BOLT_MEM(!json_object_array_add(bux, aux));
                        json_object_object_add(root, "x5t#S256", bux);
                        BOLT_SUB(send_json_message(clt, 1, 0, msg->stream_id,
                                "xl4bus.request-cert", root, 1));

                        HASH_ADD(hh, i_clt->stream_hash, stream_id, 2, mint);
                        clean_mint = 0;

                        break;

                    }

                    xl4bus_address_t * to_addr = 0;

                    xl4bus_message_t message;
                    memset(&message, 0, sizeof(message));

                    json_object * destinations;
                    if (json_object_object_get_ex(vot.bus_object, "destinations", &destinations)) {
                        xl4bus_json_to_address(json_object_get_string(destinations), &to_addr);
                    }

                    message.source_address = vot.remote_info->addresses;
                    message.address = to_addr;

                    cjose_jwe_t * jwe = 0;

                    do {

                        if (z_strcmp(vot.content_type, "application/jose+json")) {

                            DBG("Payload is not jose message");

#if !XL4_DISABLE_ENCRYPTION
                            BOLT_SAY(E_XL4BUS_DATA, "Encryption is required");
#else
                            BOLT_MEM(message.content_type = f_strdup(vot.content_type));
                            BOLT_MALLOC(message.data, vot.data_len);
                            memcpy((void*)message.data, vot.data, vot.data_len);
                            message.data_len = vot.data_len;
#endif

                        } else {

                            BOLT_IF(((char *) vot.data)[vot.data_len - 1] != 0,
                                    E_XL4BUS_DATA, "json must be 0 terminated");

                            BOLT_CJOSE(jwe = cjose_jwe_import_json((char *) vot.data, vot.data_len - 1, &c_err));

                            BOLT_CJOSE(message.data = cjose_jwe_decrypt_full(jwe, key_locator, clt, &message.data_len,
                                    &c_err));

                            cjose_header_t *hdr = cjose_jwe_get_protected(jwe);

                            const char *ct;
                            BOLT_CJOSE(ct = cjose_header_get(hdr, CJOSE_HDR_CTY, &c_err));
                            BOLT_MEM(message.content_type = inflate_content_type(ct));

                        }

                        message.was_encrypted = 1;

                        clt->on_message(clt, &message);

                    } while (0);

                    // clean up
                    cfg.free((void*)message.content_type);
                    cfg.free((void*)message.data);
                    cjose_jwe_release(jwe);

                    if (err != E_XL4BUS_OK) {

                        // send original message as is.

                        memset(&message, 0, sizeof(message));

                        message.content_type = vot.content_type;
                        message.data = vot.data;
                        message.data_len = vot.data_len;

                        clt->on_message(clt, &message);

                        // it's not an error, really.
                        err = E_XL4BUS_OK;

                    }

                    xl4bus_free_address(to_addr, 1);

                    // tell broker we are done
                    send_json_message(clt, 1, 1, msg->stream_id,
                            "xl4bus.message-confirm", 0, 1);

                }

            }

            break;

        }

        BOLT_IF(missing_remote, E_XL4BUS_DATA,
                "Can not cope with missing remote during connection negotiation");

        BOLT_SUB(get_xl4bus_message(&vot, &root, &type));

        if (i_clt->state == CS_EXPECTING_ALGO && !strcmp(type, "xl4bus.alg-supported")) {

            i_clt->state = CS_EXPECTING_CONFIRM;

            // send registration request.
            // https://gitlab.excelfore.com/schema/json/xl4bus/registration-request.json
            BOLT_SUB(send_json_message(clt, 1, 0, msg->stream_id,
                    "xl4bus.registration-request", 0, 1));

        } else if (i_clt->state == CS_EXPECTING_CONFIRM &&
                !strcmp(type, "xl4bus.presence") && msg->is_final) {

            i_clt->state = CS_RUNNING;
            if (clt->on_status) {
                clt->on_status(clt, XL4BCC_RUNNING);
            }

            DBG("Presence contents : %s", json_object_get_string(root));

            handle_presence(clt, root);

            // if there are any pending messages, let's
            // kick them off.

            message_internal_t * mit;
            DL_FOREACH(i_clt->message_list, mit) {
                process_message_out(clt, mit, 1);
            }

        } else {

            DBG("Resetting handshake. State: %s, incoming typ: %s, is_final: %d", state_str(i_clt->state),
                    type, msg->is_final);

        }

    } while (0);

    for (xl4bus_asn1_t ** asn1 = id.x509.chain; asn1 && *asn1; asn1++) {
        cfg.free((*asn1)->buf.data);
        cfg.free(*asn1);
    }
    cfg.free(id.x509.chain);

    if (clean_mint) {
        cfg.free((void*)mint->ll_msg.data);
        cfg.free((void*)mint->ll_msg.content_type);
        cfg.free(mint);
    }

    cfg.free(missing_remote);

    clean_validated_object(&vot);
    json_object_put(root);
    json_object_put(req_destinations);

    return err;

}

int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg) {

    int err/* = E_XL4BUS_OK*/;
    json_object * addr = 0;
    message_internal_t * mint = 0;

    do {

        client_internal_t * i_clt = clt->_private;

        BOLT_IF(!msg->address, E_XL4BUS_ARG, "No message address");

        BOLT_SUB(make_json_address(msg->address, &addr));

        BOLT_SUB(err);

        BOLT_MALLOC(mint, sizeof(message_internal_t));

        mint->msg = msg;
        mint->stream_id = i_clt->stream_id += 2;
        mint->mis = MIS_VIRGIN;
        mint->addr = addr;
        mint->custom = arg;

        DL_APPEND(i_clt->message_list, mint);
        HASH_ADD(hh, i_clt->stream_hash, stream_id, 2, mint);

        BOLT_SUB(process_message_out(clt, mint, 0));

    } while(0);

    if (err != E_XL4BUS_OK) {
        free(mint);
        json_object_put(addr);
    }

    return err;

}

int xl4bus_stop_client(xl4bus_client_t * clt) {

    client_internal_t * i_clt = clt->_private;

#if XL4_PROVIDE_THREADS
    if (clt->use_internal_thread) {

        int err = E_XL4BUS_OK;

        do {
            itc_message_t itc;
            itc.magic = ITC_STOP_CLIENT_MAGIC;
            itc.ref = clt;
            BOLT_SYS(pf_send(i_clt->ll->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc), "pf_send");
        } while (0);

        return err;

    }
#endif

    stop_client_ts(clt);
    return E_XL4BUS_OK;

}

void stop_client_ts(xl4bus_client_t * clt) {

    drop_client(clt, XL4BCC_CLIENT_STOPPED);
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

static int process_message_out(xl4bus_client_t * clt, message_internal_t * msg, int thread_safe) {

    json_object * json = 0;
    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    if (i_clt->state != CS_RUNNING) {
        return err;
    }

    while (msg->mis == MIS_VIRGIN) {

        BOLT_MEM(json = json_object_new_object());
        json_object_object_add(json, "destinations", json_object_get(msg->addr));
        send_json_message(clt, 0, 0, msg->stream_id, "xl4bus.request-destinations", json, thread_safe);
        msg->mis = MIS_WAIT_DESTINATIONS;

    }

    json_object_put(json);

    return err;

}

int get_xl4bus_message(validated_object_t const * vot, json_object ** json, char const ** type) {

    int err = E_XL4BUS_OK;
    *json = 0;

    do {

        BOLT_IF(z_strcmp("application/vnd.xl4.busmessage+json", vot->content_type),
                E_XL4BUS_CLIENT, "Invalid content type %s", SAFE_STR(vot->content_type));

        // the json must be ASCIIZ.
        BOLT_IF((vot->data)[vot->data_len-1], E_XL4BUS_CLIENT, "Incoming XL4 message is not ASCIIZ");

        // $TODO: distinguish out of memory
        BOLT_IF(!(*json = json_tokener_parse(vot->data)), E_XL4BUS_CLIENT, "Not valid json: %s", vot->data);

        json_object * aux;
        BOLT_IF(!json_object_object_get_ex(*json, "type", &aux) || !json_object_is_type(aux, json_type_string),
                E_XL4BUS_CLIENT, "No/non-string type property in %s", json_object_get_string(*json));

        *type = json_object_get_string(aux);

    } while(0);

    if (err != E_XL4BUS_OK) {
        json_object_put(*json);
        *json = 0;
    }

    return err;

}

static void release_message(xl4bus_client_t * clt, message_internal_t * mint, int ok) {

    clt->on_delivered(clt, mint->msg, mint->custom, ok);

    client_internal_t * i_clt = clt->_private;
    HASH_DEL(i_clt->stream_hash, mint);
    DL_DELETE(i_clt->message_list, mint);

    for (int i=0; i<mint->key_count; i++) {
        release_remote_info(mint->remotes[i]);
    }
    cfg.free(mint->remotes);

    json_object_put(mint->addr);
    cfg.free(mint);

}

void ll_send_cb(struct xl4bus_connection* conn, xl4bus_ll_message_t * msg, void * ref, int err) {
    free_outgoing_message(msg);
    json_object_put(ref);
}

int xl4bus_address_to_json(xl4bus_address_t *addr, char **json) {

    int err = E_XL4BUS_OK;
    char * res = 0;
    json_object * j_res = 0;

    do {

        BOLT_IF(!addr, E_XL4BUS_ARG, "Empty address");
        BOLT_SUB(make_json_address(addr, &j_res));
        BOLT_MEM(res = f_strdup(json_object_get_string(j_res)));

    } while (0);

    json_object_put(j_res);

    if (err) {
        free(res);
    } else {
        *json = res;
    }

    return err;

}

static int handle_presence(xl4bus_client_t * clt, json_object * root) {

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

    } while (0);

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

int send_json_message(xl4bus_client_t * clt, int is_reply, int is_final,
        uint16_t stream_id, const char * type, json_object * body, int thread_safe) {

    int err /* = E_XL4BUS_OK */;

    json_object * json = 0;
    xl4bus_ll_message_t * x_msg = 0;

    do {

        BOLT_MEM(json = json_object_new_object());
        if (body) {
            json_object_object_add(json, "body", json_object_get(body));
        }

        BOLT_MEM(body = json_object_new_string(type));
        json_object_object_add(json, "type", body);

        BOLT_MALLOC(x_msg, sizeof(xl4bus_ll_message_t));

        const char * bux = json_object_get_string(json);

        x_msg->data = bux;
        x_msg->data_len = strlen(bux) + 1;
        x_msg->content_type = "application/vnd.xl4.busmessage+json";
        x_msg->stream_id = stream_id;
        x_msg->is_reply = is_reply;
        x_msg->is_final = is_final;

        DBG("XCGH: sending json on stream %d : %s",
                x_msg->stream_id, json_object_get_string(json));

        BOLT_SUB(to_broker(clt, x_msg, 0, 0, thread_safe));

        /*
        BOLT_SUB(SEND_LL(i_clt->ll, x_msg, json));
        json = json_object_get(json);
         */

    } while(0);

    json_object_put(json);
    return err;

}

const cjose_jwk_t * key_locator(cjose_jwe_t *jwe, cjose_header_t *hdr, void * data) {

    const char * x5t = cjose_header_get(hdr, "x5t#S256", 0);
    if (!x5t) { return 0; }

    xl4bus_client_t * clt = data;
    client_internal_t * i_clt = clt->_private;
    xl4bus_connection_t * conn = i_clt->ll;

    if (z_strcmp(x5t, conn->my_x5t)) {
        return 0;
    }

    return i_clt->private_key;

}

int to_broker(xl4bus_client_t * clt, xl4bus_ll_message_t * msg, xl4bus_address_t * addr, int free_data, int thread_safe) {

    // we need to sign the message, and pass it to the lower level,
    // where it will be encrypted and sent out.

    json_object * bus_object = 0;

    int err = 0;

    client_internal_t * i_clt = clt->_private;

    void * signed_data = 0;
    char * ct = 0;
    size_t signed_data_len;

    do {

        BOLT_MEM(bus_object = json_object_new_object());
        json_object *array;
        BOLT_SUB(make_json_address(addr, &array));
        json_object_object_add(bus_object, "destinations", array);

        DBG("Attaching BUS object: %s", json_object_get_string(bus_object));

        BOLT_SUB(sign_jws(i_clt->ll, bus_object, msg->data, msg->data_len,
                msg->content_type, (char**)&signed_data, &signed_data_len));

#if XL4_DISABLE_JWS
        BOLT_MEM(ct = f_strdup("application/vnd.xl4.busmessage-trust+json"));
#else
        BOLT_MEM(ct = f_strdup("application/jose"));
#endif

        // OK, everything worked, free old data if needed and replace.
        if (free_data) {
            cfg.free((void*)msg->data);
        }

        // no freeing content type, it's always constant for this method
        // cfg.free((void*)msg->content_type);

        msg->data = signed_data;
        signed_data = 0;
        msg->content_type = ct;
        ct = 0;
        msg->data_len = signed_data_len;

        BOLT_SUB(SEND_LL(i_clt->ll, msg, 0, thread_safe));

    } while (0);

    json_object_put(bus_object);
    cfg.free(signed_data);
    cfg.free(ct);

    return err;

}

void free_outgoing_message(xl4bus_ll_message_t * msg) {
    if (!msg) { return; }
    cfg.free((void*)msg->data);
    cfg.free((void*)msg->content_type);
    cfg.free(msg);
}

#if XL4_SUPPORT_THREADS
static int handle_mt_message(struct xl4bus_connection * conn, void * buf, size_t buf_size) {

    if (buf_size == sizeof(itc_message_t) && ((itc_message_t*)buf)->magic == ITC_STOP_CLIENT_MAGIC) {
        ((client_internal_t *) ((xl4bus_client_t *) (((itc_message_t *) buf)->ref))->_private)->stop = 1;
    }

    return E_XL4BUS_OK;

}
#endif


int receive_cert_details(xl4bus_client_t * clt, message_internal_t * mint, xl4bus_ll_message_t * msg, json_object * root) {

    int err = E_XL4BUS_OK;

    client_internal_t * i_clt = clt->_private;
    xl4bus_connection_t * conn = i_clt->ll;

    int outgoing = mint->mis != MIS_NEED_REMOTE;

    do {

        json_object *body;
        json_object *tags;
        int l;

        if (!json_object_object_get_ex(root, "body", &body) ||
            !json_object_is_type(body, json_type_object) ||
            !json_object_object_get_ex(body, "x5c", &tags) ||
            !json_object_is_type(tags, json_type_array) ||
            (l = json_object_array_length(tags)) <= 0) {

            DBG("XCHG: can't find any certificates in %s", json_object_get_string(root));
            if (outgoing) {
                xl4bus_abort_stream(conn, msg->stream_id);
                release_message(clt, mint, 0);
            }
            break;

        }

        for (int i=0; i<l; i++) {

            json_object * single = json_object_array_get_idx(tags, i);

            if (outgoing) {
                if (mint->key_idx == mint->key_count) {
                    DBG("XCHG: requested certificate response overflows key count?");
                    break;
                }

                if (!accept_x5c(single, conn, &mint->remotes[mint->key_idx])) {
                    mint->key_idx++;
                }
            } else {

                accept_x5c(single, conn, 0);

            }

        }

        if (outgoing) {
            if (mint->key_idx) {
                BOLT_SUB(send_main_message(clt, mint));
            } else {
                DBG("No keys were constructed for encrypting payload");
                xl4bus_abort_stream(conn, mint->stream_id);
                release_message(clt, mint, 0);
            }
        }

    } while (0);

    return err;

}
