
#include <libxl4bus/high_level.h>
#include <libxl4bus/low_level.h>
#include <netdb.h>
#include "internal.h"
#include "porting.h"
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
#define SEND_LL(a,b,c) xl4bus_send_ll_message(a,b,c,(a)->mt_support)
#else
#define SEND_LL(a,b,c) xl4bus_send_ll_message(a,b,c)
#endif

static void ares_gethostbyname_cb(void *, int, int, struct hostent*);
static int min_timeout(int a, int b);
static void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t);
static int ll_poll_cb(struct xl4bus_connection*, int, int);
static int ll_msg_cb(struct xl4bus_connection*, xl4bus_ll_message_t *);
static int create_ll_connection(xl4bus_client_t *);
static int process_message_out(xl4bus_client_t *, message_internal_t *);
static int get_xl4bus_message(xl4bus_message_t const *, json_object **, char const **);
static void release_message(xl4bus_client_t *, message_internal_t *, int);
static int build_address_list(json_object *, xl4bus_address_t **);
static int handle_presence(xl4bus_client_t * clt, json_object*);

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

                *timeout = min_timeout(*timeout, (int) left);

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

                    int ll_timeout;
                    ll_called = 1;
                    if (xl4bus_process_connection(i_clt->ll, pfd->fd, pfd->flags, &ll_timeout) != E_XL4BUS_OK) {
                        cfg.free(i_clt->ll);
                        i_clt->ll = 0;
                        drop_client(clt, XL4BCC_CONNECTION_BROKE);
                        continue;
                    }
                    *timeout = min_timeout(*timeout, ll_timeout);
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
                *timeout = min_timeout(*timeout, timeval_to_millis(&tv));
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
            int ll_timeout;
            BOLT_SUB(xl4bus_process_connection(i_clt->ll, -1, 0, &ll_timeout));
            *timeout = min_timeout(*timeout, ll_timeout);
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
            xl4bus_stop_client(clt);
            return;
        }

        for (int i=0; res && i<poll_info.polls_len; i++) {
            pf_poll_t * pp = poll_info.polls + i;
            if (pp->revents) {
                res--;
                // DBG("Clt %p : flagging %x for fd %d", clt, pp->revents, pp->fd);
                if (xl4bus_flag_poll(clt, pp->fd, pp->revents) != E_XL4BUS_OK) {
                    xl4bus_stop_client(clt);
                    return;
                }
            }
        }

        xl4bus_run_client(clt, &timeout);
        if (i_clt->stop) { break; }

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

int min_timeout(int a, int b) {
    if (a == -1) { return b; }
    if (b == -1) { return a; }
    if (a < b) { return a; }
    return b;
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

#endif

        memcpy(&i_clt->ll->identity, &clt->identity, sizeof(clt->identity));

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

    } while(0);

    return err;

}

int ll_msg_cb(struct xl4bus_connection* conn, xl4bus_ll_message_t * msg) {

    int err = E_XL4BUS_OK;
    json_object * root = 0;

    do {

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;
        char const * type;

        if (i_clt->state == CS_RUNNING) {

            DBG("XCHG: Incoming stream %d", msg->stream_id);

            message_internal_t * mint;
            HASH_FIND(hh, i_clt->stream_hash, &msg->stream_id, 2, mint);
            if (mint) {

                BOLT_SUB(get_xl4bus_message(&msg->message, &root, &type));

                if (mint->mis == MIS_WAIT_DESTINATIONS && !strcmp("xl4bus.destination-info", type)) {

                    if (msg->is_final) {
                        // the broker saying it's not deliverable.
                        DBG("XCHG: no destinations");
                        release_message(clt, mint, 0);
                    } else {

                        DBG("XCHG: got destination info");

                        // here we would request certificate details, but since
                        // we are using trust, there is nothing to request,
                        // so we can skip on to sending the actual message.
                        // mint->mis = MIS_WAIT_DETAILS;

                        xl4bus_ll_message_t * x_msg;
                        BOLT_MALLOC(x_msg, sizeof(xl4bus_ll_message_t));

                        memcpy(&x_msg->message, mint->msg, sizeof(msg->message));

                        x_msg->stream_id = msg->stream_id;
                        x_msg->is_reply = 1;
                        BOLT_SUB(SEND_LL(i_clt->ll, x_msg, 0));
                        mint->mis = MIS_WAIT_CONFIRM;

                    }


                } else if (mint->mis == MIS_WAIT_CONFIRM && !strcmp("xl4bus.message-confirm", type)) {

                    DBG("XCHG: got confirmation");

                    if (!msg->is_final) {
                        DBG("Message confirmation was not a final stream message!");
                        xl4bus_abort_stream(conn, mint->stream_id);
                    }
                    release_message(clt, mint, 1);

                }

            } else {

                if (!strcmp(msg->message.content_type, "application/vnd.xl4.busmessage+json")) {

                    BOLT_SUB(get_xl4bus_message(&msg->message, &root, &type));

                    if (!strcmp(type, "xl4bus.presence")) {
                        handle_presence(clt, root);
                    } else {

                        DBG("Unknown message type %s received : %s", type, json_object_get_string(root));

                    }

                } else {

                    clt->on_message(clt, &msg->message);

                }

            }

            break;

        }

        BOLT_SUB(get_xl4bus_message(&msg->message, &root, &type));

        if (i_clt->state == CS_EXPECTING_ALGO && !strcmp(type, "xl4bus.alg-supported")) {

            i_clt->state = CS_EXPECTING_CONFIRM;

            // send registration request.
            // https://gitlab.excelfore.com/schema/json/xl4bus/registration-request.json

            json_object * json = json_object_new_object();
            json_object_object_add(json, "type", json_object_new_string("xl4bus.registration-request"));

#if 1   /* replace with X.509 based auth */

            BOLT_IF(conn->identity.type != XL4BIT_TRUST, E_XL4BUS_ARG, "Only trust identity is supported yet");

            {
                json_object * id = json_object_new_object();
                json_object_object_add(json, "xxx-id", id);

                if (conn->identity.trust.is_dm_client) {
                    json_object_object_add(id, "is_dmclient", json_object_new_boolean(1));
                } else if (conn->identity.trust.update_agent) {
                    json_object_object_add(id, "is_update_agent", json_object_new_boolean(1));
                    json_object_object_add(id, "update_agent",
                            json_object_new_string(conn->identity.trust.update_agent));
                } else {
                    BOLT_SAY(E_XL4BUS_ARG, "Can not identify as either update agent or dmclient");
                }

                json_object * groups = json_object_new_array();
                json_object_object_add(id, "groups", groups);
                for (int i=0; i<conn->identity.trust.group_cnt; i++) {
                    json_object_array_add(groups, json_object_new_string(conn->identity.trust.groups[i]));
                }

            }
#endif

            xl4bus_ll_message_t * x_msg;
            BOLT_MALLOC(x_msg, sizeof(xl4bus_ll_message_t));

            const char * bux = json_object_get_string(json);
            x_msg->message.data = bux;
            x_msg->message.data_len = strlen(bux) + 1;
            x_msg->message.content_type = "application/vnd.xl4.busmessage+json";

            x_msg->stream_id = msg->stream_id;
            x_msg->is_reply = 1;

            BOLT_SUB(SEND_LL(conn, x_msg, json));

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
                process_message_out(clt, mit);
            }

        } else {

            DBG("Resetting handshake. State: %s, incoming typ: %s, is_final: %d", state_str(i_clt->state),
                    type, msg->is_final);

        }

    } while (0);

    json_object_put(root);

    return err;

}

int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg) {

    int err = E_XL4BUS_OK;
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

        BOLT_SUB(process_message_out(clt, mint));

    } while(0);

    if (err != E_XL4BUS_OK) {
        free(mint);
        json_object_put(addr);
    }

    return err;

}

void xl4bus_stop_client(xl4bus_client_t * clt) {

    drop_client(clt, XL4BCC_CLIENT_STOPPED);
    client_internal_t * i_clt = clt->_private;
#if XL4_PROVIDE_THREADS
    i_clt->stop = 1;
#endif

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

static int process_message_out(xl4bus_client_t * clt, message_internal_t * msg) {

    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    if (i_clt->state != CS_RUNNING) {
        return err;
    }

    while (msg->mis == MIS_VIRGIN) {
        // request destinations
        // https://gitlab.excelfore.com/schema/json/xl4bus/request-destinations.json
        json_object * json = json_object_new_object();
        json_object * body;

        json_object_object_add(json, "type", json_object_new_string("xl4bus.request-destinations"));
        json_object_object_add(json, "body", body = json_object_new_object());
        json_object_object_add(body, "destinations", json_object_get(msg->addr));

        xl4bus_ll_message_t * x_msg;
        BOLT_MALLOC(x_msg, sizeof(xl4bus_ll_message_t));

        const char * bux = json_object_get_string(json);
        x_msg->message.data = bux;
        x_msg->message.data_len = strlen(bux) + 1;
        x_msg->message.content_type = "application/vnd.xl4.busmessage+json";
        x_msg->stream_id = msg->stream_id;

        DBG("XCGH: sending request-destinations on stream %d : %s", x_msg->stream_id, json_object_get_string(json));

        BOLT_SUB(SEND_LL(i_clt->ll, x_msg, json));

        // json_object_put(json);

        msg->mis = MIS_WAIT_DESTINATIONS;
    }

    return err;

}

int get_xl4bus_message(xl4bus_message_t const * msg, json_object ** json, char const ** type) {

    int err = E_XL4BUS_OK;
    *json = 0;

    do {

        BOLT_IF(strcmp("application/vnd.xl4.busmessage+json", msg->content_type),
                E_XL4BUS_CLIENT, "Invalid content type %s", SAFE_STR(msg->content_type));

        // the json must be ASCIIZ.
        BOLT_IF(((uint8_t*)msg->data)[msg->data_len-1], E_XL4BUS_CLIENT,
                "Incoming message is not ASCIIZ");

        BOLT_IF(!(*json = json_tokener_parse(msg->data)), E_XL4BUS_CLIENT, "Not valid json: %s", msg->data);

        json_object * aux;
        BOLT_IF(!json_object_object_get_ex(*json, "type", &aux) || !json_object_is_type(aux, json_type_string),
                E_XL4BUS_CLIENT, "No/non-string type property in %s", msg->data);

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

    json_object_put(mint->addr);
    cfg.free(mint);

}

void ll_send_cb(struct xl4bus_connection* conn, xl4bus_ll_message_t * msg, void * ref, int err) {
    cfg.free(msg);
    json_object_put(ref);
}

int build_address_list(json_object * j_list, xl4bus_address_t ** new_list) {

    int l = json_object_array_length(j_list);
    xl4bus_address_t * last = 0;
    xl4bus_address_t * next = 0;

    for (int i=0; i<l; i++) {

        if (!next) {
            next = f_malloc(sizeof(xl4bus_address_t));
            if (!next) { return E_XL4BUS_MEMORY; }
        }


        json_object * el = json_object_array_get_idx(j_list, i);
        DBG("BAL: Processing el %s", json_object_get_string(el));
        json_object * aux;
        if (json_object_object_get_ex(el, "update-agent", &aux) && json_object_is_type(aux, json_type_string)) {
            next->type = XL4BAT_UPDATE_AGENT;
            next->update_agent = f_strdup(json_object_get_string(aux));
        } else if (json_object_object_get_ex(el, "group", &aux) && json_object_is_type(aux, json_type_string)) {
            next->type = XL4BAT_GROUP;
            next->group = f_strdup(json_object_get_string(aux));
        } else if (json_object_object_get_ex(el, "special", &aux) && json_object_is_type(aux, json_type_string)) {

            char const * bux = json_object_get_string(aux);
            next->type = XL4BAT_SPECIAL;

            if (!strcmp("dmclient", bux)) {
                next->special = XL4BAS_DM_CLIENT;
            } else if (!strcmp("broker", bux)) {
                next->special = XL4BAS_DM_BROKER;
            } else {
                continue;
            }

        } else {
            continue;
        }

        if (!last) {
            *new_list = next;
        } else {
            last->next = next;
        }
        last = next;
        next = 0;

    }

    cfg.free(next);

    return E_XL4BUS_OK;

}

int address_to_json(xl4bus_address_t * addr, char ** json) {

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
