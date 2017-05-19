
#include <libxl4bus/high_level.h>
#include <libxl4bus/low_level.h>
#include <netdb.h>
#include <zconf.h>
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

static void ares_gethostbyname_cb(void *, int, int, struct hostent*);
static int min_timeout(int a, int b);
static void drop_client(xl4bus_client_t * clt, xl4bus_client_condition_t);
static int ll_poll_cb(struct xl4bus_connection*, int);
static void ll_msg_cb(struct xl4bus_connection*, xl4bus_ll_message_t *);
static int create_ll_connection(xl4bus_client_t *);

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

        BOLT_ARES(ares_init(&i_clt->ares));

#if XL4_PROVIDE_THREADS
        if (clt->use_internal_thread) {
            clt->set_poll = internal_set_poll;
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

#if XL4_PROVIDE_THREADS

void xl4bus_run_client(xl4bus_client_t * clt, int * timeout) {

    client_internal_t * i_clt = clt->_private;
    // if somebody wants to set the timeout, they better do it.
    *timeout = -1;
    int err = E_XL4BUS_OK;

    while (1) {

        int old_state = i_clt->state;

        if (i_clt->state == DOWN) {

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

#if XL4_PROVIDE_IPV4
                family = AF_INET;
#elif XL4_PROVIDE_IPV6
                family = AF_INET6;
#else
#error  No address family configured, please configure at least one
#endif

                // we are ready to come out of DOWN state.
                // first need we need to do is to resolve our broker address.
                i_clt->state = RESOLVING;
                ares_gethostbyname(i_clt->ares, i_clt->host,
                        family, ares_gethostbyname_cb, clt);

#if XL4_PROVIDE_IPV6 && XL4_PROVIDE_IPV4
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

        int ll_conn_reason = 0;

        known_fd_t * fdi;
        known_fd_t * ll_fdi = 0;

        for (int i=0; i<i_clt->pending_len; i++) {

            pending_fd_t * pfd = i_clt->pending + i;
            HASH_FIND_INT(i_clt->known_fd, &pfd->fd, fdi);

            if (fdi && fdi->is_ll_conn) {
                ll_fdi = fdi;
                ll_conn_reason = pfd->flags;
            } else {
                if (pfd->flags & XL4BUS_POLL_READ) {
                    FD_SET(pfd->fd, &read);
                }
                if (pfd->flags & XL4BUS_POLL_WRITE) {
                    FD_SET(pfd->fd, &write);
                }
            }

            // $TODO: handle errors!

        }

        ares_process(i_clt->ares, &read, &write);
        if (i_clt->ll) {
            int ll_timeout;
            if (xl4bus_process_connection(i_clt->ll, ll_conn_reason, &ll_timeout) != E_XL4BUS_OK) {
                cfg.free(i_clt->ll);
                i_clt->ll = 0;
                drop_client(clt, CONNECTION_BROKE);
                continue;
            }
            *timeout = min_timeout(*timeout, ll_timeout);
        } else if (ll_conn_reason) {

            if (ll_conn_reason & XL4BUS_POLL_WRITE) {
                // this should not happen.
                BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_READ));
            }

            if (ll_conn_reason & XL4BUS_POLL_READ) {

                // no matter what, we should remove that
                // socket. When needed, the poll request from the low-level
                // will put it back.
                BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_REMOVE));
                HASH_DEL(i_clt->known_fd, ll_fdi);
                cfg.free(ll_fdi);

                // the read event came, since there is no clt, this must
                // be connection event.
                if (pf_get_socket_error(i_clt->tcp_fd)) {
                    close(i_clt->tcp_fd);
                    i_clt->tcp_fd = -1;
                } else {
                    create_ll_connection(clt);
                }
            }

        }

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
                    clt->set_poll(clt, fdi->fd, reason);
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
            ares_timeout(i_clt->ares, 0, &tv);
            *timeout = min_timeout(*timeout, timeval_to_millis(&tv));

        }

        if (i_clt->state == CONNECTING) {

            if (i_clt->tcp_fd < 0) {
                // socket has not been established, or we have failed.
                // try next address, or go down.
                ip_addr_t * addr = 0;
                if (i_clt->addresses) {
                    addr = &i_clt->addresses[i_clt->net_addr_current++];
                }
                if (!addr || addr->family == AF_UNSPEC) {
                    // no (more) addresses to try.
                    drop_client(clt, addr ? CONNECTION_FAILED : RESOLUTION_FAILED);
                    break;
                }

                void * ip_addr;
                int ip_len;
#if XL4_PROVIDE_IPV6
                if (addr->family == AF_INET6) {
                    ip_addr = addr->ipv6;
                    ip_len = 16;
                }
#endif
#if XL4_PROVIDE_IPV4
                if (addr->family == AF_INET) {
                    ip_addr = addr->ipv4;
                    ip_len = 4;
                }
#endif
                int async;
                i_clt -> tcp_fd = pf_connect_tcp(ip_addr, ip_len, i_clt->port, &async);

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
                        BOLT_SUB(clt->set_poll(clt, i_clt->tcp_fd, XL4BUS_POLL_READ));
                    }
                }
            }
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

    if (err != E_XL4BUS_OK) {
        xl4bus_client_condition_t reason;
        switch (i_clt->state) {
            case DOWN:
                return;
            case RESOLVING:
                reason = RESOLUTION_FAILED;
                break;
            case CONNECTING:
                reason = CONNECTION_FAILED;
                break;
            default:
            case CONNECTED:
                reason = CONNECTION_BROKE;
                break;
        }

        drop_client(clt, reason);
    }

}

void client_thread(void * arg) {

    poll_info_t poll_info = { .polls = 0, .polls_len = 0};
    xl4bus_client_t * clt = arg;
    client_internal_t * i_clt = clt->_private;
    i_clt->xl4_thread_space = &poll_info;

    int timeout;
    xl4bus_run_client(clt, &timeout);

    while (1) {

        int err = pf_poll(poll_info.polls, poll_info.polls_len, timeout);
        if (err < 0) {
            xl4bus_stop_client(clt);
            return;
        }

        for (int i=0; err && i<poll_info.polls_len; i++) {
            pf_poll_t * pp = poll_info.polls + i;
            if (pp->revents) {
                err--;
                if (xl4bus_flag_poll(clt, pp->fd, pp->revents) != E_XL4BUS_OK) {
                    xl4bus_stop_client(clt);
                    return;
                }
            }
        }

        xl4bus_run_client(clt, &timeout);

    }

}

int internal_set_poll(xl4bus_client_t *clt, int fd, int modes) {

    client_internal_t * i_clt = clt->_private;
    poll_info_t * poll_info = i_clt->xl4_thread_space;

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
            } else if (fd < 0) {
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
                found = v + poll_info->polls_len++;
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

        if (status != ARES_SUCCESS) {
            DBG("ARES reported failure %d", status);
        }

        int addr_count;
        int addr_start;
        for (addr_count = 0; hent->h_addr_list[addr_count]; addr_count++);

        if (!addr_count) {
            DBG("Ares hostent result has 0 addresses?");
            break;
        }

        addr_start = 0;
        if (i_clt->addresses) {
            for (; i_clt->addresses[addr_start].family != AF_UNSPEC; addr_start++);
        }

        int family = AF_UNSPEC;

#if XL4_PROVIDE_IPV6
        if (hent->h_addrtype == AF_INET6) { family = AF_INET6; }
        if (hent->h_length != 16) {
            DBG("Invalid address length %d for AF_INET6", hent->h_length);
        }
#endif
#if XL4_PROVIDE_IPV4
        if (hent->h_addrtype == AF_INET) { family = AF_INET; }
        if (hent->h_length != 4) {
            DBG("Invalid address length %d for AF_INET", hent->h_length);
        }
#endif

        if (family == AF_UNSPEC) {
            DBG("Unknown family %d", hent->h_addrtype);
            break;
        }

        size_t aux;
        BOLT_REALLOC(i_clt->addresses, ip_addr_t, addr_start + addr_count + 1, aux);
        for (int i=0; i <= addr_count; i++) {
            ip_addr_t * ip = i_clt->addresses + i + addr_start;
            if (i == addr_count) {
                ip->family = AF_UNSPEC; // last
            } else {
                ip->family = family;
#if XL4_PROVIDE_IPV4
                if (family == AF_INET) {
                    memcpy(ip->ipv4, hent->h_addr_list[i], 4);
                }
#endif
#if XL4_PROVIDE_IPV6
                if (family == AF_INET6) {
                    memcpy(ip->ipv6, hent->h_addr_list[i], 16);
                }
#endif
            }
        }

    } while (0);

    if (err != E_XL4BUS_OK) {
        drop_client(clt, RESOLUTION_FAILED);
        return;
    }

#if XL4_PROVIDE_IPV6 && XL4_PROVIDE_IPV4
    if (i_clt->dual_ip) {
        ares_gethostbyname(i_clt->ares, i_clt->host,
                AF_INET6, ares_gethostbyname_cb, clt);
        i_clt->repeat_process = 1;
        i_clt->dual_ip = 0;
        return;
    }
#endif

    i_clt->state = CONNECTING;

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
    i_clt->state = DOWN;
    i_clt->net_addr_current = 0;

    if (i_clt->addresses) {
        cfg.free(i_clt->addresses);
        i_clt->addresses = 0;
    }

    clt->conn_notify(clt, how);

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
        i_clt->ll->ll_message = ll_msg_cb;

        BOLT_SUB(xl4bus_init_connection(i_clt->ll));

        i_clt->state = CONNECTED;

    } while (0);

    return err;

}

int ll_poll_cb(struct xl4bus_connection* conn, int modes) {

    int err = E_XL4BUS_OK;
    do {

        xl4bus_client_t * clt = conn->custom;
        client_internal_t * i_clt = clt->_private;

        BOLT_IF(conn->fd != i_clt->tcp_fd, E_XL4BUS_INTERNAL,
                "connection FD doesn't match client FD");

        known_fd_t * fdi;

        HASH_FIND_INT(i_clt->known_fd, &conn->fd, fdi);
        if (!fdi && modes) {
            BOLT_MALLOC(fdi, sizeof(known_fd_t));
            fdi->fd = conn->fd;
            HASH_ADD_INT(i_clt->known_fd, fd, fdi);
        }

        if (fdi) {
            fdi->modes = modes;
        }

    } while(0);

    return err;

}

void ll_msg_cb(struct xl4bus_connection* conn, xl4bus_ll_message_t * msg) {

    DBG("Look, a message!");

}
