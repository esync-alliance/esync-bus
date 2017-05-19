
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

static void ares_gethostbyname_cb(void *, int, int, struct hostent*);
static int min_timeout(int a, int b);
static void drop_client(xl4bus_client_t * clt);

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

                // we are ready to come out of DOWN state.
                // first need we need to do is to resolve our broker address.
                i_clt->state = RESOLVING;
                ares_gethostbyname(i_clt->ares, i_clt->host,
                        AF_UNSPEC, ares_gethostbyname_cb, clt);

            }

        }

        // we may have requested c-ares FDs to be polled.
        fd_set read;
        fd_set write;
        FD_ZERO(&read);
        FD_ZERO(&write);

        int ll_conn_reason = 0;

        known_fd_t * fdi;

        for (int i=0; i<i_clt->pending_len; i++) {

            pending_fd_t * pfd = i_clt->pending + i;
            HASH_FIND_INT(i_clt->known_fd, &pfd->fd, fdi);

            if (fdi && fdi->is_ll_conn) {
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
                i_clt->ll = 0;
                drop_client(clt);
                continue;
            }
            *timeout = min_timeout(*timeout, ll_timeout);
        }

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
                if (i_clt->net_addr_current == i_clt->net_addr_count) {
                    // no more addresses to try.
                    clt->conn_notify(clt, CONNECTION_FAILED);
                    i_clt->state = DOWN;
                    break;
                }
            }
        }

        if (i_clt->state == old_state) {
            // there is no change, let's get out.
            break;
        }

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

        BOLT_IF(status != ARES_SUCCESS, E_XL4BUS_SYS, "Ares result %d", status);

        if (i_clt->net_addr) {
            cfg.free(i_clt->net_addr);
            i_clt->net_addr = 0;
        }

        i_clt->net_addr_current = 0;
        i_clt->tcp_fd = 0;

        for (i_clt->net_addr_count = 0; hent->h_addr_list[i_clt->net_addr_count]; i_clt->net_addr_count++);
        BOLT_IF(!i_clt->net_addr_count, E_XL4BUS_INTERNAL, "Ares hostent result has 0 addresses?");
        BOLT_MALLOC(i_clt->net_addr, (size_t)i_clt->net_addr_count * (i_clt->net_addr_len = hent->h_length));
        for (int i=0; i < i_clt->net_addr_count; i++) {
            memcpy(i_clt->net_addr + i_clt->net_addr_len * i, hent->h_addr_list[i], (size_t)i_clt->net_addr_len);
        }

    } while (0);

    if (err != E_XL4BUS_OK) {
        clt->conn_notify(clt, RESOLUTION_FAILED);
        i_clt->state = DOWN;
        return;
    }

    i_clt->state = CONNECTING;

}

int min_timeout(int a, int b) {
    if (a == -1) { return b; }
    if (b == -1) { return a; }
    if (a < b) { return a; }
    return b;
}

static void drop_client(xl4bus_client_t * clt) {
    client_internal_t * i_clt = clt->_private;
    // $TODO: 2sec here is an arbitrary constant, and probably should
    // be a configuration value.
    i_clt->down_target = pf_msvalue() + 2000;
    i_clt->state = DOWN;
}
