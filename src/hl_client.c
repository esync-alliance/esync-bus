
#include <libxl4bus/high_level.h>
#include "internal.h"
#include "porting.h"

#if XL4_PROVIDE_THREADS

typedef struct poll_info {
    pf_poll_t * polls;
    int polls_len;
} poll_info_t;

static void client_thread(void *);
static int internal_set_poll(xl4bus_client_t *, int fd, int modes);
#endif

int xl4bus_init_client(xl4bus_client_t * clt) {

#if XL4_PROVIDE_THREADS
    if (clt->use_internal_thread) {

        clt->set_poll = internal_set_poll;

        if (!pf_start_thread(client_thread, clt)) {
            return E_XL4BUS_OK;
        } else {
            return E_XL4BUS_SYS;
        }
    }
#endif

    // the caller must call process_client right away.
    return E_XL4BUS_OK;

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

        int err = pf_poll(poll_info.polls, poll_info.polls_len, timeout);
        if (err < 0) {
            xl4bus_stop_client(clt);
            break;
        }

        for (int i=0; err && i<poll_info.polls_len; i++) {
            pf_poll_t * pp = poll_info.polls + i;
            if (pp->revents) {
                err--;
                xl4bus_flag_poll(clt, pp->fd, pp->revents);
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

