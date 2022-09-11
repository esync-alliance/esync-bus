
#include "config.h"

#if XL4_PROVIDE_EPOLL

#include "xl4_epoll.h"
#include "xl4_tablefd.h"
#include "porting.h"

typedef struct epoll_event  epoll_event_t;

typedef struct iepoll_event {
    int fd;
    epoll_event_t ev;
} iepoll_event_t;

typedef struct iepoll_data {
    int epfd;
    int qrevents;
    pthread_mutex_t lock;
    iepoll_event_t elems[MAX_WAIT_EVENT];
    epoll_event_t revents[MAX_WAIT_EVENT];
} iepoll_data_t;

static uint64_t ms_value() {

    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    return ((unsigned long long) tp.tv_sec) * 1000L +
           tp.tv_nsec / 1000000L;

}


int epoll_create1(int size) {
    int i;
    iepoll_data_t* iepoll;

    if(size < 0) {
        errno = EINVAL;
        return -1;
    }

    if(!(iepoll = malloc(sizeof(iepoll_data_t)))) {
        return -1;
    }

    iepoll->qrevents = 0;

    for(i = 0; i < MAX_WAIT_EVENT; i++) {
        iepoll->elems[i].fd = -1;
    }

    if (pthread_mutex_init(&iepoll->lock, 0)) {
        free(iepoll);
        return -1;
    }

    if((iepoll->epfd = xl4_tablefd_open(FD_TYPE_EPOLL, iepoll)) < 0) {
        free(iepoll);
        return -1;
    }

    return iepoll->epfd;
}

int epoll_ctl(int epfd, int op, int fd, epoll_event_t *event) {
    int i, rc = 0;
    iepoll_event_t *exist = NULL;
    iepoll_event_t *avail = NULL;
    iepoll_data_t *iepoll;

    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }

    if (!(iepoll = xl4_tablefd_get_data(epfd, FD_TYPE_EPOLL))) {
        errno = EINVAL; //?
        return -1;
    }

    if(pthread_mutex_lock(&iepoll->lock)) {
        rc = -1;
        goto exit;
    }

    for(i = 0; i < MAX_WAIT_EVENT; i++) {
        if(!exist) {
            if(iepoll->elems[i].fd == fd) {
                exist = &iepoll->elems[i];
                break;
            }
        }
        if(!avail) {
            if(iepoll->elems[i].fd == -1) {
                avail = &iepoll->elems[i];
            }
        }
    }

    if(!exist) {
        if(op == EPOLL_CTL_ADD) {
            if(!avail) {
                rc = -1;
                errno = ENOMEM;
                goto exit;
            }
            else {
                memcpy(&avail->ev, event, sizeof(epoll_event_t));
                avail->fd = fd;
            }
        }
        else {
            rc = -1;
            errno = ENOENT;
            goto exit;
        }
    }
    else {
        if(op == EPOLL_CTL_DEL) {
            memset(&exist->ev, 0, sizeof(epoll_event_t));
            exist->fd = -1;
        }
        else if(op == EPOLL_CTL_MOD) {
            memcpy(&exist->ev, event, sizeof(epoll_event_t));
            exist->fd = fd;
        }
        else {
            rc = -1;
            errno = EEXIST;
            goto exit;
        }
    }

exit:
    if(pthread_mutex_unlock(&iepoll->lock)) {
        rc = -1;
    }

    xl4_tablefd_unref_data(epfd);

    return rc;
}

int epoll_wait(int epfd, epoll_event_t *events,
                      int maxevents, int timeout) {
    int i, j, len1 = 0, len2 = 0, qev = 0;
    iepoll_data_t* iepoll;
    int count = -1;

    if(maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    if(!(iepoll = xl4_tablefd_get_data(epfd, FD_TYPE_EPOLL))) {
        errno = EINVAL;
        return -1;
    }
    bool is_locked = false;
    if(pthread_mutex_lock(&iepoll->lock)) {
        goto exit;
    }
    is_locked = true;
    if(iepoll->qrevents) {
        count = 0;
        int qlen = iepoll->qrevents;
        for(i = 0; i < qlen; i++) {
            if(iepoll->revents[i].events) {
                memcpy(&events[count++], &iepoll->revents[i], sizeof(epoll_event_t));
                iepoll->revents[i].events = 0;
                if(count == maxevents) {
                    break;
                }
            }
        }
        iepoll->qrevents -= count;
        goto exit;
    }
    uint64_t t1, t2;

    t1 = pf_ms_value();
    count = -1;
    iepoll_event_t snap[MAX_WAIT_EVENT];
    struct pollfd s_poll[MAX_WAIT_EVENT];

    memcpy(snap, iepoll->elems, sizeof(iepoll->elems));

    for(i = 0; i < MAX_WAIT_EVENT; i++) {
        if (snap[i].fd < 0) {
            continue;
        }
        s_poll[len1].fd = snap[i].fd;
        s_poll[len1].revents = 0;
        s_poll[len1++].events = snap[i].ev.events;
    }
    if (pf_unlock(&iepoll->lock)) {
        goto exit;
    }
    is_locked = false;

    if(timeout > 0) {
        t2 = pf_ms_value();
        int consume = t2-t1;
        if(consume >= timeout) {
            errno = ETIMEDOUT;
            goto exit;
        }
        timeout -= consume;
    }

    count = poll(s_poll, (nfds_t)len1, timeout);

    if (count < 0) {
        goto exit;
    }
    if (pf_lock(&iepoll->lock)) {
        goto exit;
    }
    is_locked = true;
    for (i = 0; i < len1; i++) {
        if(!s_poll[i].revents) {
            continue;
        }
        for(j = 0; j < MAX_WAIT_EVENT; j++) {
            if(s_poll[i].fd == snap[j].fd) {
                if(len2 < maxevents) {
                    memcpy(&events[len2], &snap[j].ev, sizeof(epoll_event_t));
                    events[len2++].events = s_poll[i].revents;
                }
                else {
                    memcpy(&iepoll->revents[qev], &snap[j].ev, sizeof(epoll_event_t));
                    iepoll->revents[qev++].events = s_poll[i].revents;
                }
                break;
            }
        }
    }

    iepoll->qrevents = qev;
    count = len2;
 exit:
    if (is_locked) {
        pf_unlock(&iepoll->lock);
    }
    xl4_tablefd_unref_data(epfd);

    return count;
}

void epoll_close(void* ptr) {
    iepoll_data_t* iepoll = (iepoll_data_t*)ptr;
    pthread_mutex_destroy(&iepoll->lock);
    xl4_tablefd_unref_data(iepoll->epfd);
}

#endif