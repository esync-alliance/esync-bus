#include "qtablefd.h"
#include "qepoll.h"
    
typedef struct epoll_event  epoll_event_t;
    
#define MAX_WAIT_EVENT  64

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

uint64_t timespec_diff(struct timespec *start, struct timespec *stop)
{
    struct timespec result;
    
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result.tv_sec = stop->tv_sec - start->tv_sec - 1;
        result.tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result.tv_sec = stop->tv_sec - start->tv_sec;
        result.tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return result.tv_sec * (uint64_t)1000000000L + result.tv_nsec;
}

extern int epoll_create(int size)
{
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
    
    if(pthread_mutex_init(&iepoll->lock, NULL)) {
        free(iepoll);
        return -1;
    }
    
    if((iepoll->epfd = qtablefd_open(FD_TYPE_EPOLL, iepoll)) < 0) {
        free(iepoll);
        return -1;
    }

    return iepoll->epfd;
}

int epoll_create1(int flags)
{
    return (flags) ? -1 : epoll_create(0);
}

extern int epoll_ctl(int epfd, int op, int fd, epoll_event_t *event)
{
    int i, rc = 0;
    iepoll_event_t *exist = NULL;
    iepoll_event_t *avail = NULL;
    iepoll_data_t *iepoll;
    
    if(fd < 0) {
        errno = EINVAL;
        return -1;
    }
    
    if(!(iepoll = qtablefd_get_data(epfd, FD_TYPE_EPOLL))) {
        return -1;
    }
    
    if(pthread_mutex_lock(&iepoll->lock)) {
        qtablefd_unref_data(epfd);
        return -1;
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
            exist->fd == fd;
        }
        else {
            rc = -1;
            errno = EEXIST;
            goto exit;
        }
    }
    
exit:
    if(pthread_mutex_unlock(&iepoll->lock)) {
        qtablefd_unref_data(epfd);
        return -1;
    }
    
    qtablefd_unref_data(fd);
    
    return rc;
}

extern int epoll_wait(int epfd, epoll_event_t *events, int maxevents, int timeout)
{
    int i, j, len1 = 0, len2 = 0, qev = 0;
    iepoll_data_t* iepoll;

    if(maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    if(!(iepoll = qtablefd_get_data(epfd, FD_TYPE_EPOLL))) {
        errno = EINVAL;
        return -1;
    }

    if(iepoll->qrevents) {
        int count = 0;
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
        qtablefd_unref_data(epfd);
        return count;
    }
    
    struct timespec tp1;
    struct timespec tp2;
    
    clock_gettime(CLOCK_MONOTONIC, &tp1);
    
    if(timeout > 0) {
        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        tp.tv_sec += timeout / 1000;
        tp.tv_nsec += (timeout % 1000) * 1000000;
        if(pthread_mutex_timedlock(&iepoll->lock, &tp)) {
            qtablefd_unref_data(epfd);
            return -1;
        }
    }
    else {
        if(pthread_mutex_lock(&iepoll->lock)) {
            qtablefd_unref_data(epfd);
            return -1;
        }
    }
    
    iepoll_event_t snap[MAX_WAIT_EVENT];
    struct pollfd s_poll[MAX_WAIT_EVENT];
    
    memcpy(snap, &iepoll->elems, sizeof(iepoll->elems));

    for(i = 0; i < MAX_WAIT_EVENT; i++) {
        if (snap[i].fd < 0) {
            continue;
        }
        s_poll[len1].fd = snap[i].fd;
        s_poll[len1].revents = 0;
        s_poll[len1++].events = snap[i].ev.events;
    }
    
    if(pthread_mutex_unlock(&iepoll->lock)) {
        qtablefd_unref_data(epfd);
        return -1;
    }
    
    if(timeout > 0) {
        clock_gettime(CLOCK_MONOTONIC, &tp2);
        int consume = (int)(timespec_diff(&tp1, &tp2)/1000000L);
        if(consume >= timeout) {
            qtablefd_unref_data(epfd);
            errno = ETIMEDOUT;
            return -1;
        }
        timeout -= consume;
    }
    
    int ec = poll(s_poll, (nfds_t)len1, timeout);

    if (ec < 0) {
        qtablefd_unref_data(epfd);
        return -1;
    }

    for (i = 0; i < len1; i++) {
        if(!s_poll[i].revents) {
            continue;
        }
        for(j = 0; j < MAX_WAIT_EVENT; j++) {
            if(s_poll[i].fd == snap[j].fd) { break; }
        }
        if(len2 != maxevents) { 
            memcpy(&events[len2], &snap[j].ev, sizeof(epoll_event_t));
            events[len2++].events = s_poll[i].revents;
        }
        else {
            memcpy(&iepoll->revents[qev], &snap[j].ev, sizeof(epoll_event_t));
            iepoll->revents[qev++].events = s_poll[i].revents;
        }    
    }
    
    iepoll->qrevents = qev;
    
    qtablefd_unref_data(epfd);
    
    return ec;
}

void epoll_close(void* ptr)
{
    iepoll_data_t* iepoll = (iepoll_data_t*)ptr;
    pthread_mutex_destroy(&iepoll->lock);
}
