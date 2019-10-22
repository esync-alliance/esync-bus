#ifndef _QEPOLL_H_
#define _QEPOLL_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>

enum EPOLL_EVENTS
{
    EPOLLIN = POLLIN,
    EPOLLPRI = POLLPRI,
    EPOLLOUT = POLLOUT,
    EPOLLRDNORM = POLLRDNORM,
    EPOLLRDBAND = POLLRDBAND,
    EPOLLWRNORM = POLLWRNORM,
    EPOLLWRBAND = POLLWRBAND,
    EPOLLERR = POLLERR,
    EPOLLHUP = POLLHUP,
};

/* Valid opcodes ( "op" parameter ) to issue to epoll_ctl().  */
#define EPOLL_CTL_ADD 1        /* Add a file decriptor to the interface.  */
#define EPOLL_CTL_DEL 2        /* Remove a file decriptor from the interface.  */
#define EPOLL_CTL_MOD 3        /* Change file decriptor epoll_event structure.  */

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;        	/* Epoll events */
    epoll_data_t data;        /* User data variable */
};

int epoll_create(int size);
int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#endif