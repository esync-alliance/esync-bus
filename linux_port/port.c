
#include <libxl4bus/build_config.h>

#include "config.h"
#include "porting.h"

#include <libxl4bus/types.h>
#include "porting_support.h"

#include "fragments/linux_if_bind.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <termios.h> // FIONREAD
#include <sys/ioctl.h>
#include <netinet/tcp.h>

#if XL4_PROVIDE_THREADS
#include <pthread.h>
#endif

#if XL4_PROVIDE_THREADS
struct runner_info {
    pf_runnable_t code;
    void * arg;
};
static void * thread_runner(void *);
#endif

ssize_t pf_send(int sockfd, const void *buf, size_t len) {
    return send(sockfd, buf, len, MSG_NOSIGNAL);
}

ssize_t pf_recv(int sockfd, void *buf, size_t len) {
    #if 0
    /* quickack disables the delayed ACK timer but has to be reset after every recv and is said to be non-portable */
    /* This gives similar speed up to TCP_NODELAY but does increase the number of individual ACK packets           */
    /* so set TCP_NODELAY only for now.                                                                            */
    int opt=1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, (void*)&opt, sizeof(int));
    #endif
    return recv(sockfd, buf, len, 0);
}

int pf_add_and_get(int * addr, int value) {

    return __atomic_add_fetch(addr, value, __ATOMIC_RELAXED);

}

// sets descriptor to non-blocking mode, return 0 if OK,
// !0 if not OK (errno must be set)
int pf_set_nonblocking(int fd) {

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;

}

void pf_set_errno(int x) {
    errno = x;
}

int pf_get_errno(void) {
    return errno;
}

uint64_t pf_ms_value() {

    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);

    return ((unsigned long long) tp.tv_sec) * 1000L +
            tp.tv_nsec / 1000000L;

}

void pf_random(void * to, size_t where) {

    do {

        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) { break; }
        while (where) {
            ssize_t rc = read(fd, to, where);
            if (rc < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ERESTART) {
                    continue;
                }
                perror("read /dev/random");
                break;
            } else if (rc == 0) {
                // EOF before where is expended?
                break;
            }
            // rc is >0 here
            where -= rc;
            to += rc;
        }

        close(fd);

        if (!where) { return; }

    } while (0);

    abort();

}

int pf_poll(pf_poll_t * polls, int polls_len, int timeout) {

    struct rlimit r_lim;

    getrlimit(RLIMIT_NOFILE, &r_lim);

    if (polls_len < 0 || polls_len > r_lim.rlim_cur) {
        pf_set_errno(EINVAL);
        return -1;
    }

    struct pollfd s_poll[polls_len];
    memset(s_poll, 0, sizeof(struct pollfd) * polls_len);
    for (int i=0; i<polls_len; i++) {

        polls[i].revents = 0;
        if ((s_poll[i].fd = polls[i].fd) < 0) {
            // DBG("pf_poll: skipping negative fd");
            continue;
        }

        s_poll[i].events = 0;
        short ine = polls[i].events;
        if (ine & XL4BUS_POLL_WRITE) {
            s_poll[i].events |= POLLOUT;
        }
        if (ine & XL4BUS_POLL_READ) {
            s_poll[i].events |= POLLIN;
        }

        // DBG("pf_poll : %d: %x->%x", s_poll[i].fd, polls[i].events, s_poll[i].events);

    }

    int ec;
    while (1) {
        ec = poll(s_poll, (nfds_t) polls_len, timeout);
        if (ec <= 0) {
            if (errno == EINTR) { continue; }
            return ec;
        }
        break;
    }

    // DBG("pf_poll: %d descriptors, %d timeout, returned %d", polls_len, timeout, ec);

    for (int i=0; i<polls_len; i++) {
        if (s_poll[i].fd < 0) { continue; }
        short ine = s_poll[i].revents;
        if (ine & POLLOUT) {
            polls[i].revents |= XL4BUS_POLL_WRITE;
        }
        if (ine & POLLIN) {
            polls[i].revents |= XL4BUS_POLL_READ;
        }
        if (ine & (POLLERR|POLLHUP|POLLNVAL)) {
            polls[i].revents |= XL4BUS_POLL_ERR;
        }
        // DBG("pf_poll: %x->%x for %d", ine, polls[i].revents, s_poll[i].fd);
    }

    return ec;

}

int pf_get_socket_error(int fd) {

    int error;
    socklen_t err_len = sizeof(int);
    int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len);
    if (rc) { return 1; }
    if (error) {
        pf_set_errno(error);
        return 1;
    }

    return 0;

}

int pf_connect_tcp(void * ip, size_t ip_len, uint16_t port, char const * net_if, int * async) {

    int family = AF_UNSPEC;
#if XL4_SUPPORT_IPV4
    if (ip_len == 4) {
        family = AF_INET;
    }
#endif
#if XL4_SUPPORT_IPV6
    if (ip_len == 16) {
        family = AF_INET6;
    }
#endif

    if (family == AF_UNSPEC) {
        DBG("Unsupported address length %d", ip_len);
        pf_set_errno(ENOTSUP);
        return -1;
    }

    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }

#if 1
    /* set tcp_nodelay improves xl4bus performance from 40mS delivery to ~ 500uS */
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  (void*)&opt, sizeof(int));
#endif

    // $TODO: ESYNC-5108 the connection must be non-blocking.
    // pf_set_nonblocking(fd);

    int rc;

    if (!(rc = if_bind(fd, net_if, family, 0))) {

        rc = -1;
        pf_set_errno(ENOTSUP);

#if XL4_SUPPORT_IPV4
        if (family == AF_INET) {
            struct sockaddr_in sin = {0};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            memcpy(&sin.sin_addr, ip, ip_len);
            rc = connect(fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
        }
#endif
#if XL4_SUPPORT_IPV6
        if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {0};
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = htons(port);
            memcpy(&sin6.sin6_addr, ip, ip_len);
            rc = connect(fd, (struct sockaddr*)&sin6, sizeof(struct sockaddr_in6));
        }
#endif

    }

    int err;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wuninitialized"
    if (!rc) {
#pragma clang diagnostic pop
        // connection actually completed already.
        *async = 0;
        return fd;
    } else if ((err = pf_get_errno()) == EINPROGRESS) {
        *async = 1;
        return fd;
    }

    DBG("pf_connect: failed with %s", strerror(err));

    close(fd);
    pf_set_errno(err);

    return -1;

}


int pf_is_feature_supported(int f) {

    if (PF_FEATURE_IF_ADDR == f) { return 1; }
    return 0;

}

void pf_shutdown_rdwr(int fd) {
    shutdown(fd, SHUT_RDWR);
}

#if XL4_PROVIDE_THREADS

int pf_start_thread(pf_runnable_t code, void * arg) {

    struct runner_info * info = ps_malloc(sizeof(struct runner_info));
    if (!info) {
        pf_set_errno(ENOMEM);
        return 1;
    }

    info->code = code;
    info->arg = arg;

    pthread_t p;

    if (pthread_create(&p, 0, thread_runner, info)) {
        ps_free(info);
        return 1;
    }

    return 0;

}

void * thread_runner(void * arg) {
    struct runner_info info;
    memcpy(&info, arg, sizeof(struct runner_info));
    ps_free(arg);
    info.code(info.arg);
    return 0;
}

int pf_init_lock(void ** lock) {

    if (!(*lock = ps_malloc(sizeof(pthread_mutex_t)))) {
        pf_set_errno(ENOMEM);
        return -1;
    }

    return pthread_mutex_init(*lock, 0);

}

int pf_lock(void** lock) {

#if XL4_DEBUG_LOCKS
    DBG("LOCKING: %p", lock);
#endif
    int rc = pthread_mutex_lock(*lock);
#if XL4_DEBUG_LOCKS
    if (rc) {
        DBG("FAILED TO LOCK: %p, %d", lock, rc);
    } else {
        DBG("LOCKED: %p", lock);
    }
#endif
    return rc;

}

int pf_unlock(void** lock) {

    int rc = pthread_mutex_unlock(*lock);
#if XL4_DEBUG_LOCKS
    DBG("UNLOCKED: %p (rc: %d)", lock, rc);
#endif
    return rc;

}

void pf_release_lock(void * lock) {

    if (lock) {
        pthread_mutex_destroy(lock);
        ps_free(lock);
    }

}

#endif /* XL4_PROVIDE_THREADS */

void pf_close(int fd) {
    close(fd);
}

#if XL4_NEED_DGRAM
ssize_t pf_recv_dgram(int sockfd, void ** addr, pf_malloc_fun _malloc) {

    unsigned char test;
    ssize_t s = recv(sockfd, &test, 1, MSG_PEEK|MSG_TRUNC);
    if (s <= 0) {
        return s;
    }
    *addr = _malloc((size_t) s);
    if (!*addr) {
        pf_set_errno(ENOMEM);
        return -1;
    }

    return recv(sockfd, *addr, (size_t) s, 0);
}
#endif

#if XL4_SUPPORT_UNIX_DGRAM_PAIR
int pf_dgram_pair(int sv[2]) {
    return socketpair(PF_UNIX, SOCK_DGRAM, 0, sv);
}
#endif

ssize_t pf_fionread(int fd) {

    int bytes;
    int rc = ioctl(fd, FIONREAD, &bytes);
    if (rc) {
        return -1;
    }
    return (ssize_t)bytes;

}

void pf_abort(const char * msg) {

    fprintf(stderr, "Abort:%s", msg);
    abort();

}

uint64_t pf_sec_time(void) {

    struct timeval tv = {.tv_sec = 0 };
    gettimeofday(&tv, 0);
    return (uint64_t)tv.tv_sec;

}

