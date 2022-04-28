#include <INTEGRITY.h>
#include <libxl4bus/build_config.h>
#include "config.h"
#include "porting.h"
#include "debug.h"
#include <libxl4bus/types.h>
#include "internal.h"

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
#include <time.h>
#include <termios.h> // FIONREAD
#include <sys/ioctl.h>
#include <netinet/tcp.h>

#if XL4_PROVIDE_THREADS
#include <pthread.h>
#endif
static LocalMutex ghs_mutex = NULL;

#if XL4_PROVIDE_THREADS
struct runner_info {
    pf_runnable_t code;
    void * arg;
};
static void * thread_runner(void *);
#endif

ssize_t pf_send(int sockfd, const void *buf, size_t len) {
    return send(sockfd, buf, len, 0);
}

ssize_t pf_recv(int sockfd, void *buf, size_t len) {
    return recv(sockfd, buf, len, 0);
}

int pf_add_and_get(int *addr, int value) {
#if 0
    // AtomicModify is only used when the addr is changed from int* to uint64_t*.
    // Otherwise, INTEGRITY throws errorflow error
    Address oldval;
    AtomicModify((Address *)addr, &oldval, 0, (Value)value);
#else
    if (!ghs_mutex)
        CheckSuccess(CreateLocalMutex(&ghs_mutex));

    CheckSuccess(WaitForLocalMutex(ghs_mutex));
    *addr += value;
    CheckSuccess(ReleaseLocalMutex(ghs_mutex));
#endif
    return *addr;
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
    /* Integrity only support CLOCK_REALTIME */
    clock_gettime(CLOCK_REALTIME, &tp);

    return ((unsigned long long) tp.tv_sec) * 1000L +
            tp.tv_nsec / 1000000L;
}

void pf_random(void * to, size_t where) {
    gid_t curr_gid;
    pid_t curr_pid;
    uid_t curr_uid;
    int i, k;
    struct timespec ts;
    unsigned char v;
    uint8_t *buf = (uint8_t *)to;

    /*  There is no /dev/urandom in INTEGRITY to get random data like Linux
        This API generates some random data based on some uncertaint data
     */

    curr_gid = getgid();
    *buf++ = curr_gid;
    where--;
    if (where == 0) return;

    curr_pid = getpid();
    *buf++ = curr_pid;
    where--;
    if (where == 0) return;

    curr_uid = getuid();
	*buf++ = curr_uid;
    where--;
	if (where == 0) return;

    for (i = 0; i < where; i++) {
        /*
         * burn some cpu; hope for interrupts, cache collisions, bus
         * interference, etc.
         */
        for (k = 0; k < 99; k++)
            ts.tv_nsec = random();

        /* get wall clock time.  */
        clock_gettime(CLOCK_REALTIME, &ts);

        /* take 8 bits */
        v = (unsigned char)(ts.tv_nsec % 256);
        *buf++ = v;
    }
}

int pf_poll(pf_poll_t * polls, int polls_len, int timeout) {

    if (polls_len < 0) {
        pf_set_errno(EINVAL);
        return -1;
    }
    struct pollfd s_poll[polls_len];
    for (int i=0; i<polls_len; i++) {

        polls[i].revents = 0;
        if ((s_poll[i].fd = polls[i].fd) < 0) {
            DBG("pf_poll: skipping negative fd");
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
    /* set tcp_nodelay improves xl4bus performance from 40mS delivery to ~ 500uS */
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  (void*)&opt, sizeof(int));

    int rc = -1;
#if XL4_SUPPORT_IPV4
    if (family == AF_INET) {
        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        memcpy(&sin.sin_addr, ip, ip_len);
        rc = connect(fd, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
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

    int err;
    if (!rc) {
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

void pf_shutdown_rdwr(int fd) {
    shutdown(fd, SHUT_RDWR);
}

#if XL4_PROVIDE_THREADS

int pf_start_thread(pf_runnable_t code, void * arg) {

    struct runner_info * info = cfg.malloc(sizeof(struct runner_info));
    if (!info) {
        pf_set_errno(ENOMEM);
        return 1;
    }

    info->code = code;
    info->arg = arg;

    pthread_t p;

    if (pthread_create(&p, 0, thread_runner, info)) {
        cfg.free(info);
        return 1;
    }

    return 0;

}

void * thread_runner(void * arg) {
    struct runner_info info;
    memcpy(&info, arg, sizeof(struct runner_info));
    cfg.free(arg);
    info.code(info.arg);
    return 0;
}

int pf_init_lock(void ** lock) {

    if (!(*lock = cfg.malloc(sizeof(pthread_mutex_t)))) {
        pf_set_errno(ENOMEM);
        return -1;
    }
    return pthread_mutex_init(*lock, 0);

}

int pf_lock(void** lock) {
    return pthread_mutex_lock(*lock);
}

int pf_unlock(void** lock) {
    return pthread_mutex_unlock(*lock);
}

void pf_release_lock(void * lock) {

    if (lock) {
        pthread_mutex_destroy(lock);
        cfg.free(lock);
    }

}

#endif /* XL4_PROVIDE_THREADS */

void pf_close(int fd) {
    close(fd);
}

#if XL4_NEED_DGRAM
ssize_t pf_recv_dgram(int sockfd, void ** addr, pf_malloc_fun _malloc) {

    size_t s = pf_fionread(sockfd);
    if (s <= 0) {
        return s;
    }
    *addr =  (unsigned char *)_malloc(s);
    if (!*addr) {
        pf_set_errno(ENOMEM);
        return -1;
    }
    return recv(sockfd, *addr, (size_t)s, 0);
}
#endif

#if XL4_SUPPORT_UNIX_DGRAM_PAIR
int pf_dgram_pair(int sv[2]) {
    /* INTEGRITY doesn't support SOCK_DGRAM for AF_UNIX like Linux come up with a solution using SOCK_STREAM */
    return socketpair(PF_LOCAL, SOCK_STREAM, 0, sv);
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

int pf_is_feature_supported(int f) {
    return 0;
}
