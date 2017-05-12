
#include "config.h"
#include "porting.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>

ssize_t pf_send(int sockfd, const void *buf, size_t len) {
    return send(sockfd, buf, len, 0);
}


ssize_t pf_recv(int sockfd, void *buf, size_t len) {
    return recv(sockfd, buf, len, 0);
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

uint64_t pf_msvalue() {

    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);

    return ((unsigned long long) tp.tv_sec) * 1000L +
            tp.tv_nsec / 1000000L;

}

void pf_random(void * to, size_t where) {

    do {

        int fd = open("/dev/random", O_RDONLY);
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

