
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "broker/common.h"
#include "broker/debug.h"

void print_out(const char * msg) {

    printf("%s\n", msg);

}

char * f_asprintf(char * fmt, ...) {

    char * ret;
    va_list ap;

    va_start(ap, fmt);
    int rc = vasprintf(&ret, fmt, ap);
    va_end(ap);

    if (rc < 0) {
        return 0;
    }

    return ret;

}

char * f_strdup(const char * s) {
    if (!s) { return 0; }
    size_t l = strlen(s) + 1;
    char * r = f_malloc(l);
    return memcpy(r, s, l);
}

void * f_malloc(size_t t) {

    void * r = malloc(t);
    if (!r) {
        DBG("Failed to malloc %ld bytes", t);
        abort();
    }

    memset(r, 0, t);

    return r;

}

void * f_realloc(void * m, size_t t) {

    void * r = realloc(m, t);
    if (!r) {
        DBG("Failed to realloc %p to %ld bytes", m, t);
        abort();
    }

    return r;

}

int set_nonblocking(int fd) {

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;

}

uint64_t msvalue() {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    return ((unsigned long long) tp.tv_sec) * 1000L +
            tp.tv_nsec / 1000000L;
}

int get_socket_error(int fd) {

    int error;
    socklen_t err_len = sizeof(int);
    int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len);
    if (rc) { return 1; }
    if (error) {
        errno = error;
        return 1;
    }

    return 0;

}
