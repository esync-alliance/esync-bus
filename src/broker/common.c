
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include "broker/common.h"
#include "broker/debug.h"

static xl4bus_buf_t * load_full(char * path);
static char * simple_password (struct xl4bus_X509v3_Identity *);

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



void load_simple_x509_creds(xl4bus_identity_t * identity, char * p_key_path, char * cert_path, char * ca_path, char * password) {

    // xl4bus_identity_t * identity = f_malloc(sizeof(xl4bus_identity_t));

    memset(identity, 0, sizeof(xl4bus_identity_t));

    identity->type = XL4BIT_X509;
    identity->x509.private_key = load_full(p_key_path);
    identity->x509.trust = f_malloc(2 * sizeof(void*));
    identity->x509.chain = f_malloc(2 * sizeof(void*));
    identity->x509.trust[0] = load_full(ca_path);
    identity->x509.chain[0] = load_full(cert_path);
    if (password) {
        identity->x509.custom = password;
        identity->x509.password = simple_password;
    }

}

// note that we return buffer with PEM, and a terminating
// 0, and length includes the terminating 0. This is what
// mbedtls requires.
xl4bus_buf_t * load_full(char * path) {

    int fd = open(path, O_RDONLY);
    int ok = 0;
    if (fd < 0) {
        DBG_SYS("Failed to open %s", path);
        return 0;
    }

    xl4bus_buf_t * buf = f_malloc(sizeof(xl4bus_buf_t));

    do {

        off_t size = lseek(fd, 0, SEEK_END);
        if (size == (off_t)-1) {
            DBG_SYS("Failed to seek %s", path);
            break;
        }
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            DBG_SYS("Failed to rewind %s", path);
            break;
        }

        buf->len = (size_t) (size + 1);
        void * ptr = buf->data = f_malloc(buf->len);
        while (size) {
            ssize_t rd = read(fd, ptr, (size_t) size);
            if (rd < 0) {
                DBG_SYS("Failed to read from %s", path);
                break;
            }
            if (!rd) {
                DBG("Premature EOF reading %d, file declared %d bytes, read %d bytes, remaining %d bytes",
                        path, buf->len-1, ptr-(void*)buf->data, size);
                break;
            }
            size -= rd;
            ptr += rd;
        }

        if (!size) { ok = 1; }

    } while(0);

    close(fd);

    if (!ok) {
        free(buf->data);
        free(buf);
        return 0;
    }

    return buf;


}

static char * simple_password (struct xl4bus_X509v3_Identity * id) {

    return id->custom;

}