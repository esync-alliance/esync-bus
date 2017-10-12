
#ifndef _XL4BROKER_COMMON_H_
#define _XL4BROKER_COMMON_H_

#include <stdint.h>
#include <sys/types.h>
#include <include/libxl4bus/types.h>

#define NULL_STR(a) ((a)?(a):"(NULL)")

void print_out(const char *);
char * f_asprintf(char * fmt, ...);
char * f_strdup(const char *);
void * f_malloc(size_t);
void * f_realloc(void *, size_t);
int set_nonblocking(int fd);
uint64_t msvalue();
int get_socket_error(int fd);
char * f_strndup(const char * s, size_t n);

int load_test_x509_creds(xl4bus_identity_t * identity, char * key, char * argv0);

int load_simple_x509_creds(xl4bus_identity_t * identity, char * p_key_path,
        char * cert_path, char * ca_path, char * password);

void release_identity(xl4bus_identity_t *);

int pick_timeout(int t1, int t2);

static inline int z_strcmp(const char * s1, const char * s2) {

    if (!s1) {
        if (!s2) { return 0; }
        return -1;
    }

    if (!s2) { return 1; }

    return strcmp(s1, s2);

}

static inline char * inflate_content_type(char const * ct) {

    if (!ct) { return f_strdup("application/octet-stream"); }
    if (strchr(ct, 0)) {
        return f_asprintf("application/%s", ct);
    }
    return f_strdup(ct);

}

static const char * pack_content_type(const char * ct) {

    // this is for https://tools.ietf.org/html/rfc7515#section-4.1.10,
    // application/ can be omitted if there are no other slashes.

    if (!ct) {
        return "octet-stream";
    }

    if (!strncmp(ct, "application/", 12) && !strchr(ct+12, '/')) {
        ct += 12;
    }

    return ct;

}

static inline void secure_bzero(void * addr, size_t len) {
    for (size_t i = 0; i<len; i++) {
        ((char*)addr)[i] = 0;
    }
}

#endif
