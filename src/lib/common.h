
#ifndef _XL4BUS_LIB_COMMON_H_
#define _XL4BUS_LIB_COMMON_H_

#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include <include/libxl4bus/types.h>

#if defined(__ANDROID__) && __ANDROID__
#include <android/log.h>
#define XL4BUS_ANDROID (1)
#define XL4BUS_ANDROID_TAG "xl4bus-broker"
#define MSG_OUT(fmt, c...) do { \
    __android_log_print(ANDROID_LOG_INFO, XL4BUS_ANDROID_TAG, fmt, ## c); \
} while (0)
#else
#define XL4BUS_ANDROID (0)
#define MSG_OUT(fmt, c...) do { \
    printf(fmt, ## c); \
} while (0)
#endif

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
char * addr_to_str(xl4bus_address_t *);
char * simple_password_input(struct xl4bus_X509v3_Identity *);
char * console_password_input(struct xl4bus_X509v3_Identity *);

int load_test_x509_creds(xl4bus_identity_t * identity, char * key, const char * argv0);
int load_test_data_x509_creds(xl4bus_identity_t * identity, char * key);

xl4bus_asn1_t * load_pem(char *path);

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

static const char * deflate_content_type(const char * ct) {

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

// point to memory that has at least 19 bytes
// format : MM-DD:HH:MM:SS.FFF

static inline void my_str_time(char * ptr) {

    struct tm tmnow;
    struct timeval tv;
    gettimeofday(&tv, 0);

    int micros = (int)(tv.tv_usec % 1000);
    int millis = (int)(tv.tv_usec / 1000);
    if (micros >= 500) {
        // rout
        millis++;
    }
    while (millis >= 1000) {
        // millis should always either be 1000 or less,
        // but just in case there is something wrong...
        millis -= 1000;
        tv.tv_sec++;
    }

    localtime_r(&tv.tv_sec, &tmnow);
    if (!strftime(ptr, 19, "%m-%d:%H:%M:%S", &tmnow)) {
        strcpy(ptr, "strftime?");
        return;
    }

    ptr[14] = '.';
    ptr[15] = (char) ((millis / 100) + '0');
    ptr[16] = (char) (((millis / 10) % 10) + '0');
    ptr[17] = (char) (millis % 10 + '0');
    ptr[18] = 0;

}

static inline void free_s(void * ptr, size_t s) {

    // $TODO: I don't understand why memset_s is not available,
    // <string.h> is included, and language is set to c11...
    // memset_s(ptr, s, 0, s);

    volatile unsigned char *p = ptr;
    while (s--) { *p++ = 0; }

    free(ptr);

}

#endif
