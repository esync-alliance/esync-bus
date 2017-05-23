
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

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