
#ifndef _TEST_TESTS_H_
#define _TEST_TESTS_H_

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "lib/common.h"
#include <libxl4bus/low_level.h>

static inline const char * test_chop_path(const char * path) {
    const char * aux = strrchr(path, '/');
    if (aux) { return aux + 1; }
    return path;
}

#define iSYS(op, f, x...) do { \
    if (op) { \
        iERR(f "(%s -> system err %s)", ## x, #op, strerror(errno));\
    } \
} while(0)

#define iSYS_M1(op, f, x...) do { \
    if ((op) < 0) { \
        iERR(f "(%s -> system err %s)", ## x, #op, strerror(errno));\
    } \
} while(0)

#define iXL4(op, f, x...) do { \
    int __xl4_res = (op); \
    if (__xl4_res != E_XL4BUS_OK) { \
        iERR(f "(%s -> XL4BUS err %s)", ## x, #op, xl4bus_strerr(errno)); \
    } \
} while(0)

#define iERR(f, x...) do { \
    fprintf(stderr, "(TEST ERROR, ABORTING) %s:%d: " f "\n", test_chop_path(__FILE__), __LINE__ , ## x); \
    _exit(1); \
    } while(0)

#define iDBG(f, x...)   do { \
    fprintf(stderr, "%s:%d: " f "\n", test_chop_path(__FILE__), __LINE__ , ## x); \
    } while(0)

static inline void test_print_out(const char * t) {
    iDBG("%s", t);
}

#endif

