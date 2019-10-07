
#ifndef _XL4BROKER_DEBUG_H_
#define _XL4BROKER_DEBUG_H_

#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <cjose/cjose.h>
#include <unistd.h>
#include <mbedtls/error.h>
#include <libxl4bus/types.h>

extern int debug;

#define HOW_ERR 1
#define HOW_FATAL 2
#define HOW_MSG 3

void debug_out(char const * func, char const * file, int line, int how, char const * str, ...);
void str_output_time(char *);

#define LINE_OUT(how, str, args...) debug_out(__func__, chop_path(__FILE__), __LINE__, how, str, ## args)

#define LINE_OUT_SYS(how,a,b...) LINE_OUT(how, a " - %s (%d)", ##b, strerror(errno), errno)

#define ERR(a,b...) LINE_OUT(HOW_ERR, a, ##b)
#define ERR_SYS(a,b...) LINE_OUT_SYS(HOW_ERR, a, ##b)
#define DBG_SYS(a,b...) LINE_OUT_SYS(HOW_MSG, a, ##b)
#define DBG(a,b...) do { if (debug) { LINE_OUT(HOW_MSG, a, ##b); } } while(0)
#define MSG(a,b...) do { LINE_OUT(HOW_MSG, a, ##b); } while(0)
#define FATAL(a,b...) do { LINE_OUT(HOW_FATAL, a, ##b); } while(0)
#define FATAL_SYS(a,b...) do { LINE_OUT_SYS(HOW_FATAL, a, ##b); } while(0)
#define FATAL_DIR(rc, a,b...) do { errno = rc; LINE_OUT_SYS(HOW_FATAL, a, ##b); } while(0)

#define BOLT_MEM(a) if (!(a)) { \
    FATAL("out of memory"); \
} do{}while(0)

#define SAFE_STR(s) (s?s:"(null)")

#define BOLT(why) err = (why); DBG("setting err %d", err); break; do{}while(0)
#define BOLT_SAY(__err, msg, x...) err = (__err); DBG(msg ", setting err %d", ## x, err); break; do{}while(0)
#define BOLT_IF(cond, __err, msg, x...) if ((cond)) { err = (__err); DBG(msg ", setting err %d", ## x, err); break; } do{}while(0)
#define BOLT_M1(a, m, x...) if ((a)==-1) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SYS(a, m, x...) if ((a)) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_DIR(a, m, x...) if ((err = a)) { errno = err; DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SUB(a) { err = (a); if (err != E_XL4BUS_OK) { BOLT_SAY(err, #a); }} do{}while(0)
#define BOLT_CJOSE(a) { c_err.code = CJOSE_ERR_NONE; a; if (c_err.code != CJOSE_ERR_NONE) { BOLT_SAY(cjose_to_err(&c_err), "cjose failure %d %s:%s", c_err.code, c_err.message, #a);}} do {} while(0)
#define BOLT_ARES(a) { int __err = (a); if (__err != ARES_SUCCESS) { if (__err == ARES_ENOMEM) { __err = E_XL4BUS_MEMORY; } else { __err = E_XL4BUS_INTERNAL; } BOLT_SAY(__err, "%s", #a); } } do{} while(0)
#define BOLT_NEST() BOLT_SUB(err)
#define BOLT_MTLS(a) do { \
    int __mtls_err = (a); \
    if (__mtls_err) { \
        if (debug) { \
            char e_buf[512]; \
            mbedtls_strerror(__mtls_err, e_buf, 512); \
            DBG("%s failed with (%x) %s", #a, __mtls_err, e_buf); \
        } \
        err = E_XL4BUS_SYS; \
    } \
} while(0); \
if (err) { break; } \
do {} while(0)

static inline const char * chop_path(const char * path) {
    const char * aux = strrchr(path, '/');
    if (aux) { return aux + 1; }
    return path;
}

static inline int cjose_to_err(cjose_err * err) {

    switch (err->code) {

        case CJOSE_ERR_NONE:
            return E_XL4BUS_OK;
        case CJOSE_ERR_NO_MEMORY:
            return E_XL4BUS_MEMORY;
            // case CJOSE_ERR_CRYPTO:
            // case CJOSE_ERR_INVALID_ARG:
            // case CJOSE_ERR_INVALID_STATE:
        default:
            return E_XL4BUS_INTERNAL;
    }

}

#endif
