#ifndef _XL4BUS_DEBUG_H_
#define _XL4BUS_DEBUG_H_

#include "porting.h"
#include "config.h"
#include "internal.h"

#if XL4_PROVIDE_DEBUG

#if !XL4_HAVE_GETTIMEOFDAY
#define _ltime_ \
    char now[1]; \
    now[0] = 0
#else
#define _ltime_ \
    char now[24]; \
    struct tm tmnow; \
    struct timeval tv; \
    memset(now, 0, 24); \
    gettimeofday(&tv, 0); \
    usec_to_msec(&tv); \
    localtime_r(&tv.tv_sec, &tmnow); \
    strftime(now, 20, "%m-%d:%H:%M:%S.", &tmnow); \
    sprintf(now+15, "%03d", tv.tv_usec)
#endif

#define DBG(a,b...) do { if (cfg.debug_f) { \
    _ltime_; \
    char * _str = f_asprintf("[%s] xl4bus:%s:%d " a, now, chop_path(__FILE__), __LINE__, ## b); \
    if (_str) { \
        cfg.debug_f(_str); \
        cfg.free(_str); \
    } \
} } while(0)

#define DBG_SYS(a,b...) do { if (cfg.debug_f) { \
    int _errno = pf_get_errno(); \
    _ltime_; \
    char * _str = f_asprintf("[%s] xl4bus:%s:%d error %s(%d): " a, now, chop_path(__FILE__), __LINE__, strerror(_errno), _errno, ## b); \
    if (_str) { \
        cfg.debug_f(_str); \
        cfg.free(_str); \
    } \
} } while(0)

static inline const char * chop_path(const char * path) {
    const char * aux = strrchr(path, '/');
    if (aux) { return aux + 1; }
    return path;
}

static inline void usec_to_msec(struct timeval * tv) {

    for (int i=0; i<3; i++) {
        int r = (int)(tv->tv_usec % 10);
        tv->tv_usec /= 10;
        if (r >= 5) {
            tv->tv_usec++;
        }
    }

    if (tv->tv_usec >= 1000) {
        tv->tv_usec -= 1000;
        tv->tv_sec++;
    }

}

#else

#define DBG(a...) do{}while(0)
#define DBG_SYS(a...) do{}while(0)

#endif // XL4BUS_PROVIDE_DEBUG

#define BOLT_MEM(a) if (!(a)) { \
    err = E_XL4BUS_MEMORY; \
    DBG("out of memory"); \
    break; \
} do{}while(0)

// pointer to realloc
// type of pointer
// size
#define BOLT_REALLOC(ptr,type,size,newsize) { \
    int __size = size; \
    void * __aux = cfg.realloc(ptr, (__size)*sizeof(type)); \
    if (!__aux) { err = E_XL4BUS_MEMORY; DBG("out of memory, realloc %d", __size); break; } \
    ptr = (type*)__aux; \
    newsize = __size; \
} do{}while(0)

#define BOLT_REALLOC_NS(ptr,type,size) { \
    int __size = size; \
    void * __aux = cfg.realloc(ptr, (__size)*sizeof(type)); \
    if (!__aux) { err = E_XL4BUS_MEMORY; DBG("out of memory, realloc %d", __size); break; } \
    ptr = (type*)__aux; \
} do{}while(0)

#define SAFE_STR(s) (s?s:"(null)")

#define BOLT(why) err = (why); DBG("setting err %d", err); break; do{}while(0)
#define BOLT_SAY(__err, msg, x...) err = (__err); DBG(msg ", setting err %d", ## x, err); break; do{}while(0)
#define BOLT_IF(cond, __err, msg, x...) if ((cond)) { err = (__err); DBG(msg ", setting err %d", ## x, err); break; } do{}while(0)
#define BOLT_M1(a, m, x...) if ((a)==-1) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SYS(a, m, x...) if ((a)) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SUB(a) { err = (a); if (err != E_XL4BUS_OK) { BOLT_SAY(err, #a); }} do{}while(0)
#define BOLT_NEST() BOLT_SUB(err)
#define BOLT_CJOSE(a) { c_err.code = CJOSE_ERR_NONE; a; if (c_err.code != CJOSE_ERR_NONE) { BOLT_SAY(cjose_to_err(&c_err), "cjose failure %d (%s:%d) %s:%s", c_err.code, c_err.file, c_err.line, c_err.message, #a);}}
#define BOLT_ARES(a) { int __err = (a); if (__err != ARES_SUCCESS) { if (__err == ARES_ENOMEM) { __err = E_XL4BUS_MEMORY; } else { __err = E_XL4BUS_INTERNAL; } BOLT_SAY(__err, "%s", #a); } } do{} while(0)
#define BOLT_MALLOC(var, how_much) { if (!((var) = f_malloc(how_much))) { BOLT_SAY(E_XL4BUS_MEMORY, "failed to alloc %d for %s", how_much, #var); } } do{}while(0)

#define BOLT_MTLS(a) do { \
    int __mtls_err = (a); \
    if (__mtls_err) { \
        if (XL4_PROVIDE_DEBUG) { \
            char e_buf[512]; \
            mbedtls_strerror(__mtls_err, e_buf, 512); \
            DBG("%s failed with (%x) %s", #a, __mtls_err, e_buf); \
        } \
        err = E_XL4BUS_SYS; \
        pf_set_errno(EINVAL); \
    } \
} while(0); \
if (err) { break; } \
do {} while(0)

#endif // _XL4BUS_DEBUG_H_
