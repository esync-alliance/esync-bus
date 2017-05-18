#ifndef _XL4BUS_DEBUG_H_
#define _XL4BUS_DEBUG_H_

#include "porting.h"
#include "config.h"
#include "internal.h"

#if XL4BUS_PROVIDE_DEBUG

#if !HAVE_GETTIMEOFDAY
#define _ltime_ \
    char now[1]; \
    now[0] = 0
#else
#define _ltime_ \
    char now[20]; \
    struct tm tmnow; \
    struct timeval tv; \
    memset(now, 0, 20); \
    gettimeofday(&tv, 0); \
    localtime_r(&tv.tv_sec, &tmnow); \
    strftime(now, 19, "%m-%d:%H:%M:%S", &tmnow)
#endif

#define DBG(a,b...) do { if (cfg.debug_f) { \
    _ltime_; \
    char * _str = f_asprintf("[%s] %s:%d " a, now, __FILE__, __LINE__, ## b); \
    if (_str) { \
        cfg.debug_f(_str); \
        cfg.free(_str); \
    } \
} } while(0)

#define DBG_SYS(a,b...) do { if (cfg.debug_f) { \
    int _errno = pf_get_errno(); \
    _ltime_; \
    char * _str = f_asprintf("[%s] %s:%d error %s(%d): " a, now, __FILE__, __LINE__, strerror(_errno), _errno, ## b); \
    if (_str) { \
        cfg.debug_f(_str); \
        cfg.free(_str); \
    } \
} } while(0)

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

#define BOLT(why) err = (why); DBG("setting err %d", err); break; do{}while(0)
#define BOLT_SAY(__err, msg, x...) err = (__err); DBG(msg ", setting err %d", ## x, err); break; do{}while(0)
#define BOLT_IF(cond, __err, msg, x...) if (cond) { err = (__err); DBG(msg ", setting err %d", ## x, err); break; } do{}while(0)
#define BOLT_M1(a, m, x...) if ((a)==-1) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SYS(a, m, x...) if ((a)) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SUB(a) { err = (a); if (err != E_XL4BUS_OK) { BOLT_SAY(err, #a); }} do{}while(0)
#define BOLT_CJOSE(a) { a; BOLT_SUB(cjose_to_err(&c_err)); }

#endif // _XL4BUS_DEBUG_H_
