
#ifndef _XL4BROKER_DEBUG_H_
#define _XL4BROKER_DEBUG_H_

#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

extern int debug;

#define _ltime_ \
    char now[20]; \
    struct tm tmnow; \
    struct timeval tv; \
    memset(now, 0, 20); \
    gettimeofday(&tv, 0); \
    localtime_r(&tv.tv_sec, &tmnow); \
    strftime(now, 19, "%m-%d:%H:%M:%S", &tmnow)

#define DBG(a,b...) do { if (debug) { \
    _ltime_; \
    char * _str = f_asprintf("[%s] %s:%d " a, now, __FILE__, __LINE__, ## b); \
    if (_str) { \
        printf("%s\n", _str); \
        free(_str); \
    } \
} } while(0)

#define DBG_SYS(a,b...) do { if (debug) { \
    int _errno = errno; \
    _ltime_; \
    char * _str = f_asprintf("[%s] %s:%d error %s(%d): " a, now, __FILE__, __LINE__, strerror(_errno), _errno, ## b); \
    if (_str) { \
        printf("%s\n", _str); \
        free(_str); \
    } \
} } while(0)

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
    void * __aux = realloc(ptr, (__size)*sizeof(type)); \
    if (!__aux) { err = E_XL4BUS_MEMORY; DBG("out of memory, realloc %d", __size); break; } \
    ptr = (type*)__aux; \
    newsize = __size; \
} do{}while(0)

#define SAFE_STR(s) (s?s:"(null)")

#define BOLT(why) err = (why); DBG("setting err %d", err); break; do{}while(0)
#define BOLT_SAY(__err, msg, x...) err = (__err); DBG(msg ", setting err %d", ## x, err); break; do{}while(0)
#define BOLT_IF(cond, __err, msg, x...) if ((cond)) { err = (__err); DBG(msg ", setting err %d", ## x, err); break; } do{}while(0)
#define BOLT_M1(a, m, x...) if ((a)==-1) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SYS(a, m, x...) if ((a)) { DBG_SYS(m, ## x); err = E_XL4BUS_SYS; break; } do{}while(0)
#define BOLT_SUB(a) { err = (a); if (err != E_XL4BUS_OK) { BOLT_SAY(err, #a); }} do{}while(0)
#define BOLT_CJOSE(a) { a; if (c_err.code != CJOSE_ERR_NONE) { BOLT_SAY(cjose_to_err(&c_err), "cjose failure %d %s:%s", c_err.code, c_err.message, #a);}}
#define BOLT_ARES(a) { int __err = (a); if (__err != ARES_SUCCESS) { if (__err == ARES_ENOMEM) { __err = E_XL4BUS_MEMORY; } else { __err = E_XL4BUS_INTERNAL; } BOLT_SAY(__err, "%s", #a); } } do{} while(0)
#define BOLT_MALLOC(var, how_much) { if (!((var) = f_malloc(how_much))) { BOLT_SAY(E_XL4BUS_MEMORY, "failed to alloc %d for %s", how_much, #var); } } do{}while(0)

#endif
