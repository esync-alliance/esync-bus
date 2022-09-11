#ifndef __GHS_PORT__
#define __GHS_PORT__
#include "ghs_epoll.h"
#include "ghs_misc.h"
#include "porting.h"

#ifndef ASSERT
#define ASSERT(c, fmt,...) do { if (!(c)) { \
        printf(LOG_PREFIX fmt" \n", ##__VA_ARGS__);           \
        fflush(stdout);                            \
        assert(0);                                 \
    } \
} while(0)
#endif

#ifndef GDBG
#define GDBG(fmt, ...)  do { printf(LOG_PREFIX fmt"\n", ##__VA_ARGS__); } while (0)
#endif

#endif
