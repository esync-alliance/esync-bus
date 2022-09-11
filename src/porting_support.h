
// include this header from code that implements functionality
// for a particular target. It provides and includes headers
// so that implementation code doesn't need to explicitly differentiate
// whether it's compiled for the library code, or for the binaries.

#ifndef _XL4BUS_PORTING_SUPPORT_H_
#define _XL4BUS_PORTING_SUPPORT_H_

#ifdef XL4BUS_BUILD

#include "internal.h"
#include "debug.h"

#define ps_malloc(a) (cfg.malloc(a))
#define ps_free(a) (cfg.free(a))

#else

#include "lib/debug.h"
#include "lib/common.h"

#define ps_malloc(a) f_malloc(a)
#define ps_free(a) free(a)

#endif



#endif // _XL4BUS_PORTING_SUPPORT_H_