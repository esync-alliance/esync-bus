#ifndef _XL4BUS_BASICS_H_
#define _XL4BUS_BASICS_H_

#include "json-c-rename.h"
#include <json.h>

// whatever is defined in this header file can be used by both the library and our own clients.
// this header, therefore, must not defined any functions, unless they are inline, or can execute
// without any questionable system functionality.

#define CT_JOSE_COMPACT 0
#define CT_JOSE_JSON    1
#define CT_APPLICATION_JSON 2
#define CT_TRUST_MESSAGE 3

#define FCT_JOSE_COMPACT "application/jose"
#define FCT_JOSE_JSON "application/jose+json"
#define FCT_APPLICATION_JSON "application/json"
#define FCT_TRUST_MESSAGE "application/vnd.xl4.busmessage-trust+json"
#define FCT_APPLICATION_OCTET_STREAM "application/octet-stream"
#define FCT_BUS_MESSAGE "application/vnd.xl4.busmessage+json"
#define FCT_TEXT_PLAIN "text/plain"

#define MILLIS_PER_SEC 1000ULL
#define SEC_PER_MIN 60ULL
#define MIN_PER_HOUR 60ULL
#define HOUR_PER_DAY 24ULL
#define MILLIS_PER_DAY (HOUR_PER_DAY * MIN_PER_HOUR * SEC_PER_MIN * MILLIS_PER_SEC)

#ifndef XI
#define XI(a) a
#endif

#define xl4json_get_pointer XI(xl4json_get_pointer)
int xl4json_get_pointer(json_object *, char const *, json_type, void *);

static inline char const * BOOL_STR(int a) {
    if (a) { return "TRUE"; }
    return "FALSE";
}

#endif