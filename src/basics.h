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
#define MICROS_PER_MILLI 1000ULL
#define NANOS_PER_MICRO 10000ULL
#define NANOS_PER_SEC (MILLIS_PER_SEC * MICROS_PER_MILLI * NANOS_PER_MICRO)
#define SEC_PER_MIN 60ULL
#define MIN_PER_HOUR 60ULL
#define HOUR_PER_DAY 24ULL
#define MILLIS_PER_HOUR (MIN_PER_HOUR * SEC_PER_MIN * MILLIS_PER_SEC)
#define MILLIS_PER_DAY (HOUR_PER_DAY * MILLIS_PER_HOUR)

#define HDR_XL4BUS "x-xl4bus"
#define HDR_X5T256 "x5t#S256"
#define HDR_X5C "x5c"
#define BUS_OBJ_NONCE "nonce"
#define BUS_OBJ_TIMESTAMP "nonce"

#define MSG_TYPE_REG_REQUEST "xl4bus.registration-request"
#define MSG_TYPE_REQ_DESTINATIONS "xl4bus.request-destinations"
#define MSG_TYPE_REQ_CERT "xl4bus.request-cert"
#define MSG_TYPE_CERT_DETAILS "xl4bus.cert-details"
#define MSG_TYPE_MESSAGE_CONFIRM "xl4bus.message-confirm"
#define MSG_TYPE_KEY_INFO "xl4bus.key-info"
#define MSG_TYPE_REQ_KEY "xl4bus.request-key"

#define JSON_ADDR_PROP_UPDATE_AGENT "update-agent"
#define JSON_ADDR_PROP_SPECIAL "special"
#define JSON_ADDR_PROP_GROUP "group"
#define JSON_ADDR_PROP_X5T_S256 "x5t#S256"

#define JSON_ADDR_SPECIAL_DMCLIENT "dmclient"
#define JSON_ADDR_SPECIAL_BROKER "broker"

// high level key expires in 24 hours
#ifndef XL4_HL_KEY_EXPIRATION_MS
#define XL4_HL_KEY_EXPIRATION_MS (24 * MILLIS_PER_HOUR)
#endif

// the remote can request the key for one additional hour
#ifndef XL4_HL_KEY_USE_EXPIRATION_MS
#define XL4_HL_KEY_USE_EXPIRATION_MS MILLIS_PER_HOUR
#endif

// low level symmetric key expires in 24 hours
#ifndef XL4_LL_KEY_EXPIRATION_MS
#define XL4_LL_KEY_EXPIRATION_MS (24 * MILLIS_PER_HOUR)
#endif

#ifndef XL4_CLIENT_RECONNECT_INTERVAL_MS
#define XL4_CLIENT_RECONNECT_INTERVAL_MS (2 * MILLIS_PER_SEC)
#endif

#ifndef XI
#define XI(a) a
#endif

#define Z(op, p) do { op(p); p = 0; } while (0)

#define xl4json_get_pointer XI(xl4json_get_pointer)
int xl4json_get_pointer(json_object *, char const *, json_type, void *);

static inline char const * BOOL_STR(int a) {
    if (a) { return "TRUE"; }
    return "FALSE";
}

#endif
