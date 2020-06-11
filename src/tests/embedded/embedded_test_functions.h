
#ifndef _EMBEDDED_TEST_FUNCTIONS_H_
#define _EMBEDDED_TEST_FUNCTIONS_H_

#include <libxl4bus/low_level.h>

#if XL4_SYMBOL_VISIBILITY_SUPPORTED
#define XL4_PUB __attribute__((visibility ("default")))
#else
#define XL4_PUB
#endif


XL4_PUB
int esync_4841_intercept(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, xl4bus_client_t * for_client);
XL4_PUB
int esync_4841_check_mints(xl4bus_client_t * clt);

#undef XL4_PUB

#endif