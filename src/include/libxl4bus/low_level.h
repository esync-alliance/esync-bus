
/**
 * @file
 */

#ifndef _XL4BUS_LOW_LEVEL_H_
#define _XL4BUS_LOW_LEVEL_H_

#include <libxl4bus/types.h>

#ifndef XL4_PUB
#define XL4_PUB __attribute__((visibility ("default")))
#endif

XL4_PUB
/**
 * Returns library version string. The string shall
 * not be modified in any way.
 * @return library version string, for identification purposes
 */
const char * xl4bus_version(void);

XL4_PUB
/**
 * Initializes the library.
 * @param cfg
 * @return
 */
int xl4bus_init_ll(xl4bus_ll_cfg_t * cfg);

XL4_PUB
/**
 * Initializes xl4bus connection object. If an error is returned,
 * the connection object should be considered uninitialized. Check the
 * documentation for ::xl4bus_connection_t structure to see which fields
 * must be initialized before calling this function.
 * @param conn connection object to initialize.
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem.
 */
int xl4bus_init_connection(xl4bus_connection_t * conn);

XL4_PUB int xl4bus_process_connection(xl4bus_connection_t *, int fd, int flags);
XL4_PUB void xl4bus_shutdown_connection(xl4bus_connection_t *);
XL4_PUB int xl4bus_send_ll_message(xl4bus_connection_t *, xl4bus_ll_message_t *msg, void *ref
#if XL4_SUPPORT_THREADS
        , int is_mt
#endif
);
XL4_PUB char const * xl4bus_strerr(int);
XL4_PUB void xl4bus_abort_stream(xl4bus_connection_t *, uint16_t stream_id);

#undef XL4_PUB

#endif
