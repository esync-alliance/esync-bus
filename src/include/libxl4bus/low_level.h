#ifndef _XL4BUS_LOW_LEVEL_H_
#define _XL4BUS_LOW_LEVEL_H_

#include <libxl4bus/types.h>

#ifndef XL4_PUB
#define XL4_PUB __attribute__((visibility ("default")))
#endif

XL4_PUB int xl4bus_init_ll(xl4bus_ll_cfg_t *);
XL4_PUB int xl4bus_init_connection(xl4bus_connection_t *);
XL4_PUB int xl4bus_process_connection(xl4bus_connection_t *, int flags, int *);
XL4_PUB void xl4bus_shutdown_connection(xl4bus_connection_t *);
XL4_PUB int xl4bus_send_ll_message(xl4bus_connection_t *, xl4bus_ll_message_t *msg, void *ref);
XL4_PUB char const * xl4bus_strerr(int);

#undef XL4_PUB

#endif
