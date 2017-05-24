#ifndef _XL4BUS_HIGH_LEVEL_H_
#define _XL4BUS_HIGH_LEVEL_H_

#include <libxl4bus/types.h>

#ifndef XL4_PUB
#define XL4_PUB __attribute__((visibility ("default")))
#endif

// the only URL format accepted so far is:
// tcp://hostname:port
XL4_PUB int xl4bus_init_client(xl4bus_client_t *, char * url);
XL4_PUB int xl4bus_flag_poll(xl4bus_client_t *, int fd, int modes);
XL4_PUB void xl4bus_run_client(xl4bus_client_t *, int *);
XL4_PUB void xl4bus_stop_client(xl4bus_client_t *);
XL4_PUB int xl4bus_send_message(xl4bus_client_t *, xl4bus_message_t *, void *);

#undef XL4_PUB

#endif
