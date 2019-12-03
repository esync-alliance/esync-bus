
#if WITH_UNIT_TEST

#ifndef _XL4BUS_BUS_TEST_SUPPORT_H_
#define _XL4BUS_BUS_TEST_SUPPORT_H_

#ifndef XL4_PUB
/**
 * Used to indicate that the library symbol is properly exported.
 */
#define XL4_PUB __attribute__((visibility ("default")))
#endif

/* client.c */

typedef void (*xl4bus_pause_callback)(struct xl4bus_client *, int is_pause);
XL4_PUB void xl4bus_pause_client_receive(xl4bus_client_t * clt, int is_pause);
XL4_PUB extern xl4bus_pause_callback test_pause_callback;

#endif

#endif
