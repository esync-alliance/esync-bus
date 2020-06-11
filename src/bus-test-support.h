
#if WITH_UNIT_TEST

#ifndef _XL4BUS_BUS_TEST_SUPPORT_H_
#define _XL4BUS_BUS_TEST_SUPPORT_H_

#include <libxl4bus/types.h>
#include "renamed_json.h"

#ifndef XL4_PUB
/**
 * Used to indicate that the library symbol is properly exported.
 */
#define XL4_PUB __attribute__((visibility ("default")))
#endif

/* client.c */

struct decrypt_and_verify_data;

typedef void (*xl4bus_pause_callback)(struct xl4bus_client *, int is_pause);
typedef int (*control_message_interceptor)(struct xl4bus_client * clt, xl4bus_ll_message_t *,
        struct decrypt_and_verify_data * dav, json_object * msg, char const * type);
XL4_PUB void xl4bus_pause_client_receive(xl4bus_client_t * clt, int is_pause);
XL4_PUB int xl4bus_process_ll_message(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg);
XL4_PUB int xl4bus_process_client_message(xl4bus_client_t * clt, xl4bus_ll_message_t *,
        struct decrypt_and_verify_data * dav, json_object * msg, char const * type);
XL4_PUB int get_xl4bus_message_msg(xl4bus_ll_message_t const *, json_object **, char const **);
XL4_PUB extern xl4bus_pause_callback test_pause_callback;
XL4_PUB extern xl4bus_handle_ll_message test_message_interceptor;
XL4_PUB extern control_message_interceptor test_control_message_interceptor;

#endif

#endif
