
/**
 * @file
 * @brief High-level XL4-Bus API for connecting to a XL4-Bus broker
 * and exchanging messages with other clients.
 */

#ifndef _XL4BUS_HIGH_LEVEL_H_
#define _XL4BUS_HIGH_LEVEL_H_

#include <libxl4bus/types.h>

#ifndef XL4_PUB
/**
 * Used to indicate that the library symbol is properly exported.
 */
#define XL4_PUB __attribute__((visibility ("default")))
#endif

XL4_PUB
/**
 * Initializes a high level client.
 * Note that the low level (using ::xl4bus_init_ll) must be initialized
 * @param clt client structure, with handler information filled in.
 * @param url URL of the broker. The only supported connection URL
 * at this point is in form of `tcp://hostname:port`.
 * @return ::E_XL4BUS_OK if the initialization is successful, or another
 * error code otherwise. If an error is returned, the client is unusable.
 */
int xl4bus_init_client(xl4bus_client_t * clt, char * url);

XL4_PUB
/**
 * Informs the library that a specific file descriptor bound to
 * a specific client, has been triggered by poll with the specified
 * flags.
 * This function must not be called if internal threads are being
 * used for this client.
 * @param clt client structure
 * @param fd file descriptor that was triggered
 * @param modes triggered operations, can be combination of
 * ::XL4BUS_POLL_READ, ::XL4BUS_POLL_WRITE and ::XL4BUS_POLL_ERR, should not
 * be 0, or contain other bits.
 * @return ::E_XL4BUS_OK in case of success, or ::E_XL4BUS_MEMORY if there
 * was insufficient memory. The client won't stop operating in case
 * an error is returned, but the user must retry, or stop the client.
 */
int xl4bus_flag_poll(xl4bus_client_t * clt, int fd, int modes);

XL4_PUB
/**
 * Lets the library to execute its operations. This function must not be
 * called if internal threads are being used for this client.
 * @param clt client structure
 * @param timeout_ms pointer to the timeout value that will be populated
 * at the end of the function. Timeout value can be set to -1 indicating
 * infinite timeout. If timeout value is set, the user must call ::xl4bus_run_client
 * function no later than that many milliseconds after the function returned.
 * The user may call the function earlier. Any new timeout value returned
 * supersedes any previously issued.
 */
void xl4bus_run_client(xl4bus_client_t * clt, int * timeout_ms);

XL4_PUB
/**
 * Stops running client.
 * @param clt client structure
 */
void xl4bus_stop_client(xl4bus_client_t * clt);

XL4_PUB
/**
 * Sends specified message to the destination.
 * Once the message was accepted (E_XL4BUS_OK is returned), the
 * library takes ownership of the message, and no associated data can be freed
 * until the message is returned back through the ::xl4bus_client_t.on_delivered.
 * In case when an error is returned, the library does not hold on to any references,
 * and the message can be disposed of right away.
 * @param clt client structure
 * @param msg message to send
 * @param arg argument, will be reported into the ::xl4bus_client_t.on_delivered.
 * @return ::E_XL4BUS_OK if message was sent successfully, or a corresponding
 * error code.
 */
int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg);

#undef XL4_PUB

#endif
