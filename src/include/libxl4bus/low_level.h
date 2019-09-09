
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

XL4_PUB
/**
 * Sets remote identity for this connection. Useful when remote identity
 * enables encrypting for this identity. For X.509, specifying remote certificate
 * is sufficient. The caller can dispose of any memory used for identity
 * value after this function returns. This function must only be called on the same
 * thread as ::xl4bus_process_connection.
 * @param conn connection to set identity for
 * @param identity identity object
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem.
 */
int xl4bus_set_remote_identity(xl4bus_connection_t * conn, xl4bus_identity_t * identity);

XL4_PUB
/**
 * Sets fast (typically symmetric) keys for encrypting/decrypting data on the specified
 * connection. The key data must contain expiration value expressed in milliseconds from current time.
 * The key object can be disposed of (securely) after this function returns, as data will be copied.
 *
 * @param conn connection to set the keys for.
 * @param key session key to use. The outgoing messages are encrypted and signed using this key, and
 * the received messages are decrypted and verified using this key.
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem.
 */
int xl4bus_set_session_key(xl4bus_connection_t * conn, xl4bus_key_t * key);

XL4_PUB
/**
 * Set default keep-alive settings for the connection, as empty connection
 * object will effectively have keep-alive turned off.
 * @param conn connection to set default keep-alive parameters on.
 */
void xl4bus_set_default_keep_alive(xl4bus_connection_t * conn);

XL4_PUB int xl4bus_get_next_outgoing_stream(xl4bus_connection_t * conn, uint16_t * stream);

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
