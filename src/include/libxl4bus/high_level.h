
/**
 * @file
 * @brief High-level XL4-Bus API for connecting to a XL4-Bus broker
 * and exchanging messages with other clients.
 *
 * Before using the high level client in any way, the caller must
 * create the client object and initialize it using ::xl4bus_init_client
 * function.
 *
 * There are two ways to use the high level API from there on. First way is with
 * doing direct I/O multiplexing, having caller be responsible for polling for data,
 * and invoking the corresponding functions when there are socket events
 * on the reported file descriptors. This invokes using ::xl4bus_flag_poll
 * to tell the library which descriptors have changed state, and making
 * sure to configure xl4bus_client_t::set_poll to point to the function
 * that would tell the caller which file descriptor should be listened on.
 * Once some of the file descriptors recorded an event, call
 * ::xl4bus_run_client. If ::xl4bus_run_client ever fails, the caller
 * should call ::xl4bus_stop_client, and either re-initialize the client
 * after the corresponding callback as been invoked. The caller should
 * use ::xl4bus_stop_client in the case when it wants to stop processing
 * of the client object as well.
 *
 * Second mode is only available if threading support was compiled in,
 * and internal thread support has been configured during compilation.
 * In this case, the xl4bus_client::use_internal_thread must be set to 1.
 * The client object can still be destroyed if there was an I/O problem,
 * or if the caller called ::xl4bus_stop_client explicitly.
 */

#ifndef _XL4BUS_HIGH_LEVEL_H_
#define _XL4BUS_HIGH_LEVEL_H_

#include <libxl4bus/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef XL4_PUB
/**
 * Used to indicate that the library symbol is properly exported.
 */
#if XL4_SYMBOL_VISIBILITY_SUPPORTED
#define XL4_PUB __attribute__((visibility ("default")))
#else
#define XL4_PUB
#endif
#endif

XL4_PUB
/**
 * Initializes a high level client.
 * Note that the low level (using ::xl4bus_init_ll) must be initialized
 * before initializing any high level clients.
 *
 * If the internal threads are supported, and it is requested
 * for the client to use an internal thread for handling, callbacks
 * can start being issued before this function returns; however,
 * callbacks are only issued when this function to return success.
 *
 * The caller must not release any memory associated with any
 * of the objects provided during this function, until
 * xl4bus_client_t::on_release has been called.
 *
 * @param clt client structure, with handler information filled in.
 * @param url URL of the broker. The only supported connection URL
 * at this point is in form of `tcp://hostname:port`. The library
 * will make a copy of this data, and the memory can be released after
 * the call returns.
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
 * be 0, or have any other bits set.
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
int xl4bus_stop_client(xl4bus_client_t * clt);

XL4_PUB
/**
 * Sends specified message to the destination.
 * Once the message was accepted (E_XL4BUS_OK is returned), the
 * library takes ownership of the message, and no associated data can be freed
 * until the message is returned back through the ::xl4bus_client_t.on_delivered.
 * In case when an error is returned, the library does not hold on to any references,
 * and the message can be disposed of right away. Note that sending message
 * from application thread is only permitted if ::xl4bus_client_t.mt_support is
 * `!0`.
 * @param clt client structure
 * @param msg message to send
 * @param arg argument, will be reported into the ::xl4bus_client_t.on_delivered.
 * @param app_thread, if !0, indicates that the call is made from any thread other
 * than where the xl4bus callbacks are executed. To preserve multi-thread safety,
 * and minimize porting requirements, it's expected that the application provides
 * caller this information, rather than it being deduced.
 * @return ::E_XL4BUS_OK if message was sent successfully, or a corresponding
 * error code.
 */
int xl4bus_send_message2(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg, int app_thread);

XL4_PUB
/**
 * Older version of ::xl4bus_send_message2, simply calls
 * {@code xl4bus_send_message2(..., 1)}. Newer function should be used to properly specify
 * whether the call is coming from xl4bus client thread (typically executed from the message
 * callback, or the polling thread used by the application), or some other (application) thread.
 */
int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg);

#undef XL4_PUB

#ifdef __cplusplus
}
#endif

#endif /* _XL4BUS_HIGH_LEVEL_H_ */
