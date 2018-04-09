
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
int xl4bus_stop_client(xl4bus_client_t * clt);

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
 * @param app_thread, if !0, indicates that the call is made from any thread other
 * than where the xl4bus callbacks are executed. To preserve multi-thread safety,
 * and minimize porting requirements, it's expected that the application provides
 * caller provides this information, rather than it being deduced.
 * @return ::E_XL4BUS_OK if message was sent successfully, or a corresponding
 * error code.
 */
int xl4bus_send_message2(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg, int app_thread);

XL4_PUB
/**
 * Older version of ::xl4bus_send_message2, simply calls
 * {@code xl4bus_send_message2(..., clt->use_internal_thread)}. Use the newer
 * function to make sure you properly specify whether the you are currently calling
 * from xl4bus callback, or from an application thread.
 */
int xl4bus_send_message(xl4bus_client_t * clt, xl4bus_message_t * msg, void * arg);

XL4_PUB
/**
 * Converts specified address, or list of addresses to corresponding
 * JSON format, according to array of xl4bus JSON addresses as
 * referenced in https://gitlab.excelfore.com/schema/json/xl4bus/xl4bus-address.json
 * The caller must free the memory if this function completed successfully.
 * @param addr address, or beginning of chain of addresses, to serialize
 * @param json pointer to the variable to take in pointer to the serialized JSON value.
 * @return ::E_XL4BUS_OK if serialization succeeded, or an error code otherwise.
 */
int xl4bus_address_to_json(xl4bus_address_t *addr, char **json);

XL4_PUB
/**
 * Converts XL4 JSON address specification into internal address values, and
 * chains them to an existing address, or creates a new address chain.
 * @param json Serialized JSON containing one or multiple addresses. In case
 * of multiple addresses, the top-level object must be an array.
 * @param addr pointer to an address that will have the new address list chained to.
 * If there was an error, no addresses will be chained. *addr can be NULL to
 * create a new address chain.
 * @return ::E_XL4BUS_OK if operation succeeded, or an error code otherwise. Note
 * that unrecognized address entries in the JSON are quietly ignored.
 */
int xl4bus_json_to_address(char const *json, xl4bus_address_t **addr);

XL4_PUB
/**
 * Allocates address structure and copies or assigns relevant address information.
 * @param receiver pointer to memory where the full address chain will be referenced at.
 * If *receiver is 0, then a new address chain is created; if it is !0, then the current
 * address is appended to the new address. In any case, the value at *receiver may or may not
 * be modified. The value is never modified if the function fails.
 * @param type address type
 * @param ...
 * For type ::XL4BAT_SPECIAL, the argument is of type xl4bus_address_special_t
 * For type ::XL4BAT_UPDATE_AGENT and XL4BAT_GROUP, the address value is a char*, followed by an int.
 * The int is either 0 or 1, specifying whether the char* should be duplicated (1), or assigned (0).
 * @return ::E_XL4BUS_OK if there are no errors, or an error code otherwise.
 */
int xl4bus_chain_address(xl4bus_address_t ** receiver, xl4bus_address_type_t type, ...);

XL4_PUB
/**
 * Copies all addresses from the specified address or chain.
 * @param src address, or address chain to copy from
 * @param chain if !0, then all chain is copied
 * @param receiver address to copy the chain to. If points to existing chain, the addresses
 * are prepended to the specified chain.
 * @return ::E_XL4BUS_OK if there are no errors, or an error code otherwise. In case of an error,
 * the existing chain at the destination, if any, is not modified.
 */
int xl4bus_copy_address(xl4bus_address_t * src, int chain, xl4bus_address_t ** receiver);

XL4_PUB
/**
 * Frees previously allocated address. Note that for addresses that contain
 * string values, such values are always freed, even if they were assigned and the
 * address was created using ::xl4bus_chain_address. Note that memory that
 * ::xl4bus_address_t structure pointers reference is also always freed.
 * @param addr address to free
 * @param chain !0 to indicate that all addresses accessible through ::xl4bus_address_t.next
 * should be freed as well.
 */
void xl4bus_free_address(xl4bus_address_t * addr, int chain);

XL4_PUB
/**
 * Checks whether all specified addresses are present in the specified address list.
 * @param needle All of these addresses must be found in haystack.
 * @param haystack List of addresses to check against.
 * @param failed, optional, if !0, then the function will place the pointer to the first address that failed
 * to have been found in the haystack. If needle was 0, it will set to 0 as well.
 * @return ::E_XL4BUS_OK if address is found, error otherwise.
 */
int xl4bus_require_address(xl4bus_address_t * needle, xl4bus_address_t * haystack, xl4bus_address_t ** failed);

XL4_PUB
/**
 * Checks whether the specified special address is present in the specified address list.
 * @param special Special address value that must be found in the haystack
 * @param haystack List of addresses to check against.
 * @return ::E_XL4BUS_OK if address is found, error otherwise.
 */
int xl4bus_require_special(xl4bus_address_special_t special, xl4bus_address_t * haystack);

XL4_PUB
/**
 * Checks whether the specified group address is present in the specified address list.
 * @param name Group address value that must be found in the haystack
 * @param haystack List of addresses to check against.
 * @return ::E_XL4BUS_OK if address is found, error otherwise.
 */
int xl4bus_require_group(const char * name, xl4bus_address_t * haystack);

XL4_PUB
/**
 * Checks whether the specified update agent address is present in the specified address list.
 * Note that update agent address name matching will be used.
 * @param name Update agent address value that must be found in the haystack
 * @param haystack List of addresses to check against.
 * @return ::E_XL4BUS_OK if address is found, error otherwise.
 */
int xl4bus_require_update_agent(const char * name, xl4bus_address_t * haystack);

#undef XL4_PUB

#endif
