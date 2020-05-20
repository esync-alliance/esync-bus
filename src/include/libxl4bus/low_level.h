
/**
 * @file
 */

#ifndef _XL4BUS_LOW_LEVEL_H_
#define _XL4BUS_LOW_LEVEL_H_

#include <libxl4bus/types.h>

#ifndef XL4_PUB
#if XL4_SYMBOL_VISIBILITY_SUPPORTED
#define XL4_PUB __attribute__((visibility ("default")))
#else
#define XL4_PUB
#endif
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
 * Extracts addresses that this identity represents.
 * @param conn connection to extract addresses from.
 * @param addresses pointer to the tip of the address chain where the addresses will be stored.
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem extracting or
 * allocating address information.
 * @deprecated Use ::xl4bus_get_identity_data instead.
 */
int xl4bus_get_identity_addresses(xl4bus_identity_t * identity, xl4bus_address_t ** addresses);

XL4_PUB
/**
 * Extracts addresses that this identity represents.
 * @param conn connection to extract addresses from.
 * @param addresses pointer to the tip of the address chain where the addresses will be stored. Can be `0`, so
 * no addresses are extracted.
 * @param sender_data pointer to the sender_data pointer that will be set to point to custom data associated
 * with the certificate (if any). Can be `0` to not extract such data.
 * @param sender_data_count pointer to a size_t that will be set with the length of sender data. Must be set to
 * valid memory address if `sender_data` is `!0`.
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem extracting or
 * allocating address information.
 */
int xl4bus_get_identity_data(xl4bus_identity_t * identity, xl4bus_address_t ** addresses,
        xl4bus_sender_data_t ** sender_data, size_t * sender_data_count);

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
 * Sets fast (typically symmetric) keys for encrypting/decrypting data on the specified
 * connection. The key data must contain expiration value expressed in milliseconds from current time.
 * The key object can be disposed of (securely) after this function returns, as data will be copied.
 *
 * @param conn connection to set the keys for.
 * @param key session key to use. The outgoing messages are encrypted and signed using this key, and
 * the received messages are decrypted and verified using this key.
 * @param use_now if `!0`, then the key will be used immediately, otherwise it will only be used
 * if the remote sent a message encrypted with this key.
 * @return ::E_XL4BUS_OK for success, or an error code if there was a problem.
 */
int xl4bus_set_session_key(xl4bus_connection_t * conn, xl4bus_key_t * key, int use_now);

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
 * Frees previously allocated custom data.
 * @param data data to free
 * @param count element count in the data object, as was reported when it was allocated.
 */
void xl4bus_free_sender_data(xl4bus_sender_data_t * data, size_t count);

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

/**
 * Sends a message to connected xl4bus peer. Important note about message object ownership. If this function
 * returned an error, the message was not accepted, and no callbacks will be invoked. It's the responsibility of
 * the caller to clean up the message in this case. If success was returned, then it's guaranteed that
 * xl4bus_connection::on_sent_message will be invoked, so any resources provided along with the message must not
 * be released until that point.
 * @param conn connection to send the message through
 * @param msg message to send
 * @param ref reference pointer, used for callbacks involving the message being sent.
 * @param is_mt (only if multi-threading is supported), if `!0`, then calling thread
 * is not xl4bus thread. Note that multi-threading must be enabled for the connection.
 * @return ::E_XL4BUS_OK if the message was accepted for delivery, an error code otherwise.
 */
XL4_PUB int xl4bus_send_ll_message(xl4bus_connection_t * conn, xl4bus_ll_message_t *msg, void *ref
#if XL4_SUPPORT_THREADS
        , int is_mt
#endif
);
XL4_PUB char const * xl4bus_strerr(int);
XL4_PUB void xl4bus_abort_stream(xl4bus_connection_t *, uint16_t stream_id);

/**
 * Returns the size of cache object to allocate.
 * @return cache object size.
 */
XL4_PUB size_t xl4bus_get_cache_size(void);

/**
 * Cleans up the cache, releasing all memory used by the cached objects.
 * The pointer itself is not freed.
 * @param cache pointer to the cache used in xl4bus operations.
 */
XL4_PUB void xl4bus_release_cache(struct xl4bus_global_cache * cache);

#undef XL4_PUB

#endif
